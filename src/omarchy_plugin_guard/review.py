from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from omarchy_plugin_guard.prompt import build_prompt
from omarchy_plugin_guard.verdict import VerdictName

JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


class ReviewError(RuntimeError):
    pass


@dataclass
class AgentReview:
    verdict: VerdictName
    summary: str
    findings: list[dict[str, Any]]
    raw: str
    run_id: str = ""
    agent_id: str = ""


def run_agent_review(
    *,
    workspace: Path,
    plugin_id: str,
    origin: str,
    old_sha: str,
    new_sha: str,
    expansion: list[str],
    scan_payload: dict[str, Any],
    diff_text: str,
) -> AgentReview:
    api_key = os.environ.get("CURSOR_API_KEY", "").strip()
    if not api_key:
        raise ReviewError(
            "CURSOR_API_KEY is not set. Export a Cursor user API key before running agent review."
        )
    model = os.environ.get("CURSOR_MODEL", "composer-2.5").strip() or "composer-2.5"

    prompt = build_prompt(
        plugin_id=plugin_id,
        origin=origin,
        old_sha=old_sha,
        new_sha=new_sha,
        expansion=expansion,
        scan_json=json.dumps(scan_payload, indent=2),
        diff_text=diff_text,
    )

    try:
        from cursor_sdk import Agent, AgentOptions, LocalAgentOptions
    except ImportError as exc:
        raise ReviewError("cursor-sdk is not installed in this environment") from exc

    local_kwargs: dict[str, Any] = {"cwd": str(workspace)}
    try:
        from cursor_sdk import SandboxOptions

        local_kwargs["sandbox_options"] = SandboxOptions(enabled=True)
    except Exception:
        pass

    def _prompt(kwargs: dict[str, Any]):
        return Agent.prompt(
            prompt,
            AgentOptions(
                api_key=api_key,
                model=model,
                tools=["read", "grep", "glob", "ls"],
                disallowed_tools=["shell", "edit", "task", "mcp"],
                local=LocalAgentOptions(**kwargs),
            ),
        )

    try:
        result = _prompt(local_kwargs)
    except Exception as exc:
        if "sandbox_options" not in local_kwargs:
            raise ReviewError(str(exc)) from exc
        local_kwargs = {k: v for k, v in local_kwargs.items() if k != "sandbox_options"}
        try:
            result = _prompt(local_kwargs)
        except Exception as retry_exc:
            raise ReviewError(str(retry_exc)) from retry_exc
    if getattr(result, "status", None) == "error":
        raise ReviewError(f"agent run failed: {getattr(result, 'id', '')}")
    text = getattr(result, "result", None) or ""
    if not isinstance(text, str) or not text.strip():
        raise ReviewError("agent returned empty review text")
    parsed = parse_agent_verdict(text)
    parsed.raw = text
    parsed.run_id = str(getattr(result, "id", "") or "")
    return parsed


def parse_agent_verdict(text: str) -> AgentReview:
    payload = _extract_json(text)
    verdict = str(payload.get("verdict") or "").strip().lower()
    if verdict not in {"allow", "deny", "needs-human"}:
        raise ReviewError(f"agent verdict is not allow/deny/needs-human: {verdict!r}")
    findings = payload.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    return AgentReview(
        verdict=verdict,  # type: ignore[arg-type]
        summary=str(payload.get("summary") or "").strip(),
        findings=[item for item in findings if isinstance(item, dict)],
        raw=text,
    )


def _extract_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    candidates = [stripped]
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL)
    if fenced:
        candidates.append(fenced.group(1))
    match = JSON_OBJECT.search(stripped)
    if match:
        candidates.append(match.group(0))
    last_error: Exception | None = None
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError as exc:
            last_error = exc
            continue
        if isinstance(data, dict) and "verdict" in data:
            return data
    raise ReviewError(f"could not parse JSON verdict from agent output ({last_error})")
