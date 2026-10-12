"""Agent review through a headless, locked-down Claude Code session.

The agent runs as `claude -p` in the review workspace with:
- no settings, hooks, MCP servers, CLAUDE.md or auto-memory from this machine,
- a replaced system prompt (the reviewer instructions only),
- Read scoped to the workspace, plus Grep and Glob; everything else denied,
- a JSON schema so the verdict comes back as structured output.

Authentication is whatever `claude` is already logged in with. No API key is
handled here.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from omarchy_plugin_guard.prompt import SYSTEM_PROMPT, build_prompt
from omarchy_plugin_guard.verdict import VerdictName

JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)

DEFAULT_MODEL = "sonnet"
DEFAULT_MAX_TURNS = 24
DEFAULT_TIMEOUT_SECONDS = 600

ALLOWED_TOOLS = ["Read(./**)", "Grep", "Glob"]
DISALLOWED_TOOLS = [
    "Bash",
    "Edit",
    "Write",
    "MultiEdit",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
    "Task",
    "Agent",
    "ToolSearch",
]

VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["allow", "deny", "needs-human"]},
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["block", "warn"]},
                    "path": {"type": "string"},
                    "why": {"type": "string"},
                },
                "required": ["severity", "why"],
            },
        },
    },
    "required": ["verdict", "summary", "findings"],
}


class ReviewError(RuntimeError):
    pass


@dataclass
class AgentReview:
    verdict: VerdictName
    summary: str
    findings: list[dict[str, Any]]
    raw: str
    run_id: str = ""
    denied_calls: int = 0
    turns: int = 0
    cost_usd: float = 0.0


def default_model() -> str:
    return os.environ.get("OMARCHY_PLUGIN_GUARD_MODEL", "").strip() or DEFAULT_MODEL


def claude_binary() -> str:
    return os.environ.get("OMARCHY_PLUGIN_GUARD_CLAUDE", "").strip() or "claude"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def build_claude_command(*, claude_bin: str, model: str, max_turns: int) -> list[str]:
    """The exact argv; the prompt itself goes in on stdin."""
    return [
        claude_bin,
        "-p",
        "--strict-mcp-config",
        "--setting-sources",
        "",
        "--permission-mode",
        "dontAsk",
        "--system-prompt",
        SYSTEM_PROMPT,
        "--settings",
        json.dumps({"autoMemoryEnabled": False}),
        "--allowedTools",
        *ALLOWED_TOOLS,
        "--disallowedTools",
        *DISALLOWED_TOOLS,
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(VERDICT_SCHEMA),
        "--max-turns",
        str(max_turns),
        "--model",
        model,
    ]


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
    model: str | None = None,
) -> AgentReview:
    claude_bin = claude_binary()
    if not (shutil.which(claude_bin) or Path(claude_bin).is_file()):
        raise ReviewError(
            f"{claude_bin} not found; install Claude Code or set OMARCHY_PLUGIN_GUARD_CLAUDE"
        )
    chosen_model = (model or "").strip() or default_model()
    max_turns = _env_int("OMARCHY_PLUGIN_GUARD_MAX_TURNS", DEFAULT_MAX_TURNS)
    timeout = _env_int("OMARCHY_PLUGIN_GUARD_AGENT_TIMEOUT", DEFAULT_TIMEOUT_SECONDS)

    prompt = build_prompt(
        plugin_id=plugin_id,
        origin=origin,
        old_sha=old_sha,
        new_sha=new_sha,
        expansion=expansion,
        scan_json=json.dumps(scan_payload, indent=2),
        diff_text=diff_text,
    )
    command = build_claude_command(claude_bin=claude_bin, model=chosen_model, max_turns=max_turns)
    env = os.environ.copy()
    env["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] = "1"
    try:
        completed = subprocess.run(
            command,
            input=prompt,
            capture_output=True,
            text=True,
            cwd=str(workspace),
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReviewError(f"agent timed out after {timeout}s") from exc
    except OSError as exc:
        raise ReviewError(f"could not start {claude_bin}: {exc}") from exc
    return parse_claude_result(completed.stdout, stderr=completed.stderr, returncode=completed.returncode)


def parse_claude_result(stdout: str, *, stderr: str = "", returncode: int = 0) -> AgentReview:
    """Turn `claude -p --output-format json` output into an AgentReview."""
    text = stdout.strip()
    if not text:
        detail = stderr.strip()[:300] or f"exit {returncode}"
        raise ReviewError(f"agent produced no output ({detail})")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        if returncode != 0:
            raise ReviewError(f"agent exited {returncode}: {(stderr or text).strip()[:300]}")
        return parse_agent_verdict(text)
    if not isinstance(data, dict):
        raise ReviewError("agent output is not a JSON object")

    result_text = str(data.get("result") or "")
    subtype = str(data.get("subtype") or "")
    structured = data.get("structured_output")
    if data.get("is_error") or subtype.startswith("error"):
        detail = result_text.strip()[:300] or subtype or stderr.strip()[:300] or f"exit {returncode}"
        raise ReviewError(f"agent run failed: {detail}")
    if isinstance(structured, dict) and "verdict" in structured:
        review = _review_from_payload(structured, raw=result_text or json.dumps(structured))
    else:
        if returncode != 0 and not result_text:
            raise ReviewError(f"agent exited {returncode}: {stderr.strip()[:300]}")
        review = parse_agent_verdict(result_text)
    review.run_id = str(data.get("session_id") or "")
    denials = data.get("permission_denials") or []
    review.denied_calls = len(denials) if isinstance(denials, list) else 0
    try:
        review.turns = int(data.get("num_turns") or 0)
    except (TypeError, ValueError):
        review.turns = 0
    try:
        review.cost_usd = float(data.get("total_cost_usd") or 0.0)
    except (TypeError, ValueError):
        review.cost_usd = 0.0
    return review


def parse_agent_verdict(text: str) -> AgentReview:
    payload = _extract_json(text)
    return _review_from_payload(payload, raw=text)


def _review_from_payload(payload: dict[str, Any], *, raw: str) -> AgentReview:
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
        raw=raw,
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
