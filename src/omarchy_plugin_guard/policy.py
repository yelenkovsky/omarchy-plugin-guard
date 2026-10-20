"""Unattended auto-apply policy.

`update --auto` merges without a human only when every gate here passes.
Everything that fails a gate is left for the next interactive run; nothing
here can turn a needs-human or deny into a merge.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta

from omarchy_plugin_guard.scan import Capabilities

DEFAULT_SOAK_DAYS = 3
DEFAULT_MAX_DIFF_LINES = 400


@dataclass(frozen=True)
class AutoPolicy:
    soak_days: int = DEFAULT_SOAK_DAYS
    max_diff_lines: int = DEFAULT_MAX_DIFF_LINES

    @classmethod
    def from_env(cls, *, soak_days: int | None = None, max_diff_lines: int | None = None) -> AutoPolicy:
        soak = soak_days if soak_days is not None else _env_int("OMARCHY_PLUGIN_GUARD_SOAK_DAYS", DEFAULT_SOAK_DAYS)
        lines = (
            max_diff_lines
            if max_diff_lines is not None
            else _env_int("OMARCHY_PLUGIN_GUARD_MAX_DIFF_LINES", DEFAULT_MAX_DIFF_LINES)
        )
        return cls(soak_days=max(0, soak), max_diff_lines=max(1, lines))


@dataclass
class PolicyDecision:
    apply: bool
    reasons: list[str]


def evaluate_auto_apply(
    *,
    policy: AutoPolicy,
    verdict: str | None,
    diff_truncated: bool,
    diff_lines: int,
    old_caps: Capabilities | None,
    new_caps: Capabilities,
    first_seen_at: datetime,
    now: datetime,
) -> PolicyDecision:
    reasons: list[str] = []
    if verdict != "allow":
        reasons.append(f"verdict is {verdict or 'missing'}, not allow")
    if diff_truncated:
        reasons.append("diff was truncated")
    if diff_lines > policy.max_diff_lines:
        reasons.append(f"diff has {diff_lines} changed lines, cap is {policy.max_diff_lines}")
    if old_caps is None:
        reasons.append("no stored baseline")
    elif old_caps.runs_code():
        reasons.append("plugin already runs commands or code; auto-apply is for declarative QML only")
    if new_caps.runs_code() and (not reasons or "runs commands" not in reasons[-1]):
        reasons.append("incoming tree runs commands or code; auto-apply is for declarative QML only")
    age = now - first_seen_at
    needed = timedelta(days=policy.soak_days)
    if age < needed:
        remaining = needed - age
        hours = int(remaining.total_seconds() // 3600)
        reasons.append(
            f"soak: first seen {_humanize(age)} ago, auto-apply after {policy.soak_days}d ({hours}h left)"
        )
    return PolicyDecision(apply=not reasons, reasons=reasons)


def count_diff_lines(diff_text: str) -> int:
    count = 0
    for line in diff_text.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-")):
            count += 1
    return count


def _humanize(delta: timedelta) -> str:
    total = int(delta.total_seconds())
    if total < 3600:
        return f"{max(total // 60, 0)}m"
    if total < 86400:
        return f"{total // 3600}h"
    return f"{total // 86400}d"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default
