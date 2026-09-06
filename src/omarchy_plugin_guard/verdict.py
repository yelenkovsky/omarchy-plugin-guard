from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

VerdictName = Literal["allow", "deny", "needs-human"]


@dataclass
class CombinedVerdict:
    verdict: VerdictName
    reasons: list[str]


def combine_verdict(
    *,
    blocked: bool,
    expansion: list[str],
    origin_changed: bool,
    history_rewritten: bool,
    has_baseline: bool,
    agent_verdict: VerdictName | None,
    agent_error: str | None,
) -> CombinedVerdict:
    reasons: list[str] = []
    if blocked:
        reasons.append("mechanical block finding")
    if agent_error:
        reasons.append(f"agent review failed: {agent_error}")
    if agent_verdict == "deny":
        reasons.append("agent denied")
    if reasons:
        return CombinedVerdict("deny", reasons)

    if not has_baseline:
        reasons.append("no stored baseline")
    if expansion:
        reasons.append("capability expansion: " + ", ".join(expansion))
    if origin_changed:
        reasons.append("git origin URL changed")
    if history_rewritten:
        reasons.append("incoming commit is not a fast-forward")
    if agent_verdict == "needs-human":
        reasons.append("agent requested a human")
    if reasons:
        return CombinedVerdict("needs-human", reasons)

    if agent_verdict is None:
        return CombinedVerdict("needs-human", ["agent review skipped"])

    return CombinedVerdict("allow", ["mechanical scan clean; agent allowed"])
