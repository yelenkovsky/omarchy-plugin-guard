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
    diff_truncated: bool = False,
    agent_denied_calls: int = 0,
) -> CombinedVerdict:
    """Fold the mechanical gates and the agent verdict into one decision.

    An agent *failure* is deliberately not an input here. It is not a
    judgement about the plugin, so the caller reports it as status "error"
    and retries on the next run instead of recording a false "deny".
    """
    reasons: list[str] = []
    if blocked:
        reasons.append("mechanical block finding")
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
    if diff_truncated:
        reasons.append("diff truncated; the agent did not see the whole change")
    if agent_denied_calls:
        reasons.append(
            f"agent attempted {agent_denied_calls} denied tool call(s); possible prompt injection"
        )
    if agent_verdict == "needs-human":
        reasons.append("agent requested a human")
    if reasons:
        return CombinedVerdict("needs-human", reasons)

    if agent_verdict is None:
        return CombinedVerdict("needs-human", ["agent review skipped"])

    return CombinedVerdict("allow", ["mechanical scan clean; agent allowed"])
