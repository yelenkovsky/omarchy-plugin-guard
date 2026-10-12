from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from omarchy_plugin_guard import __version__
from omarchy_plugin_guard.apply import (
    ApplyError,
    apply_reviewed_update,
    check_git_url,
    enable_plugin,
    install_reviewed_clone,
    validate_plugin,
)
from omarchy_plugin_guard.baseline import load_baseline, save_baseline
from omarchy_plugin_guard.confirm import confirm
from omarchy_plugin_guard.gitops import (
    GitError,
    clone,
    diff,
    fetch_origin,
    git,
    git_out,
    is_ancestor,
    is_git_plugin,
    list_git_plugins,
    remote_url,
    rev_parse,
    snapshot,
)
from omarchy_plugin_guard.paths import plugins_dir, reviews_dir, state_dir
from omarchy_plugin_guard.policy import AutoPolicy, count_diff_lines, evaluate_auto_apply
from omarchy_plugin_guard.review import ReviewError, default_model, run_agent_review
from omarchy_plugin_guard.scan import (
    Capabilities,
    capability_expansion,
    findings_to_dict,
    has_block_findings,
    scan_tree,
)
from omarchy_plugin_guard.state import (
    LockHeld,
    append_audit,
    clear_first_seen,
    note_first_seen,
    now_utc,
    run_lock,
)
from omarchy_plugin_guard.verdict import combine_verdict

PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
DIFF_LIMIT = 80_000

# Files and directories that an agent harness might treat as instructions.
# They are renamed inside the review snapshot so they stay plain data.
UNTRUSTED_INSTRUCTION_NAMES = {
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    ".cursorrules",
    ".mcp.json",
    ".claude",
    ".cursor",
    ".codex",
}
UNTRUSTED_PREFIX = "UNTRUSTED_"

LOCKED_COMMANDS = {"baseline", "review", "update", "add"}

EPILOG = """Examples:
  omarchy-plugin-guard status
  omarchy-plugin-guard baseline --write
  omarchy-plugin-guard review --notify
  omarchy-plugin-guard update
  omarchy-plugin-guard update stappmus.activity-monitor
  omarchy-plugin-guard update --auto --notify
  omarchy-plugin-guard add https://github.com/acme/omarchy-weather.git
  omarchy-plugin-guard update --json --dry-run
"""


@dataclass
class PluginReport:
    id: str
    status: str
    verdict: str | None = None
    from_sha: str = ""
    to_sha: str = ""
    origin: str = ""
    expansion: list[str] | None = None
    reasons: list[str] | None = None
    findings: list[dict[str, Any]] | None = None
    agent: dict[str, Any] | None = None
    error: str | None = None
    diff_lines: int | None = None
    diff_truncated: bool | None = None
    policy: list[str] | None = None
    first_seen_at: str | None = None
    mode: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="omarchy-plugin-guard",
        description="Fetch Omarchy git plugins, review the incoming diff, then merge only the reviewed SHA.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    status = sub.add_parser("status", help="Show git-managed plugins and stored baselines")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    baseline = sub.add_parser("baseline", help="Record capabilities of the currently installed tree")
    baseline.add_argument("ids", nargs="*")
    baseline.add_argument("--write", action="store_true", default=True)
    baseline.add_argument("--json", action="store_true")
    baseline.set_defaults(func=cmd_baseline)

    review = sub.add_parser("review", help="Fetch and review without merging")
    _add_review_flags(review)
    review.set_defaults(func=cmd_review)

    update = sub.add_parser("update", help="Review incoming commits, then fast-forward the reviewed SHA")
    _add_review_flags(update)
    update.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Apply without prompting when the combined verdict is allow",
    )
    update.add_argument(
        "--force",
        action="store_true",
        help="Apply a needs-human verdict without prompting (never overrides deny)",
    )
    update.add_argument(
        "--auto",
        action="store_true",
        help=(
            "Unattended mode: apply an allow verdict only when the auto policy passes "
            "(soak delay, diff size cap, declarative-only plugin). Never prompts."
        ),
    )
    update.add_argument(
        "--soak-days",
        type=int,
        default=None,
        help="With --auto: days a SHA must have been visible before it may auto-apply (default 3)",
    )
    update.add_argument(
        "--max-diff-lines",
        type=int,
        default=None,
        help="With --auto: largest diff that may auto-apply, in changed lines (default 400)",
    )
    update.set_defaults(func=cmd_update)

    add = sub.add_parser("add", help="Clone, review, then install a plugin from git")
    add.add_argument("url", help="Git URL of the plugin repo")
    add.add_argument("--enable", action="store_true", help="Enable the plugin after a successful install")
    add.add_argument("--skip-agent", action="store_true")
    add.add_argument("--dry-run", action="store_true")
    add.add_argument("--json", action="store_true")
    add.add_argument("--yes", "-y", action="store_true")
    add.add_argument("--force", action="store_true")
    add.add_argument("--model", default=None, help="Claude model alias or id for the agent review")
    add.set_defaults(func=cmd_add)

    args = parser.parse_args(argv)
    if getattr(args, "auto", False) and getattr(args, "force", False):
        parser.error("--auto and --force cannot be combined")
    try:
        if args.cmd in LOCKED_COMMANDS:
            with run_lock():
                return args.func(args)
        return args.func(args)
    except LockHeld as exc:
        print(f"omarchy-plugin-guard: {exc}", file=sys.stderr)
        return 1
    except (GitError, ApplyError, ReviewError) as exc:
        print(f"omarchy-plugin-guard: {exc}", file=sys.stderr)
        return 1


def _add_review_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("ids", nargs="*", help="Plugin ids (default: every git-managed plugin)")
    parser.add_argument("--skip-agent", action="store_true", help="Mechanical gates only")
    parser.add_argument("--dry-run", action="store_true", help="Review only; do not merge")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Send a desktop notification (notify-send) summarising the run",
    )
    parser.add_argument("--model", default=None, help="Claude model alias or id for the agent review")


def cmd_status(args: argparse.Namespace) -> int:
    rows = []
    for path in _selected_plugins([]):
        plugin_id = path.name
        origin = remote_url(path)
        try:
            head = rev_parse(path, "HEAD")
        except GitError as exc:
            rows.append({"id": plugin_id, "error": str(exc)})
            continue
        stored = load_baseline(plugin_id)
        rows.append(
            {
                "id": plugin_id,
                "origin": origin,
                "head": head,
                "baseline_commit": stored.commit if stored else None,
                "baseline_origin": stored.origin if stored else None,
                "baseline_has_commands": (
                    None if stored is None else stored.capabilities.command_lines is not None
                ),
            }
        )
    if args.json:
        print(json.dumps({"plugins": rows}, indent=2))
    else:
        if not rows:
            print("No git-managed plugins installed.")
            return 0
        for row in rows:
            if row.get("error"):
                print(f"{row['id']}: error: {row['error']}")
                continue
            if not row["baseline_commit"]:
                mark = "no-baseline"
            elif row["baseline_has_commands"] is False:
                mark = "baseline: old format, re-run baseline --write"
            else:
                mark = "baseline"
            print(f"{row['id']}: {row['head'][:12]} {row['origin'] or '(no origin)'} [{mark}]")
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    reports = []
    for path in _selected_plugins(args.ids):
        findings, caps = scan_tree(path)
        origin = remote_url(path) if is_git_plugin(path) else ""
        commit = rev_parse(path, "HEAD") if is_git_plugin(path) else ""
        save_baseline(path.name, origin, commit, caps)
        reports.append(
            {
                "id": path.name,
                "commit": commit,
                "origin": origin,
                "capabilities": caps.to_dict(),
                "findings": findings_to_dict(findings),
            }
        )
        if not args.json:
            print(f"Wrote baseline for {path.name} at {commit[:12] or 'unversioned'}")
    if args.json:
        print(json.dumps({"baselines": reports}, indent=2))
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    args.yes = False
    args.force = False
    args.auto = False
    args.dry_run = True
    return cmd_update(args)


def cmd_update(args: argparse.Namespace) -> int:
    policy: AutoPolicy | None = None
    if getattr(args, "auto", False):
        policy = AutoPolicy.from_env(
            soak_days=getattr(args, "soak_days", None),
            max_diff_lines=getattr(args, "max_diff_lines", None),
        )
    reports: list[PluginReport] = []
    for path in _selected_plugins(args.ids):
        reports.append(
            _review_and_maybe_apply(
                path,
                skip_agent=args.skip_agent,
                dry_run=args.dry_run,
                assume_yes=getattr(args, "yes", False),
                force=getattr(args, "force", False),
                policy=policy,
                model=getattr(args, "model", None),
            )
        )
    code = _emit(reports, args.json)
    if getattr(args, "notify", False):
        _notify(reports)
    return code


def cmd_add(args: argparse.Namespace) -> int:
    report = _add_plugin(args)
    return _emit([report], args.json)


def _progress(message: str) -> None:
    print(f"omarchy-plugin-guard: {message}", file=sys.stderr, flush=True)


def _add_plugin(args: argparse.Namespace) -> PluginReport:
    url = args.url
    _progress(f"checking git URL {url}")
    try:
        check_git_url(url)
    except ApplyError as exc:
        return PluginReport(id="", status="error", error=str(exc), origin=url)

    tmp = Path(tempfile.mkdtemp(prefix="omarchy-plugin-guard-add-"))
    clone_dir = tmp / "clone"
    try:
        _progress("cloning (may take a while with no extra output)")
        clone(url, clone_dir)
        _progress("validating manifest")
        validate_plugin(clone_dir)
        plugin_id = json.loads((clone_dir / "manifest.json").read_text(encoding="utf-8"))["id"]
        if not _valid_id(plugin_id):
            return PluginReport(id=str(plugin_id), status="error", error="invalid plugin id", origin=url)
        _progress(f"plugin id is {plugin_id}")
        target = plugins_dir() / plugin_id
        if target.exists():
            return PluginReport(
                id=plugin_id,
                status="error",
                error=f"already installed; update with: omarchy-plugin-guard update {plugin_id}",
                origin=url,
            )
        _progress("running mechanical scan")
        empty = Capabilities()
        findings, caps = scan_tree(clone_dir)
        expansion = capability_expansion(empty, caps)
        new_sha = rev_parse(clone_dir, "HEAD")
        work = _review_workspace()
        try:
            _write_review_workspace(
                work, clone_dir, findings, caps, expansion, diff_text="(new install; full tree in snapshot/)"
            )
            _progress("mechanical scan finished")
            agent = _maybe_agent(
                work,
                plugin_id=plugin_id,
                origin=url,
                old_sha="(none)",
                new_sha=new_sha,
                expansion=expansion,
                findings=findings,
                caps=caps,
                diff_text="(new install)",
                skip_agent=args.skip_agent,
                model=getattr(args, "model", None),
            )
        finally:
            _discard_workspace(work)
        report = PluginReport(
            id=plugin_id,
            status="reviewed",
            verdict=None,
            from_sha="",
            to_sha=new_sha,
            origin=url,
            expansion=expansion,
            findings=findings_to_dict(findings),
            agent=agent,
            mode="dry-run" if args.dry_run else "manual",
        )
        if agent and agent.get("error"):
            report.status = "error"
            report.error = f"agent review failed: {agent['error']}"
            _audit(report)
            return report
        blocked = has_block_findings(findings)
        combined = combine_verdict(
            blocked=blocked,
            expansion=expansion,
            origin_changed=False,
            history_rewritten=False,
            has_baseline=False,
            agent_verdict=None if agent is None else agent.get("verdict"),
            agent_denied_calls=0 if agent is None else int(agent.get("denied_calls") or 0),
        )
        report.verdict = combined.verdict
        report.reasons = combined.reasons
        if args.dry_run:
            _audit(report)
            return report
        if combined.verdict == "deny":
            _print_human_gate(report, action="install")
            report.status = "denied"
            _audit(report)
            return report
        if not _should_apply(report, assume_yes=args.yes, force=args.force, action="install"):
            report.status = "skipped"
            _audit(report)
            return report
        install_reviewed_clone(clone_dir, target)
        save_baseline(plugin_id, url, report.to_sha, caps)
        report.status = "applied"
        if args.enable:
            try:
                enable_plugin(plugin_id)
            except ApplyError as exc:
                report.error = f"installed but enable failed: {exc}"
        _audit(report)
        return report
    except (GitError, ApplyError, OSError, json.JSONDecodeError, KeyError) as exc:
        return PluginReport(id="", status="error", error=str(exc), origin=url)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _review_and_maybe_apply(
    path: Path,
    *,
    skip_agent: bool,
    dry_run: bool,
    assume_yes: bool,
    force: bool,
    policy: AutoPolicy | None = None,
    model: str | None = None,
) -> PluginReport:
    plugin_id = path.name
    if not is_git_plugin(path):
        return PluginReport(id=plugin_id, status="error", error="not a git checkout")
    mode = "dry-run" if dry_run else ("auto" if policy is not None else "manual")
    try:
        origin = remote_url(path)
        old_sha = rev_parse(path, "HEAD")
        print(f"Fetching {plugin_id}...", file=sys.stderr, flush=True)
        fetch_origin(path)
        new_sha = rev_parse(path, "FETCH_HEAD")
        dirty_text = git(path, "status", "--porcelain").stdout
        incoming = []
        if old_sha != new_sha:
            incoming = git_out(
                path, "log", "--oneline", "--no-decorate", f"{old_sha}..{new_sha}"
            ).splitlines()
    except GitError as exc:
        return PluginReport(id=plugin_id, status="error", error=str(exc), mode=mode)

    if old_sha == new_sha:
        clear_first_seen(plugin_id)
        return PluginReport(
            id=plugin_id,
            status="up_to_date",
            from_sha=old_sha,
            to_sha=new_sha,
            origin=origin,
            mode=mode,
        )

    if is_ancestor(path, new_sha, old_sha):
        # Origin rewound, or this checkout carries local commits. A fast-forward
        # to an ancestor is a no-op, so there is nothing to review or apply.
        clear_first_seen(plugin_id)
        return PluginReport(
            id=plugin_id,
            status="ahead",
            from_sha=old_sha,
            to_sha=new_sha,
            origin=origin,
            reasons=["local checkout is ahead of origin; nothing to apply"],
            mode=mode,
        )

    if dirty_text:
        reasons = []
        local_paths = _porcelain_paths(dirty_text)
        if local_paths:
            reasons.append("local: " + ", ".join(local_paths[:12]))
        reasons.extend(f"incoming {line}" for line in incoming[:12])
        return PluginReport(
            id=plugin_id,
            status="blocked",
            error=(
                "update available; not applied because the working tree has local changes "
                "— stash, commit, or reset, then re-run update"
            ),
            origin=origin,
            from_sha=old_sha,
            to_sha=new_sha,
            reasons=reasons or None,
            mode=mode,
        )

    stored = load_baseline(plugin_id)
    history_rewritten = not is_ancestor(path, old_sha, new_sha)
    origin_changed = bool(stored and stored.origin and stored.origin != origin)
    diff_text = diff(path, old_sha, new_sha)
    diff_truncated = len(diff_text) > DIFF_LIMIT
    diff_lines = count_diff_lines(diff_text)
    first_seen = note_first_seen(plugin_id, new_sha)

    with tempfile.TemporaryDirectory(prefix="omarchy-plugin-guard-") as raw:
        tmp = Path(raw)
        old_tree = tmp / "old"
        new_tree = tmp / "snapshot"
        snapshot(path, old_sha, old_tree)
        snapshot(path, new_sha, new_tree)
        _, old_caps = scan_tree(old_tree)
        findings, new_caps = scan_tree(new_tree)
        expansion = capability_expansion(old_caps, new_caps)
        if stored:
            for item in capability_expansion(stored.capabilities, new_caps):
                if item not in expansion:
                    expansion.append(item)
        work = _review_workspace()
        try:
            _write_review_workspace(work, new_tree, findings, new_caps, expansion, diff_text)
            agent = _maybe_agent(
                work,
                plugin_id=plugin_id,
                origin=origin,
                old_sha=old_sha,
                new_sha=new_sha,
                expansion=expansion,
                findings=findings,
                caps=new_caps,
                diff_text=diff_text,
                skip_agent=skip_agent,
                model=model,
            )
        finally:
            _discard_workspace(work)

    report = PluginReport(
        id=plugin_id,
        status="reviewed",
        from_sha=old_sha,
        to_sha=new_sha,
        origin=origin,
        expansion=expansion,
        findings=findings_to_dict(findings),
        agent=agent,
        diff_lines=diff_lines,
        diff_truncated=diff_truncated,
        first_seen_at=first_seen.isoformat(timespec="seconds"),
        mode=mode,
    )
    if agent and agent.get("error"):
        # Not a judgement about the plugin: report it, keep the SHA pending,
        # and let the next run retry.
        report.status = "error"
        report.error = f"agent review failed: {agent['error']}"
        _save_review(report)
        _audit(report)
        return report

    blocked = has_block_findings(findings)
    combined = combine_verdict(
        blocked=blocked,
        expansion=expansion,
        origin_changed=origin_changed,
        history_rewritten=history_rewritten,
        has_baseline=stored is not None,
        agent_verdict=None if agent is None else agent.get("verdict"),
        diff_truncated=diff_truncated,
        agent_denied_calls=0 if agent is None else int(agent.get("denied_calls") or 0),
    )
    report.verdict = combined.verdict
    report.reasons = combined.reasons
    _save_review(report)
    if dry_run:
        _audit(report)
        return report
    if combined.verdict == "deny":
        _print_human_gate(report, action="update")
        report.status = "denied"
        _audit(report)
        return report

    if policy is not None:
        if combined.verdict != "allow":
            _print_human_gate(report, action="update")
            _audit(report)
            return report
        decision = evaluate_auto_apply(
            policy=policy,
            verdict=combined.verdict,
            diff_truncated=diff_truncated,
            diff_lines=diff_lines,
            old_caps=stored.capabilities if stored else None,
            new_caps=new_caps,
            first_seen_at=first_seen,
            now=now_utc(),
        )
        if not decision.apply:
            report.status = "deferred"
            report.policy = decision.reasons
            _audit(report)
            return report
    elif not _should_apply(report, assume_yes=assume_yes, force=force, action="update"):
        report.status = "skipped"
        _audit(report)
        return report

    try:
        apply_reviewed_update(path, new_sha)
    except ApplyError as exc:
        report.status = "error"
        report.error = str(exc)
        _audit(report)
        return report
    save_baseline(plugin_id, origin, new_sha, new_caps)
    clear_first_seen(plugin_id)
    report.status = "applied"
    _audit(report)
    return report


def _maybe_agent(
    work: Path,
    *,
    plugin_id: str,
    origin: str,
    old_sha: str,
    new_sha: str,
    expansion: list[str],
    findings: list[Any],
    caps: Capabilities,
    diff_text: str,
    skip_agent: bool,
    model: str | None = None,
) -> dict[str, Any] | None:
    if skip_agent:
        _progress(f"skipping agent review of {plugin_id}")
        return None
    chosen = (model or "").strip() or default_model()
    _progress(
        f"starting agent review of {plugin_id} with claude ({chosen}); "
        "this often looks idle for 30–120s until the agent returns"
    )
    scan_payload = {
        "findings": findings_to_dict(findings),
        "capabilities": caps.to_dict(),
        "expansion": expansion,
    }
    try:
        review = run_agent_review(
            workspace=work,
            plugin_id=plugin_id,
            origin=origin,
            old_sha=old_sha,
            new_sha=new_sha,
            expansion=expansion,
            scan_payload=scan_payload,
            diff_text=diff_text,
            model=chosen,
        )
    except ReviewError as exc:
        _progress(f"agent review failed: {exc}")
        return {"error": str(exc), "model": chosen}
    _progress(f"agent finished: {review.verdict}")
    return {
        "verdict": review.verdict,
        "summary": review.summary,
        "findings": review.findings,
        "run_id": review.run_id,
        "model": chosen,
        "denied_calls": review.denied_calls,
        "turns": review.turns,
        "cost_usd": review.cost_usd,
    }


def _review_workspace() -> Path:
    """A fixed path, so every headless session maps to one Claude project dir."""
    work = state_dir() / "workspace"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    return work


def _discard_workspace(work: Path) -> None:
    shutil.rmtree(work, ignore_errors=True)


def _write_review_workspace(
    work: Path,
    snapshot_dir: Path,
    findings: list[Any],
    caps: Capabilities,
    expansion: list[str],
    diff_text: str,
) -> None:
    work.mkdir(parents=True, exist_ok=True)
    dest = work / "snapshot"
    if snapshot_dir.resolve() != dest.resolve():
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(snapshot_dir, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    renamed = sanitize_snapshot(dest)
    (work / "SCAN.json").write_text(
        json.dumps(
            {
                "findings": findings_to_dict(findings),
                "capabilities": caps.to_dict(),
                "expansion": expansion,
                "renamed_instruction_files": renamed,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    body = diff_text
    if len(body) > DIFF_LIMIT:
        body = body[:DIFF_LIMIT] + "\n\n[truncated]\n"
    (work / "DIFF.patch").write_text(body, encoding="utf-8")


def sanitize_snapshot(root: Path) -> list[str]:
    """Rename agent-instruction files so no harness mistakes them for config.

    Returns the relative paths that were renamed, for the scan report.
    """
    renamed: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        base = Path(dirpath)
        for name in list(dirnames) + list(filenames):
            if name not in UNTRUSTED_INSTRUCTION_NAMES:
                continue
            src = base / name
            dst = base / f"{UNTRUSTED_PREFIX}{name}"
            src.rename(dst)
            renamed.append(src.relative_to(root).as_posix())
            if name in dirnames:
                dirnames[dirnames.index(name)] = dst.name
    return sorted(renamed)


def format_human_gate(report: PluginReport, *, action: str) -> str:
    """Text shown before accept/deny. Kept as a pure string so tests can lock the wording."""
    verb = "Install" if action == "install" else "Update"
    if report.verdict == "deny":
        title = "DENIED — will not apply"
        closing = "This update is blocked. It will not be applied."
    else:
        title = "NEEDS HUMAN REVIEW"
        closing = f"{verb} only if you accept the risk."
    lines = [
        "",
        "=" * 60,
        title,
        f"plugin: {report.id or '(unknown)'}",
    ]
    if report.from_sha and report.to_sha:
        lines.append(f"{action}: {report.from_sha[:12]} -> {report.to_sha[:12]}")
    elif report.to_sha:
        lines.append(f"{action}: {report.to_sha[:12]}")
    if report.origin:
        lines.append(f"origin: {report.origin}")
    lines.append("")
    lines.append("Why a human has to decide:")
    reasons = list(report.reasons or [])
    if not reasons:
        reasons = ["review did not produce a specific reason"]
    for reason in reasons:
        lines.append(f"  - {reason}")
    agent = report.agent or {}
    if agent.get("summary"):
        lines.append("")
        lines.append("Agent summary:")
        lines.append(f"  {agent['summary']}")
    agent_findings = [item for item in (agent.get("findings") or []) if isinstance(item, dict)]
    if agent_findings:
        lines.append("")
        lines.append("Agent findings:")
        for item in agent_findings[:8]:
            path = item.get("path") or ""
            why = item.get("why") or ""
            severity = item.get("severity") or "warn"
            extra = f" {path}" if path else ""
            detail = f": {why}" if why else ""
            lines.append(f"  - [{severity}]{extra}{detail}")
    blocks = [item for item in (report.findings or []) if item.get("severity") == "block"]
    if blocks:
        lines.append("")
        lines.append("Mechanical blocks:")
        for item in blocks[:8]:
            where = item.get("path") or ""
            line = f":{item['line']}" if item.get("line") else ""
            snippet = item.get("snippet") or ""
            extra = f" {snippet}" if snippet else ""
            lines.append(f"  - {item.get('rule')} {where}{line}{extra}")
    lines.append("")
    lines.append(closing)
    lines.append("=" * 60)
    return "\n".join(lines)


def _print_human_gate(report: PluginReport, *, action: str) -> None:
    print(format_human_gate(report, action=action), file=sys.stderr, flush=True)


def _should_apply(
    report: PluginReport,
    *,
    assume_yes: bool,
    force: bool,
    action: str,
) -> bool:
    verdict = report.verdict
    if verdict == "deny":
        return False
    verb = "Install" if action == "install" else "Update"
    sha = ""
    if report.from_sha and report.to_sha:
        sha = f" {report.from_sha[:8]} -> {report.to_sha[:8]}"
    if verdict == "allow":
        return confirm(f"{verb} {report.id}{sha}?", assume_yes=assume_yes)
    if verdict == "needs-human":
        _print_human_gate(report, action=action)
        if force:
            return True
        if assume_yes:
            print(
                "omarchy-plugin-guard: needs human review; pass --force to apply without a prompt",
                file=sys.stderr,
            )
            return False
        return confirm(f"Accept this {action} for {report.id}?", assume_yes=False)
    return False


def _save_review(report: PluginReport) -> None:
    reviews_dir().mkdir(parents=True, exist_ok=True)
    path = reviews_dir() / f"{report.id}.json"
    path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")


def _audit(report: PluginReport) -> None:
    agent = report.agent or {}
    agent_summary = {
        key: agent.get(key)
        for key in ("verdict", "summary", "findings", "run_id", "model", "denied_calls", "error")
        if agent.get(key) not in (None, "", [], 0)
    }
    blocks = [item for item in (report.findings or []) if item.get("severity") == "block"]
    event = {
        "event": report.status,
        "plugin": report.id,
        "mode": report.mode,
        "verdict": report.verdict,
        "from": report.from_sha or None,
        "to": report.to_sha or None,
        "origin": report.origin or None,
        "reasons": report.reasons,
        "expansion": report.expansion or None,
        "policy": report.policy,
        "diff_lines": report.diff_lines,
        "diff_truncated": report.diff_truncated,
        "first_seen_at": report.first_seen_at,
        "agent": agent_summary or None,
        "blocks": blocks or None,
        "error": report.error,
    }
    append_audit({key: value for key, value in event.items() if value is not None})


def _emit(reports: list[PluginReport], as_json: bool) -> int:
    if as_json:
        print(json.dumps({"results": [item.to_dict() for item in reports]}, indent=2))
    else:
        if not reports:
            print("No git-managed plugins installed.")
        for item in reports:
            _print_report(item)
    if any(item.status in {"error", "blocked"} for item in reports):
        return 1
    if any(item.status in {"denied", "skipped"} or item.verdict == "deny" for item in reports):
        return 2
    return 0


def _print_report(item: PluginReport) -> None:
    head = f"{item.id}: {item.status}"
    if item.verdict:
        head += f" ({item.verdict})"
    if item.from_sha and item.to_sha and item.from_sha != item.to_sha:
        head += f" {item.from_sha[:8]} -> {item.to_sha[:8]}"
    print(head)
    if item.error:
        prefix = "  error: " if item.status == "error" else "  "
        print(f"{prefix}{item.error}")
    if item.reasons:
        for reason in item.reasons:
            print(f"  {reason}")
    if item.policy:
        for reason in item.policy:
            print(f"  auto-apply deferred: {reason}")
    if item.expansion and not any(
        reason.startswith("capability expansion") for reason in (item.reasons or [])
    ):
        print("  expansion: " + ", ".join(item.expansion))
    blocks = [finding for finding in (item.findings or []) if finding.get("severity") == "block"]
    for finding in blocks[:8]:
        where = finding.get("path", "")
        line = f":{finding['line']}" if finding.get("line") else ""
        print(f"  block {finding.get('rule')} {where}{line}")
    if item.agent and item.agent.get("summary"):
        print(f"  agent: {item.agent['summary']}")
    if item.agent and item.agent.get("error"):
        print(f"  agent error: {item.agent['error']}")


def summarize_for_notification(reports: list[PluginReport]) -> tuple[str, str, str] | None:
    """(title, body, urgency) for notify-send, or None when there is nothing to say."""
    applied = [r.id for r in reports if r.status == "applied"]
    ready = [r.id for r in reports if r.status in {"reviewed", "deferred"} and r.verdict == "allow"]
    human = [r.id for r in reports if r.status == "reviewed" and r.verdict == "needs-human"]
    denied = [r.id for r in reports if r.status == "denied" or r.verdict == "deny"]
    errors = [r.id for r in reports if r.status in {"error", "blocked"}]
    if not any((applied, ready, human, denied, errors)):
        return None
    lines: list[str] = []
    if applied:
        lines.append(f"applied: {', '.join(applied)}")
    if ready:
        lines.append(f"allow, run update --yes: {', '.join(ready)}")
    if human:
        lines.append(f"needs human: {', '.join(human)}")
    if denied:
        lines.append(f"DENIED: {', '.join(denied)}")
    if errors:
        lines.append(f"errors: {', '.join(errors)}")
    total = len(applied) + len(ready) + len(human) + len(denied) + len(errors)
    title = f"omarchy-plugin-guard: {total} plugin update{'s' if total != 1 else ''}"
    urgency = "critical" if denied or errors else "normal"
    return title, "\n".join(lines), urgency


def _notify(reports: list[PluginReport]) -> None:
    binary = shutil.which("notify-send")
    if not binary:
        return
    summary = summarize_for_notification(reports)
    if summary is None:
        return
    title, body, urgency = summary
    subprocess.run(
        [binary, "-a", "omarchy-plugin-guard", "-u", urgency, title, body],
        capture_output=True,
        text=True,
    )


def _selected_plugins(ids: list[str]) -> list[Path]:
    root = plugins_dir()
    if not root.is_dir():
        raise ApplyError(f"plugins directory not found: {root}")
    if not ids:
        return list_git_plugins(root)
    selected: list[Path] = []
    for plugin_id in ids:
        if not _valid_id(plugin_id):
            raise ApplyError(f"invalid plugin id '{plugin_id}'")
        path = root / plugin_id
        if not path.is_dir():
            raise ApplyError(f"plugin '{plugin_id}' is not installed")
        selected.append(path)
    return selected


def _porcelain_paths(porcelain: str) -> list[str]:
    paths: list[str] = []
    for line in porcelain.splitlines():
        if not line:
            continue
        if " -> " in line[3:]:
            paths.append(line.split(" -> ", 1)[1])
            continue
        paths.append(line[3:] if len(line) > 3 else line.lstrip())
    return paths


def _valid_id(plugin_id: str) -> bool:
    return bool(PLUGIN_ID_RE.match(plugin_id) and ".." not in plugin_id)
