from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from omarchy_plugin_guard.gitops import GitError, merge_ff_only, reset_hard, rev_parse


class ApplyError(RuntimeError):
    pass


def run_cmd(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "command failed"
        raise ApplyError(f"{' '.join(args)}: {detail}")
    return result


def validate_plugin(folder: Path) -> None:
    binary = shutil.which("omarchy-plugin-validate") or shutil.which("omarchy")
    if shutil.which("omarchy-plugin-validate"):
        run_cmd(["omarchy-plugin-validate", str(folder)])
        return
    if binary:
        run_cmd(["omarchy", "plugin", "validate", str(folder)])
        return
    raise ApplyError("omarchy-plugin-validate is not on PATH")


def check_git_url(url: str) -> None:
    checker = shutil.which("omarchy-git-url-check")
    if checker:
        run_cmd([checker, url])


def rescan_plugins() -> None:
    binary = shutil.which("omarchy-shell")
    if not binary:
        return
    subprocess.run(
        ["omarchy-shell", "shell", "rescanPlugins"],
        capture_output=True,
        text=True,
    )


def apply_reviewed_update(plugin_dir: Path, reviewed_sha: str) -> None:
    orig = rev_parse(plugin_dir, "HEAD")
    try:
        merge_ff_only(plugin_dir, reviewed_sha)
        validate_plugin(plugin_dir)
    except (GitError, ApplyError) as exc:
        try:
            reset_hard(plugin_dir, orig)
        except GitError:
            pass
        raise ApplyError(str(exc)) from exc
    rescan_plugins()


def install_reviewed_clone(snapshot_or_clone: Path, target: Path) -> None:
    if target.exists() or target.is_symlink():
        raise ApplyError(f"plugin directory already exists: {target}")
    validate_plugin(snapshot_or_clone)
    shutil.move(str(snapshot_or_clone), str(target))
    rescan_plugins()


def enable_plugin(plugin_id: str) -> None:
    last = "enable failed"
    for _ in range(40):
        result = subprocess.run(
            ["omarchy", "plugin", "enable", plugin_id],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return
        last = (result.stderr or result.stdout).strip() or last
        time.sleep(0.05)
    raise ApplyError(last)
