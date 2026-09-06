from __future__ import annotations

import os
import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env.setdefault("GIT_SSH_COMMAND", "ssh -oBatchMode=yes")
    return env


def git(
    repo: Path,
    *args: str,
    check: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            env=_env(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {' '.join(args)}: timed out after {timeout}s") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "git failed"
        raise GitError(f"git {' '.join(args)}: {detail}")
    return result


def git_out(repo: Path, *args: str) -> str:
    return git(repo, *args).stdout.strip()


def is_git_plugin(path: Path) -> bool:
    return (path / ".git").exists()


def remote_url(repo: Path) -> str:
    result = git(repo, "remote", "get-url", "origin", check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def rev_parse(repo: Path, rev: str) -> str:
    return git_out(repo, "rev-parse", rev)


def short_sha(sha: str) -> str:
    return sha[:12]


def fetch_origin(repo: Path) -> None:
    git(repo, "fetch", "--quiet", "origin", "HEAD", timeout=45)


def clone(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["git", "clone", "--", url, str(dest)],
            capture_output=True,
            text=True,
            env=_env(),
            timeout=90,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"clone timed out after 90s: {url}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "clone failed"
        raise GitError(detail)


def is_ancestor(repo: Path, older: str, newer: str) -> bool:
    result = git(repo, "merge-base", "--is-ancestor", older, newer, check=False)
    return result.returncode == 0


def diff(repo: Path, old: str, new: str) -> str:
    result = git(repo, "diff", "--find-renames", f"{old}...{new}", check=True)
    return result.stdout


def snapshot(repo: Path, rev: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", rev],
        capture_output=True,
        env=_env(),
    )
    if archive.returncode != 0:
        detail = archive.stderr.decode("utf-8", "replace").strip() or "archive failed"
        raise GitError(detail)
    extract = subprocess.run(
        ["tar", "-xf", "-", "-C", str(dest)],
        input=archive.stdout,
        capture_output=True,
    )
    if extract.returncode != 0:
        detail = extract.stderr.decode("utf-8", "replace").strip() or "tar failed"
        raise GitError(detail)


def merge_ff_only(repo: Path, rev: str) -> None:
    git(repo, "merge", "--ff-only", rev)


def reset_hard(repo: Path, rev: str) -> None:
    git(repo, "reset", "--hard", rev)


def list_git_plugins(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    found: list[Path] = []
    for child in sorted(root.iterdir()):
        if child.is_dir() and not child.name.startswith(".") and is_git_plugin(child):
            found.append(child)
    return found
