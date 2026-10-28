from __future__ import annotations

import hashlib
import json
import re
import stat
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

BLOCK = "block"
NOTE = "note"

TEXT_SUFFIXES = {
    ".qml",
    ".js",
    ".mjs",
    ".json",
    ".md",
    ".txt",
    ".svg",
    ".css",
    ".toml",
    ".xml",
    ".html",
    ".yml",
    ".yaml",
    ".license",
}
SCRIPT_SUFFIXES = {".py", ".sh", ".bash", ".zsh"}
NATIVE_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".go"}
ASSET_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".ico",
    ".mp4",
    ".webm",
    ".mov",
    ".wav",
    ".ogg",
}
SKIP_DIR_NAMES = {".git"}
HARMLESS_NAMES = {
    "license",
    "licence",
    "copying",
    "readme",
    "readme.md",
    "changelog",
    "changelog.md",
    "makefile",
    "pkgbuild",
    ".srcinfo",
    ".gitignore",
}

# Matches both the QML binding form `command: [...]` and the imperative
# `proc.command = [...]`. The array body is extracted by _extract_array so
# that brackets inside shell strings (`[[ -f "$f" ]]`) do not cut it short.
COMMAND_START = re.compile(r"(?<![A-Za-z0-9_])command\s*[:=]\s*\[")
QUOTED = re.compile(r"""(['"])((?:\\.|(?!\1).)*)\1""", re.DOTALL)
COMMAND_SCAN_LIMIT = 4000
COMMAND_LABEL_LIMIT = 96

CONTENT_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "pipe_to_shell",
        BLOCK,
        re.compile(
            r"(curl|wget)\b[^\n]{0,120}\|\s*(?:ba)?sh\b"
            r"|base64\s+-d[^\n]{0,80}\|\s*(?:ba)?sh\b",
            re.IGNORECASE,
        ),
    ),
    (
        "credentials",
        BLOCK,
        re.compile(
            r"(?:~|/home/[^/\s]+)/\.ssh\b"
            r"|/\.ssh/"
            r"|/\.gnupg\b"
            r"|password-store"
            r"|/\.netrc\b"
            r"|id_rsa\b"
            r"|GNUPGHOME",
            re.IGNORECASE,
        ),
    ),
    (
        # Tokens and credential stores for tools that run on this machine. A
        # NOTE, not a BLOCK: a usage-meter plugin may read these legitimately,
        # but a *new* reference is a capability expansion that needs a human.
        "credential_stores",
        NOTE,
        re.compile(
            r"\.claude/\.credentials"
            r"|proton-pass-agent"
            r"|ANTHROPIC_API_KEY"
            r"|CLAUDE_CODE_OAUTH_TOKEN"
            r"|CURSOR_API_KEY"
            r"|\.config/gh/hosts\.yml"
            r"|\.aws/credentials"
            r"|\.kube/config"
            r"|\.docker/config\.json"
            r"|\bsecret-tool\b",
        ),
    ),
    (
        "eval_dynamic",
        BLOCK,
        re.compile(r"\beval\s*\(|Qt\.createQmlObject\s*\("),
    ),
    (
        "process",
        NOTE,
        re.compile(r"\bProcess\s*\{|\bQuickshell\.Io\b"),
    ),
    (
        "privileged",
        NOTE,
        re.compile(r"\b(pkexec|sudo)\b"),
    ),
    (
        "network",
        NOTE,
        re.compile(r"\bXMLHttpRequest\b|\bWebSocket\b|\bQNetworkAccessManager\b"),
    ),
    (
        "filesystem",
        NOTE,
        re.compile(r"\bFileView\s*\{|\bStandardPaths\b|\bFileIo\b"),
    ),
]


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int | None
    snippet: str


@dataclass
class Capabilities:
    kinds: list[str] = field(default_factory=list)
    manifest_version: str = ""
    flags: dict[str, bool] = field(default_factory=dict)
    process_binaries: list[str] = field(default_factory=list)
    unexpected_files: list[str] = field(default_factory=list)
    # One signature per full `command: [...]` array. None means the baseline
    # predates signatures (old on-disk format) and cannot vouch for commands.
    command_lines: list[str] | None = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Capabilities:
        raw_commands = data.get("command_lines")
        return cls(
            kinds=list(data.get("kinds") or []),
            manifest_version=str(data.get("manifest_version") or ""),
            flags=dict(data.get("flags") or {}),
            process_binaries=list(data.get("process_binaries") or []),
            unexpected_files=list(data.get("unexpected_files") or []),
            command_lines=None if raw_commands is None else list(raw_commands),
        )

    def runs_code(self) -> bool:
        """True when the tree can execute anything beyond declarative QML."""
        risky = (
            "process",
            "network",
            "helper_scripts",
            "native_source",
            "native_binaries",
            "privileged",
            "eval_dynamic",
            "pipe_to_shell",
            "sudoers",
        )
        return any(self.flags.get(name, False) for name in risky)


def empty_flags() -> dict[str, bool]:
    return {
        "process": False,
        "network": False,
        "filesystem": False,
        "credentials": False,
        "credential_stores": False,
        "privileged": False,
        "helper_scripts": False,
        "native_source": False,
        "native_binaries": False,
        "sudoers": False,
        "eval_dynamic": False,
        "pipe_to_shell": False,
    }


def scan_tree(root: Path) -> tuple[list[Finding], Capabilities]:
    findings: list[Finding] = []
    flags = empty_flags()
    binaries: set[str] = set()
    commands: set[str] = set()
    unexpected: list[str] = []
    kinds: list[str] = []
    manifest_version = ""

    manifest_path = root / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            kinds = [str(k) for k in (manifest.get("kinds") or [])]
            manifest_version = str(manifest.get("version") or "")
        except json.JSONDecodeError:
            findings.append(
                Finding("manifest", BLOCK, "manifest.json", None, "manifest.json is not valid JSON")
            )

    for path in _iter_files(root):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            findings.append(Finding("symlink", BLOCK, rel, None, "symlink inside plugin tree"))
            continue

        mode = path.stat().st_mode
        executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        suffix = path.suffix.lower()
        name = path.name.lower()

        if name.endswith(".sudoers") or name == "sudoers":
            flags["sudoers"] = True
        if suffix in SCRIPT_SUFFIXES:
            flags["helper_scripts"] = True
        if suffix in NATIVE_SOURCE_SUFFIXES:
            flags["native_source"] = True

        head = path.read_bytes()[:8192]
        if suffix in ASSET_SUFFIXES:
            continue
        if head.startswith(b"\x7fELF"):
            flags["native_binaries"] = True
            unexpected.append(rel)
            findings.append(
                Finding("native_binary", NOTE, rel, None, "native/binary file")
            )
            continue
        if _is_binary(head):
            unexpected.append(rel)
            continue

        if executable and suffix not in SCRIPT_SUFFIXES | TEXT_SUFFIXES:
            flags["native_binaries"] = True
            unexpected.append(rel)
            findings.append(
                Finding("executable", NOTE, rel, None, "executable without a script suffix")
            )

        if (
            suffix not in TEXT_SUFFIXES | SCRIPT_SUFFIXES | NATIVE_SOURCE_SUFFIXES
            and name not in HARMLESS_NAMES
            and not name.startswith(".")
        ):
            unexpected.append(rel)

        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            flags["native_binaries"] = True
            unexpected.append(rel)
            continue

        test_path = is_test_path(rel)
        for rule, severity, pattern in CONTENT_RULES:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                snippet = _clip(match.group(0))
                effective = severity
                if rule in TEST_NOTE_RULES and severity == BLOCK and test_path:
                    # A test harness under tests/ is never loaded by the shell,
                    # and tests often feed hostile strings in to prove they are
                    # rejected. Keep the capability flag so a *new* hit in tests
                    # is still an expansion that needs a human, but do not
                    # hard-deny.
                    effective = NOTE
                    snippet = f"{snippet} (test file; note only)"
                findings.append(Finding(rule, effective, rel, line, snippet))
                if rule in flags:
                    flags[rule] = True

        for inner in iter_command_arrays(text):
            flags["process"] = True
            commands.add(command_signature(inner))
            for token in _command_tokens(inner):
                binaries.add(token)

    caps = Capabilities(
        kinds=kinds,
        manifest_version=manifest_version,
        flags=flags,
        process_binaries=sorted(binaries),
        unexpected_files=sorted(set(unexpected)),
        command_lines=sorted(commands),
    )
    return findings, caps


# BLOCK rules that drop to NOTE inside a test path (see scan_tree).
TEST_NOTE_RULES = {"eval_dynamic", "pipe_to_shell"}
TEST_DIR_NAMES = {"test", "tests", "__tests__", "spec", "specs"}
TEST_FILE_RE = re.compile(r"(?:[._-]test|[._-]spec)\.[cm]?js$", re.IGNORECASE)


def is_test_path(rel: str) -> bool:
    """True for files under a test directory or named like a JS test."""
    parts = rel.split("/")
    if any(part.lower() in TEST_DIR_NAMES for part in parts[:-1]):
        return True
    return bool(TEST_FILE_RE.search(parts[-1]))


def iter_command_arrays(text: str) -> Iterable[str]:
    """Yield the body of every `command: [...]` / `command = [...]` array."""
    for match in COMMAND_START.finditer(text):
        yield _extract_array(text, match.end())


def _extract_array(text: str, start: int, limit: int = COMMAND_SCAN_LIMIT) -> str:
    depth = 1
    quote: str | None = None
    i = start
    end = min(len(text), start + limit)
    while i < end:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return text[start:i]
        i += 1
    # Unterminated or over the limit: keep what we saw so a change still
    # changes the signature.
    return text[start:end] + " [unterminated]"


def command_signature(inner: str) -> str:
    """Stable, human-readable identity for one command array.

    The label is for humans reading baselines and reports; the digest makes
    the comparison exact even when the label is clipped.
    """
    compact = " ".join(inner.split())
    digest = hashlib.sha256(compact.encode("utf-8")).hexdigest()[:12]
    label = compact if len(compact) <= COMMAND_LABEL_LIMIT else compact[: COMMAND_LABEL_LIMIT - 1] + "…"
    return f"{label} #{digest}"


def capability_expansion(old: Capabilities, new: Capabilities) -> list[str]:
    changes: list[str] = []
    old_kinds = set(old.kinds)
    for kind in new.kinds:
        if kind not in old_kinds:
            changes.append(f"kind:{kind}")
    for flag, enabled in new.flags.items():
        if enabled and not old.flags.get(flag, False):
            changes.append(f"flag:{flag}")
    old_bins = set(old.process_binaries)
    for binary in new.process_binaries:
        if binary not in old_bins:
            changes.append(f"process:{binary}")
    new_commands = list(new.command_lines or [])
    if old.command_lines is None:
        if new_commands:
            changes.append("baseline:no command signatures recorded (re-run baseline --write)")
    else:
        old_commands = set(old.command_lines)
        for signature in new_commands:
            if signature not in old_commands:
                changes.append(f"command:{signature}")
    return changes


def carry_over_blocks(old: Iterable[Finding], new: list[Finding]) -> list[Finding]:
    """Downgrade block findings the installed tree already had to notes.

    An update is judged on what it changes. A block that was already present
    when the plugin was installed would otherwise deny every update after it,
    whatever that update touched. Matching is by rule, path and matched text,
    not line number, so an edit above a finding does not make it look new; it
    is counted, so a second copy of the same match in the same file still
    blocks. The capability flag is untouched either way.
    """
    remaining = Counter(
        (item.rule, item.path, item.snippet) for item in old if item.severity == BLOCK
    )
    result: list[Finding] = []
    for item in new:
        key = (item.rule, item.path, item.snippet)
        if item.severity == BLOCK and remaining[key] > 0:
            remaining[key] -= 1
            result.append(
                replace(
                    item, severity=NOTE, snippet=f"{item.snippet} (already installed; note only)"
                )
            )
        else:
            result.append(item)
    return result


def has_block_findings(findings: Iterable[Finding]) -> bool:
    return any(item.severity == BLOCK for item in findings)


def findings_to_dict(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    return [asdict(item) for item in findings]


def _iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os_walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
        base = Path(dirpath)
        for name in filenames:
            yield base / name


def os_walk(root: Path):
    import os

    return os.walk(root)


def _is_binary(head: bytes) -> bool:
    return b"\0" in head


def _clip(text: str, limit: int = 160) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"


def _command_tokens(inner: str) -> list[str]:
    quoted = [match.group(2) for match in QUOTED.finditer(inner)]
    if not quoted:
        return []
    first = Path(quoted[0]).name
    if not first or first.startswith("-"):
        return []
    if first in {"bash", "sh", "zsh"} and len(quoted) > 1 and quoted[1] in {"-c", "-lc"}:
        return [f"{first} {quoted[1]}"]
    return [first]
