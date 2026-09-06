from __future__ import annotations

import json
import re
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


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

COMMAND_ASSIGN = re.compile(
    r"""(?:\.command|command)\s*=\s*\[([^\]]{0,800})\]""",
    re.MULTILINE,
)
QUOTED = re.compile(r"""(['"])(.*?)\1""")

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
            r"|CURSOR_API_KEY"
            r"|GNUPGHOME",
            re.IGNORECASE,
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
        "process",
        NOTE,
        re.compile(r"""(?:\.command|command)\s*=\s*\["""),
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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Capabilities:
        return cls(
            kinds=list(data.get("kinds") or []),
            manifest_version=str(data.get("manifest_version") or ""),
            flags=dict(data.get("flags") or {}),
            process_binaries=list(data.get("process_binaries") or []),
            unexpected_files=list(data.get("unexpected_files") or []),
        )


def empty_flags() -> dict[str, bool]:
    return {
        "process": False,
        "network": False,
        "filesystem": False,
        "credentials": False,
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

        for rule, severity, pattern in CONTENT_RULES:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                snippet = _clip(match.group(0))
                findings.append(Finding(rule, severity, rel, line, snippet))
                if rule in flags:
                    flags[rule] = True

        for match in COMMAND_ASSIGN.finditer(text):
            flags["process"] = True
            for token in _command_tokens(match.group(1)):
                binaries.add(token)

    caps = Capabilities(
        kinds=kinds,
        manifest_version=manifest_version,
        flags=flags,
        process_binaries=sorted(binaries),
        unexpected_files=sorted(set(unexpected)),
    )
    return findings, caps


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
    return changes


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
