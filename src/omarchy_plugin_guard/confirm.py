from __future__ import annotations

import shutil
import subprocess
import sys


def confirm(prompt: str, *, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    gum = shutil.which("gum")
    if gum:
        result = subprocess.run([gum, "confirm", prompt])
        return result.returncode == 0
    answer = input(f"{prompt} [y/N] ").strip().lower()
    return answer in {"y", "yes"}
