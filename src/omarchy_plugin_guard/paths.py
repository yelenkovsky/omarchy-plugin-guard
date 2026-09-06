from __future__ import annotations

import os
from pathlib import Path


def home() -> Path:
    return Path.home()


def plugins_dir() -> Path:
    override = os.environ.get("OMARCHY_PLUGINS_DIR")
    if override:
        return Path(override)
    return home() / ".config" / "omarchy" / "plugins"


def state_dir() -> Path:
    override = os.environ.get("OMARCHY_PLUGIN_GUARD_STATE_DIR")
    if override:
        return Path(override)
    return home() / ".config" / "omarchy" / "plugin-guard"


def baselines_dir() -> Path:
    return state_dir() / "baselines"


def reviews_dir() -> Path:
    return state_dir() / "reviews"
