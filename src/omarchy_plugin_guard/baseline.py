from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from omarchy_plugin_guard.paths import baselines_dir
from omarchy_plugin_guard.scan import Capabilities


@dataclass
class Baseline:
    version: int
    plugin_id: str
    origin: str
    commit: str
    recorded_at: str
    capabilities: Capabilities
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["capabilities"] = self.capabilities.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Baseline:
        return cls(
            version=int(data.get("version") or 1),
            plugin_id=str(data.get("plugin_id") or ""),
            origin=str(data.get("origin") or ""),
            commit=str(data.get("commit") or ""),
            recorded_at=str(data.get("recorded_at") or ""),
            capabilities=Capabilities.from_dict(data.get("capabilities") or {}),
            extra={k: v for k, v in data.items() if k not in {
                "version", "plugin_id", "origin", "commit", "recorded_at", "capabilities"
            }},
        )


def baseline_path(plugin_id: str) -> Path:
    return baselines_dir() / f"{plugin_id}.json"


def load_baseline(plugin_id: str) -> Baseline | None:
    path = baseline_path(plugin_id)
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return Baseline.from_dict(data)


def save_baseline(
    plugin_id: str,
    origin: str,
    commit: str,
    capabilities: Capabilities,
) -> Baseline:
    baselines_dir().mkdir(parents=True, exist_ok=True)
    baseline = Baseline(
        version=1,
        plugin_id=plugin_id,
        origin=origin,
        commit=commit,
        recorded_at=datetime.now(timezone.utc).isoformat(),
        capabilities=capabilities,
    )
    path = baseline_path(plugin_id)
    path.write_text(json.dumps(baseline.to_dict(), indent=2) + "\n", encoding="utf-8")
    return baseline
