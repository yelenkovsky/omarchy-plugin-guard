from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from omarchy_plugin_guard.policy import AutoPolicy, count_diff_lines, evaluate_auto_apply
from omarchy_plugin_guard.scan import Capabilities, empty_flags
from omarchy_plugin_guard.state import (
    LockHeld,
    append_audit,
    audit_path,
    clear_first_seen,
    note_first_seen,
    run_lock,
)

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


def declarative() -> Capabilities:
    return Capabilities(kinds=["bar-widget"], flags=empty_flags(), command_lines=[])


def runs_bash() -> Capabilities:
    flags = empty_flags()
    flags["process"] = True
    return Capabilities(kinds=["bar-widget"], flags=flags, process_binaries=["bash -c"], command_lines=["x #1"])


class PolicyTests(unittest.TestCase):
    def test_applies_only_when_every_gate_passes(self) -> None:
        decision = evaluate_auto_apply(
            policy=AutoPolicy(soak_days=3, max_diff_lines=400),
            verdict="allow",
            diff_truncated=False,
            diff_lines=20,
            old_caps=declarative(),
            new_caps=declarative(),
            first_seen_at=NOW - timedelta(days=4),
            now=NOW,
        )
        self.assertTrue(decision.apply)
        self.assertEqual(decision.reasons, [])

    def test_soak_delay_defers(self) -> None:
        decision = evaluate_auto_apply(
            policy=AutoPolicy(soak_days=3, max_diff_lines=400),
            verdict="allow",
            diff_truncated=False,
            diff_lines=20,
            old_caps=declarative(),
            new_caps=declarative(),
            first_seen_at=NOW - timedelta(hours=5),
            now=NOW,
        )
        self.assertFalse(decision.apply)
        self.assertTrue(any(reason.startswith("soak:") for reason in decision.reasons))

    def test_plugins_that_run_code_never_auto_apply(self) -> None:
        decision = evaluate_auto_apply(
            policy=AutoPolicy(soak_days=0, max_diff_lines=400),
            verdict="allow",
            diff_truncated=False,
            diff_lines=5,
            old_caps=runs_bash(),
            new_caps=runs_bash(),
            first_seen_at=NOW - timedelta(days=30),
            now=NOW,
        )
        self.assertFalse(decision.apply)
        self.assertTrue(any("runs commands" in reason for reason in decision.reasons))

    def test_size_truncation_and_verdict_gates(self) -> None:
        base = dict(
            policy=AutoPolicy(soak_days=0, max_diff_lines=100),
            old_caps=declarative(),
            new_caps=declarative(),
            first_seen_at=NOW - timedelta(days=1),
            now=NOW,
        )
        too_big = evaluate_auto_apply(verdict="allow", diff_truncated=False, diff_lines=101, **base)
        self.assertFalse(too_big.apply)
        truncated = evaluate_auto_apply(verdict="allow", diff_truncated=True, diff_lines=10, **base)
        self.assertFalse(truncated.apply)
        human = evaluate_auto_apply(verdict="needs-human", diff_truncated=False, diff_lines=10, **base)
        self.assertFalse(human.apply)

    def test_count_diff_lines_ignores_headers(self) -> None:
        diff = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n+more\n context\n"
        self.assertEqual(count_diff_lines(diff), 3)

    def test_policy_from_env(self) -> None:
        env = os.environ.copy()
        os.environ["OMARCHY_PLUGIN_GUARD_SOAK_DAYS"] = "7"
        os.environ["OMARCHY_PLUGIN_GUARD_MAX_DIFF_LINES"] = "50"
        try:
            policy = AutoPolicy.from_env()
            self.assertEqual((policy.soak_days, policy.max_diff_lines), (7, 50))
            override = AutoPolicy.from_env(soak_days=1)
            self.assertEqual((override.soak_days, override.max_diff_lines), (1, 50))
        finally:
            os.environ.clear()
            os.environ.update(env)


class StateTests(unittest.TestCase):
    def _with_state(self):
        raw = tempfile.TemporaryDirectory()
        env = os.environ.copy()
        os.environ["OMARCHY_PLUGIN_GUARD_STATE_DIR"] = raw.name

        def cleanup() -> None:
            os.environ.clear()
            os.environ.update(env)
            raw.cleanup()

        return Path(raw.name), cleanup

    def test_lock_is_exclusive(self) -> None:
        state, cleanup = self._with_state()
        try:
            with run_lock():
                with self.assertRaises(LockHeld):
                    with run_lock():
                        pass
            with run_lock():
                pass
        finally:
            cleanup()

    def test_audit_appends_json_lines(self) -> None:
        state, cleanup = self._with_state()
        try:
            append_audit({"event": "reviewed", "plugin": "a"})
            append_audit({"event": "applied", "plugin": "a"})
            lines = audit_path().read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            first = json.loads(lines[0])
            self.assertEqual(first["event"], "reviewed")
            self.assertIn("at", first)
        finally:
            cleanup()

    def test_first_seen_is_stable_until_sha_changes(self) -> None:
        state, cleanup = self._with_state()
        try:
            first = note_first_seen("demo", "aaa")
            again = note_first_seen("demo", "aaa")
            self.assertEqual(first, again)
            newer = note_first_seen("demo", "bbb")
            self.assertGreaterEqual(newer, first)
            clear_first_seen("demo")
            self.assertFalse((state / "seen" / "demo.json").exists())
        finally:
            cleanup()
