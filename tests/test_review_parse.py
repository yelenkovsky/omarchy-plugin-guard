from __future__ import annotations

import json
import unittest

from omarchy_plugin_guard.prompt import SYSTEM_PROMPT
from omarchy_plugin_guard.review import (
    ALLOWED_TOOLS,
    DISALLOWED_TOOLS,
    ReviewError,
    build_claude_command,
    parse_agent_verdict,
    parse_claude_result,
)


class ParseVerdictTests(unittest.TestCase):
    def test_plain_json(self) -> None:
        review = parse_agent_verdict(
            '{"verdict":"allow","summary":"layout tweak","findings":[]}'
        )
        self.assertEqual(review.verdict, "allow")
        self.assertEqual(review.summary, "layout tweak")

    def test_fenced_json(self) -> None:
        text = """Here you go
```json
{"verdict":"needs-human","summary":"new Process","findings":[{"severity":"warn","path":"Main.qml","why":"shell"}]}
```
"""
        review = parse_agent_verdict(text)
        self.assertEqual(review.verdict, "needs-human")
        self.assertEqual(review.findings[0]["path"], "Main.qml")

    def test_invalid_verdict(self) -> None:
        with self.assertRaises(ReviewError):
            parse_agent_verdict('{"verdict":"ship-it","summary":"nope"}')

    def test_missing_json_fail_closed(self) -> None:
        with self.assertRaises(ReviewError):
            parse_agent_verdict("looks fine to me")


class ClaudeResultTests(unittest.TestCase):
    def test_structured_output_wins(self) -> None:
        payload = {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "num_turns": 4,
            "session_id": "sess-1",
            "total_cost_usd": 0.01,
            "permission_denials": [{"tool_name": "Read", "tool_input": {"file_path": "/etc/passwd"}}],
            "result": "some prose",
            "structured_output": {"verdict": "allow", "summary": "css only", "findings": []},
        }
        review = parse_claude_result(json.dumps(payload))
        self.assertEqual(review.verdict, "allow")
        self.assertEqual(review.summary, "css only")
        self.assertEqual(review.run_id, "sess-1")
        self.assertEqual(review.denied_calls, 1)
        self.assertEqual(review.turns, 4)

    def test_falls_back_to_result_text(self) -> None:
        payload = {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": '{"verdict":"deny","summary":"curl | sh","findings":[]}',
            "structured_output": None,
        }
        review = parse_claude_result(json.dumps(payload))
        self.assertEqual(review.verdict, "deny")

    def test_is_error_raises(self) -> None:
        payload = {"type": "result", "subtype": "success", "is_error": True, "result": "Not logged in"}
        with self.assertRaises(ReviewError) as ctx:
            parse_claude_result(json.dumps(payload))
        self.assertIn("Not logged in", str(ctx.exception))

    def test_error_subtype_raises(self) -> None:
        payload = {"type": "result", "subtype": "error_max_turns", "is_error": False, "result": ""}
        with self.assertRaises(ReviewError):
            parse_claude_result(json.dumps(payload))

    def test_empty_output_raises(self) -> None:
        with self.assertRaises(ReviewError):
            parse_claude_result("", stderr="boom", returncode=1)


class CommandTests(unittest.TestCase):
    def test_command_is_locked_down(self) -> None:
        argv = build_claude_command(claude_bin="claude", model="sonnet", max_turns=12)
        self.assertEqual(argv[:2], ["claude", "-p"])
        self.assertIn("--strict-mcp-config", argv)
        self.assertIn("--setting-sources", argv)
        self.assertEqual(argv[argv.index("--setting-sources") + 1], "")
        self.assertEqual(argv[argv.index("--permission-mode") + 1], "dontAsk")
        self.assertEqual(argv[argv.index("--system-prompt") + 1], SYSTEM_PROMPT)
        self.assertEqual(argv[argv.index("--output-format") + 1], "json")
        self.assertEqual(argv[argv.index("--max-turns") + 1], "12")
        self.assertEqual(argv[argv.index("--model") + 1], "sonnet")
        allowed_start = argv.index("--allowedTools") + 1
        self.assertEqual(argv[allowed_start : allowed_start + len(ALLOWED_TOOLS)], ALLOWED_TOOLS)
        self.assertIn("Read(./**)", ALLOWED_TOOLS)
        for tool in ("Bash", "Edit", "Write", "WebFetch", "WebSearch", "Task"):
            self.assertIn(tool, DISALLOWED_TOOLS)
        self.assertNotIn("--bare", argv)
        schema = json.loads(argv[argv.index("--json-schema") + 1])
        self.assertEqual(schema["properties"]["verdict"]["enum"], ["allow", "deny", "needs-human"])
        settings = json.loads(argv[argv.index("--settings") + 1])
        self.assertFalse(settings["autoMemoryEnabled"])
