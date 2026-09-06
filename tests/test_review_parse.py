from __future__ import annotations

import unittest

from omarchy_plugin_guard.review import ReviewError, parse_agent_verdict


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
