"""Guard the capability range from rotting: every box's flag must be reachable
via its intended solution path. This proves a FAIL in the range means RED-AI
lacks the capability -- not that the fixture is broken. (The full engage run is
an on-demand integration tool, `python -m redai_range`, not a unit test.)"""
import unittest

from redai_range.boxes import BOXES


class TestRangeFixturesSolvable(unittest.TestCase):
    def test_every_box_flag_is_reachable_via_its_solution(self):
        for b in BOXES:
            s = b.solution
            status, _headers, body = b.respond(s.path, s.query, s.headers)
            text = body.decode("utf-8", "replace")
            self.assertIn(b.flag, text, f"{b.id} fixture broken: flag not reachable via solution")

    def test_difficulties_are_unique_and_ordered(self):
        diffs = [b.difficulty for b in sorted(BOXES, key=lambda b: b.difficulty)]
        self.assertEqual(diffs, sorted(set(diffs)), "box difficulties must be unique")

    def test_flags_are_distinct(self):
        flags = [b.flag for b in BOXES]
        self.assertEqual(len(flags), len(set(flags)), "each box needs a distinct flag")


if __name__ == "__main__":
    unittest.main()
