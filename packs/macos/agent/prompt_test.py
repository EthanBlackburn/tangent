import unittest

import prompt


class Line(unittest.TestCase):
    def test_a_prompt_is_a_line(self):
        hook = {"session_id": "abc", "cwd": "/Users/dev/code/x", "hook_event_name": "UserPromptSubmit",
                "prompt": "look at our AWS spend"}
        got = prompt.line(hook, [3, 2, 1], "t")
        self.assertEqual(got, {"time": "t", "prompt": {
            "agent": "claude-code", "session": "abc", "cwd": "/Users/dev/code/x",
            "text": "look at our AWS spend", "pids": [3, 2, 1]}})

    def test_a_long_prompt_is_cut(self):
        got = prompt.line({"prompt": "x" * 10000}, [1], "t")
        self.assertEqual(len(got["prompt"]["text"]), prompt.TEXT)

    def test_no_prompt_is_no_line(self):
        self.assertIsNone(prompt.line({"hook_event_name": "PreToolUse"}, [1], "t"))
        self.assertIsNone(prompt.line({"prompt": "  "}, [1], "t"))


if __name__ == "__main__":
    unittest.main()
