import json
import os
import tempfile
import unittest

import transcripts

SESSION = "00000000-0000-4000-8000-000000000001"


def typed(text, at="2026-11-03T20:00:06.000Z", **more):
    return {"type": "user", "origin": {"kind": "human"}, "sessionId": SESSION,
            "cwd": "/Users/dev/code/x", "timestamp": at,
            "message": {"role": "user", "content": text}, **more}


def home(tmp, lines, pid=4100):
    project = os.path.join(tmp, "projects", "-Users-dev-code-x")
    os.makedirs(project)
    os.makedirs(os.path.join(tmp, "sessions"))
    path = os.path.join(project, SESSION + ".jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for l in lines:
            f.write(json.dumps(l) + "\n")
    with open(os.path.join(tmp, "sessions", f"{pid}.json"), "w", encoding="utf-8") as f:
        json.dump({"pid": pid, "sessionId": SESSION}, f)
    return path


class Prompt(unittest.TestCase):
    def test_what_a_person_typed_is_a_prompt(self):
        self.assertEqual(transcripts.prompt(typed("look at our AWS spend")), "look at our AWS spend")
        blocks = typed([{"type": "text", "text": "and"}, {"type": "text", "text": "this"}])
        self.assertEqual(transcripts.prompt(blocks), "and\nthis")

    def test_what_nobody_typed_is_not(self):
        result = {"type": "user", "message": {"content": [{"type": "tool_result", "content": "ok"}]}}
        notice = typed("<task-notification>", origin={"kind": "task-notification"})
        for entry in (result, notice, typed("to a subagent", isSidechain=True),
                      typed("a summary", isCompactSummary=True), typed("  "),
                      {"type": "assistant", "origin": {"kind": "human"}, "message": {"content": "hi"}}):
            self.assertIsNone(transcripts.prompt(entry))

    def test_a_long_prompt_is_cut(self):
        made = transcripts.line(typed("x"), "x" * 10000, 1)
        self.assertEqual(len(made["prompt"]["text"]), transcripts.TEXT)


class Follow(unittest.TestCase):
    def test_a_session_already_open_gives_its_latest_prompt_then_what_follows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = home(tmp, [typed("first", at="t1"), {"type": "assistant"}, typed("second", at="t2")])
            f = transcripts.Follower(tmp)
            self.assertEqual(f.poll(), [{"time": "t2", "prompt": {
                "agent": "claude-code", "session": SESSION, "cwd": "/Users/dev/code/x",
                "text": "second", "pids": [4100]}}])
            self.assertEqual(f.poll(), [])
            with open(path, "a", encoding="utf-8") as out:
                out.write(json.dumps(typed("third", at="t3")) + "\n")
                out.write(json.dumps(typed("fourth", at="t4"))[:20])   # a line still being written
            self.assertEqual([l["prompt"]["text"] for l in f.poll()], ["third"])
            with open(path, "a", encoding="utf-8") as out:
                out.write(json.dumps(typed("fourth", at="t4"))[20:] + "\n")
            self.assertEqual([l["prompt"]["text"] for l in f.poll()], ["fourth"])

    def test_an_old_session_is_left_alone_and_a_new_one_is_read_whole(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = home(tmp, [typed("long ago")])
            f = transcripts.Follower(tmp)
            self.assertEqual(f.poll(now=os.stat(path).st_mtime + transcripts.RECENT + 60), [])
            new = os.path.join(os.path.dirname(path), "00000000-0000-4000-8000-000000000002.jsonl")
            with open(new, "w", encoding="utf-8") as out:
                out.write(json.dumps(typed("a", at="t1", sessionId="other")) + "\n")
                out.write("not json\n")
                out.write(json.dumps(typed("b", at="t2", sessionId="other")) + "\n")
            got = f.poll()
            self.assertEqual([l["prompt"]["text"] for l in got], ["a", "b"])
            # no running agent claims that session
            self.assertNotIn("pids", got[0]["prompt"])


if __name__ == "__main__":
    unittest.main()
