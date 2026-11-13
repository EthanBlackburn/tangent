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

    def test_a_prompt_with_a_line_separator_in_it_is_one_line(self):
        line = json.dumps(typed("first\u2028second\u0085third"), ensure_ascii=False)
        self.assertEqual(len(list(transcripts.entries(line + "\n" + line + "\n"))), 2)

    def test_a_message_typed_while_the_agent_works_is_a_prompt(self):
        queued = {"type": "attachment", "sessionId": SESSION, "timestamp": "t",
                  "attachment": {"type": "queued_command", "prompt": "and run the linter as well",
                                 "origin": {"kind": "human"}, "commandMode": "prompt"}}
        self.assertEqual(transcripts.prompt(queued), "and run the linter as well")
        self.assertIs(transcripts.line(queued, "and run the linter as well", 1)["prompt"]["during"], True)
        self.assertNotIn("during", transcripts.line(typed("x"), "x", 1)["prompt"])
        notice = {"type": "attachment", "attachment": {
            "type": "queued_command", "prompt": "<task-notification>", "origin": {"kind": "task-notification"}}}
        self.assertIsNone(transcripts.prompt(notice))
        other = {"type": "attachment", "attachment": {"type": "file", "origin": {"kind": "human"}}}
        self.assertIsNone(transcripts.prompt(other))

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

    def test_a_long_reply_to_is_its_start_and_its_end(self):
        said = "The build takes nine minutes. " + "x" * 5000 + " Which do you want first?"
        after = transcripts.line(typed("x"), "the second", 1, said)["prompt"]["after"]
        self.assertTrue(after.startswith("The build takes nine minutes."))
        self.assertTrue(after.endswith("Which do you want first?"))
        self.assertEqual(len(after), transcripts.SAID_START + transcripts.SAID_END + 3)


class Follow(unittest.TestCase):
    def test_a_session_already_open_gives_its_latest_prompt_then_what_follows(self):
        with tempfile.TemporaryDirectory() as tmp:
            spoke = {"type": "assistant", "message": {"content": [
                {"type": "text", "text": "The deny rule blocks it. Can you remove it?"},
                {"type": "tool_use", "name": "Bash", "input": {}}]}}
            path = home(tmp, [typed("zero", at="t0"), typed("first", at="t1"), spoke,
                              typed("second", at="t2"), typed("third", at="t3")])
            f = transcripts.Follower(tmp)
            got = f.poll()
            self.assertEqual([l["prompt"]["text"] for l in got], ["first", "second", "third"])
            self.assertEqual(got[1], {"time": "t2", "prompt": {
                "agent": "claude-code", "session": SESSION, "cwd": "/Users/dev/code/x",
                "text": "second", "after": "The deny rule blocks it. Can you remove it?",
                "pids": [4100]}})
            self.assertNotIn("after", got[0]["prompt"])
            self.assertEqual(f.poll(), [])
            with open(path, "a", encoding="utf-8") as out:
                out.write(json.dumps({"type": "assistant", "message": {"content": [
                    {"type": "text", "text": "Done. Anything else?"}]}}) + "\n")
                out.write(json.dumps(typed("fourth", at="t4")) + "\n")
                out.write(json.dumps(typed("fifth", at="t5"))[:20])   # a line still being written
            got = f.poll()
            self.assertEqual([l["prompt"]["text"] for l in got], ["fourth"])
            self.assertEqual(got[0]["prompt"]["after"], "Done. Anything else?")
            with open(path, "a", encoding="utf-8") as out:
                out.write(json.dumps(typed("fifth", at="t5"))[20:] + "\n")
            got = f.poll()
            self.assertEqual([l["prompt"]["text"] for l in got], ["fifth"])
            # the agent has not spoken since: the same words came before it
            self.assertEqual(got[0]["prompt"]["after"], "Done. Anything else?")

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
