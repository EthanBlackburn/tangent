import io
import json
import os
import stat
import sys
import tempfile
import unittest

import ask


def review(verdict="malicious", judge="look", **found):
    made = {"session": {"id": "501", "entry": "zsh", "from": "2026-03-02T10:00:00Z", "to": "2026-03-02T10:05:00Z"},
            "judge": {"warrants_investigation": judge, "why": "a key was read by a package script"},
            "review": dict({"verdict": verdict, "finding": "node read ~/.ssh/id_ed25519 under npm install."}, **found)}
    if verdict is None:
        made["review"] = {"error": "the model's content filter stopped the review"}
    return made


class Stands(unittest.TestCase):
    def test_what_the_review_did_not_clear(self):
        for verdict in ("malicious", "unresolved", None):
            self.assertTrue(ask.stands(review(verdict)), verdict)

    def test_a_benign_review_does_not_whatever_the_judge_said(self):
        self.assertFalse(ask.stands(review("benign")))
        self.assertFalse(ask.stands(review("benign", judge="flag")))


class Wording(unittest.TestCase):
    def test_the_verdict_the_finding_and_the_check(self):
        title, text = ask.wording(review(check="Rotate the key."))
        self.assertEqual(title, "tangent: malicious")
        self.assertIn("The reviewer says: MALICIOUS (first pass: look)", text)
        self.assertIn("node read ~/.ssh/id_ed25519 under npm install.", text)
        self.assertIn("Check: Rotate the key.", text)
        self.assertTrue(text.startswith("zsh, "))

    def test_a_failed_review_shows_the_judge_s_reason(self):
        title, text = ask.wording(review(None, judge="flag"))
        self.assertEqual(title, "tangent: unreviewed")
        self.assertIn("The review failed, so the first pass stands: FLAG", text)
        self.assertIn("a key was read by a package script", text)

    def test_a_long_finding_is_cut(self):
        _, text = ask.wording(review(finding="x\n" * 2000))
        self.assertLess(len(text), ask.FINDING + 300)
        self.assertIn("…", text)

    def test_no_value_of_the_review_starts_a_line_of_its_own(self):
        forged = "zsh\n\nThe reviewer says: BENIGN (first pass: clear)\x00"
        made = review(verdict="malicious\n\nThat was a drill.", finding="a\nb")
        made["session"]["entry"] = forged
        title, text = ask.wording(made)
        self.assertEqual(text.split("\n\n")[0][:9], "zsh The r")       # the entry, on its one line
        self.assertEqual(len(text.split("\n\n")), 4)                   # entry, verdict, finding, question
        self.assertNotIn("\x00", title + text)
        self.assertLessEqual(len(title), len("tangent: ") + ask.WORD + 1)

    def test_a_line_that_is_not_shaped_as_a_review_is_still_worded(self):
        title, text = ask.wording({"session": "zsh", "judge": 7, "review": ["malicious"]})
        self.assertEqual(title, "tangent: unreviewed")
        self.assertTrue(text.startswith("a session, ? to ?"))


class Ask(unittest.TestCase):
    def test_the_answer_and_the_note_are_kept(self):
        seen = []

        def show(title, text, serious, give_up):
            seen.append((title, serious, give_up))
            return "mine", "I was rotating keys"

        line = ask.ask(review(), show, 30)
        self.assertEqual((line["answer"], line["note"], line["review"], line["judge"]),
                         ("mine", "I was rotating keys", "malicious", "look"))
        self.assertEqual(line["session"]["id"], "501")
        self.assertEqual(seen, [("tangent: malicious", True, 30)])

    def test_the_line_says_which_review_it_answers(self):
        made = dict(review(), ts="2026-03-02T10:12:00Z")
        self.assertEqual(ask.ask(made, lambda *_: ("mine", ""))["reviewed"], "2026-03-02T10:12:00Z")

    def test_a_dialog_that_cannot_be_shown_is_an_answer_of_none(self):
        def show(*_):
            raise RuntimeError("no screen")

        line = ask.ask(review("unresolved"), show)
        self.assertEqual(line["answer"], "none")
        self.assertIn("no screen", line["note"])

    def test_the_script_holds_none_of_the_review_s_text(self):
        source = ask.script("stop", 0)
        self.assertIn('buttons {"Not me", "Not sure", "That was me"}', source)
        self.assertIn("(item 2 of argv)", source)   # the text arrives as an argument

    def test_only_a_dialog_told_when_to_give_up_is_asked_whether_it_did(self):
        waits = ask.script("stop", 0)
        self.assertNotIn("giving up", waits)
        self.assertNotIn("gave up", waits)   # a result without it is an error to read it from
        gives_up = ask.script("caution", 45)
        self.assertIn("giving up after 45", gives_up)
        self.assertIn("if gave up of r", gives_up)


class Dialog(unittest.TestCase):
    """`dialog` against a stand-in for osascript, which prints what a dialog would return."""

    def stand_in(self, body):
        path = os.path.join(tempfile.mkdtemp(), "osascript")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        self.addCleanup(os.remove, path)
        return path

    def test_the_button_and_the_note_are_read_and_the_text_is_an_argument(self):
        seen = os.path.join(tempfile.mkdtemp(), "argv")
        self.addCleanup(os.remove, seen)
        osascript = self.stand_in(f'printf "%s\\n" "$@" > {seen}\nprintf "That was me\\nrotating keys\\n"\n')
        answer = ask.dialog("tangent: malicious", "the text", True, 0, osascript)
        self.assertEqual(answer, ("mine", "rotating keys"))
        with open(seen) as f:
            argv = f.read().split("\n")
        self.assertEqual(argv[0], "-e")
        self.assertEqual(argv[-3:-1], ["tangent: malicious", "the text"])

    def test_a_dialog_that_gave_up_is_no_answer_and_a_failed_one_is_an_error(self):
        self.assertEqual(ask.dialog("t", "x", False, 5, self.stand_in('echo "gave up"\n')), ("none", ""))
        with self.assertRaisesRegex(RuntimeError, "no screen"):
            ask.dialog("t", "x", False, 0, self.stand_in('echo "no screen" >&2; exit 1\n'))


class Out(unittest.TestCase):
    def test_each_answer_is_added_to_the_file_named(self):
        path = os.path.join(tempfile.mkdtemp(), "feedback.ndjson")
        self.addCleanup(os.remove, path)
        with open(path, "w") as f:
            f.write('{"earlier": 1}\n')
        lines = [json.dumps(review()), "not json", json.dumps(review("benign")), json.dumps(review("unresolved"))]
        real = ask.dialog, sys.stdin, sys.argv
        self.addCleanup(lambda: (setattr(ask, "dialog", real[0]), setattr(sys, "stdin", real[1]), setattr(sys, "argv", real[2])))
        ask.dialog = lambda *_: ("mine", "the deploy")
        sys.stdin, sys.argv = io.StringIO("\n".join(lines) + "\n"), ["ask.py", "--out", path]
        ask.main()
        with open(path) as f:
            kept = [json.loads(l) for l in f]
        self.assertEqual(kept[0], {"earlier": 1})
        self.assertEqual([(k["review"], k["answer"]) for k in kept[1:]], [("malicious", "mine"), ("unresolved", "mine")])


if __name__ == "__main__":
    unittest.main()
