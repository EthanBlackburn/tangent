import os
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


class Follow(unittest.TestCase):
    def test_whole_lines_added_after_the_start_are_read(self):
        with tempfile.NamedTemporaryFile("w", suffix=".ndjson", delete=False) as f:
            f.write('{"old": 1}\n')
        self.addCleanup(os.remove, f.name)
        with open(f.name, "a") as more:
            more.write('{"new": 1}\n{"half":')
        self.assertEqual(next(ask.lines(f.name, start=11)), '{"new": 1}\n')


class Stands(unittest.TestCase):
    def test_what_the_review_did_not_clear(self):
        for verdict in ("malicious", "unresolved", None):
            self.assertTrue(ask.stands(review(verdict)), verdict)

    def test_a_benign_review_does_not_unless_the_judge_flagged(self):
        self.assertFalse(ask.stands(review("benign")))
        self.assertTrue(ask.stands(review("benign", judge="flag")))


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

    def test_a_long_finding_is_cut_and_kept_on_its_lines(self):
        _, text = ask.wording(review(finding="x\n" * 2000))
        self.assertLess(len(text), ask.FINDING + 300)
        self.assertIn("…", text)


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

    def test_a_dialog_that_cannot_be_shown_is_an_answer_of_none(self):
        def show(*_):
            raise RuntimeError("no screen")

        line = ask.ask(review("unresolved"), show)
        self.assertEqual(line["answer"], "none")
        self.assertIn("no screen", line["note"])

    def test_the_script_holds_none_of_the_review_s_text(self):
        source = ask.script("stop", 0)
        self.assertNotIn("giving up", source)
        self.assertIn("giving up after 45", ask.script("caution", 45.9))
        self.assertIn('buttons {"Not me", "Not sure", "That was me"}', source)
        self.assertIn("(item 2 of argv)", source)   # the text arrives as an argument


if __name__ == "__main__":
    unittest.main()
