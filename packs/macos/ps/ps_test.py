import unittest

import ps

OUT = """\
    1     0 /sbin/launchd
  412     1 /Applications/Ghostty.app/Contents/MacOS/ghostty
  500   412 /usr/bin/login
  501   500 -/bin/zsh
  640   501 claude
  700     1 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
garbage
"""


class Lines(unittest.TestCase):
    def test_each_process_is_a_line(self):
        got = [l["ps"] for l in ps.lines(OUT, "t")]
        self.assertEqual(len(got), 6)
        self.assertEqual(got[1], {"pid": 412, "ppid": 1, "path": "/Applications/Ghostty.app/Contents/MacOS/ghostty"})

    def test_a_login_shell_loses_its_dash(self):
        got = {l["ps"]["pid"]: l["ps"]["path"] for l in ps.lines(OUT, "t")}
        self.assertEqual(got[501], "/bin/zsh")

    def test_a_path_keeps_its_spaces(self):
        got = {l["ps"]["pid"]: l["ps"]["path"] for l in ps.lines(OUT, "t")}
        self.assertEqual(got[700], "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")

    def test_a_process_title_is_kept_as_it_is(self):
        got = {l["ps"]["pid"]: l["ps"]["path"] for l in ps.lines(OUT, "t")}
        self.assertEqual(got[640], "claude")


if __name__ == "__main__":
    unittest.main()
