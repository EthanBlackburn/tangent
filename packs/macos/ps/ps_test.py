import os
import time
import unittest

import ps

OUT = """\
    1     0 Mon Mar  2 08:00:00 2026     /sbin/launchd
  412     1 Mon Mar  2 09:00:00 2026     /Applications/Ghostty.app/Contents/MacOS/ghostty
  500   412 Mon Mar  2 09:00:05 2026     /usr/bin/login
  501   500 Mon Mar  2 09:00:05 2026     -/bin/zsh
  640   501 Mon Mar  2 09:30:00 2026     claude
  700     1 Mon Mar  2 09:10:00 2026     /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
garbage
"""


def setUpModule():
    os.environ["TZ"] = "Asia/Tokyo"   # ps prints this Mac's time: nine hours ahead here
    time.tzset()


class Lines(unittest.TestCase):
    def test_each_process_is_a_line(self):
        got = [l["ps"] for l in ps.lines(OUT, "t")]
        self.assertEqual(len(got), 6)
        self.assertEqual(got[1], {"pid": 412, "ppid": 1, "start": "2026-03-02T00:00:00Z",
                                  "path": "/Applications/Ghostty.app/Contents/MacOS/ghostty"})

    def test_a_start_it_cannot_read_is_left_out(self):
        got = list(ps.lines("  9     1 Mon Mar 99 09:00:00 2026     /bin/x\n", "t"))
        self.assertEqual(got[0]["ps"], {"pid": 9, "ppid": 1, "path": "/bin/x"})

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
