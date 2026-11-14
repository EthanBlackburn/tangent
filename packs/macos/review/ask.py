#!/usr/bin/env python3
"""Ask the Mac's owner about each review that stands, in a dialog, and keep the answer.

    python3 -I ask.py --follow reviews.ndjson >> feedback.ndjson    # live: each new review
    python3 -I ask.py < reviews.ndjson > feedback.ndjson            # a finished run's

Each line read is a review, as plugin macos_review writes it. One that stands (its
verdict is not `benign`; --all asks about every one) is shown in a dialog on this Mac: the session, the verdict, what
the reviewer found and what it says to check, a field for a note, and three
buttons, "Not me", "Not sure" and "That was me". The dialog waits for an
answer, the next review behind it, unless --give-up says how long.

One line goes to stdout for each review asked about: the session, the
judge's answer, the review's verdict and its time (`reviewed`, the review's
`ts`, which with the session says which review this answers), `answer`
(`not_mine`, `unsure`, `mine`, or `none` when the dialog gave up) and `note`.

Told to stop (SIGTERM), it asks about what the file already holds and then
ends, so the reviews tangent writes as it stops are asked about too. Told a
second time, it ends at once.

The dialog is `osascript`'s `display dialog`. Its text is the reviewer's,
written about records an attacker can write into, so it goes to the script
as an argument and is never part of the AppleScript that runs.

Standard library only; macOS."""
import argparse
import datetime
import json
import os
import signal
import subprocess
import sys

import time

FINDING = 900   # characters of the finding shown
CHECK = 400
NAME = 120      # of the session's entry point
WORD = 20       # of a verdict
BUTTONS = {"Not me": "not_mine", "Not sure": "unsure", "That was me": "mine"}


def when(text):
    """An RFC 3339 time as a datetime in UTC, or None."""
    try:
        t = datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t.astimezone(datetime.timezone.utc) if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def lines(follow, start=None, stopping=lambda: False):
    """The lines to read: stdin's, or with `follow` those added to that file
    from now on (from byte `start`, when given; all of a file that is not
    there yet), until `stopping()` and the file's end."""
    if not follow:
        yield from sys.stdin
        return
    if start is None and not os.path.exists(follow):
        start = 0   # whatever it comes to hold is new
    while not os.path.exists(follow):
        if stopping():
            return
        time.sleep(1)
    with open(follow) as f:
        f.seek(0, os.SEEK_END) if start is None else f.seek(start)
        line = ""
        while True:
            more = f.readline()
            if not more:
                if stopping():
                    return
                time.sleep(1)
                continue
            line += more
            if line.endswith("\n"):
                yield line
                line = ""


def part(review, key):
    """An object of the review, or an empty one when the line holds something else there."""
    held = review.get(key)
    return held if isinstance(held, dict) else {}


def stands(review):
    """Whether a person should be asked: the review did not clear it."""
    return part(review, "review").get("verdict") != "benign"


def cut(text, limit):
    """Text on one line, to `limit` characters: no line break to start a line
    of the dialog with, and no character a program's argument cannot hold."""
    text = "".join(c if c.isprintable() else " " for c in str(text or ""))
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def clock(text):
    """An RFC 3339 time as this Mac's local hour and minute."""
    t = when(text)
    return t.astimezone().strftime("%b %-d %H:%M") if t else "?"


def wording(review):
    """The dialog's title and text for a review."""
    session, found = part(review, "session"), part(review, "review")
    # every value is the log's or a model's: each on its line, cut
    judge = cut(part(review, "judge").get("warrants_investigation"), WORD) or "?"
    verdict = cut(found.get("verdict"), WORD)
    if verdict:
        head = f"The reviewer says: {verdict.upper()} (first pass: {judge})"
    else:
        head = f"The review failed, so the first pass stands: {judge.upper()}"
    entry = cut(session.get("entry"), NAME) or "a session"
    parts = [f"{entry}, {clock(session.get('from'))} to {clock(session.get('to'))}", head]
    if found.get("finding"):
        parts.append(cut(found["finding"], FINDING))
    elif found.get("error"):
        parts.append(cut(found["error"], CHECK))
        parts.append(cut(part(review, "judge").get("why"), FINDING))
    if found.get("check"):
        parts.append("Check: " + cut(found["check"], CHECK))
    parts.append("Was this you? A note is optional.")
    return f"tangent: {verdict or 'unreviewed'}", "\n\n".join(p for p in parts if p)


def script(icon, give_up):
    """The AppleScript: fixed text but for the icon's name and a number. A
    dialog's result says whether it gave up only when it was told when to."""
    wait = f" giving up after {give_up}" if give_up > 0 else ""
    gave_up = '\n    if gave up of r then return "gave up"' if give_up > 0 else ""
    buttons = ", ".join(f'"{b}"' for b in BUTTONS)
    return f'''on run argv
    tell me to activate
    set r to display dialog (item 2 of argv) with title (item 1 of argv) default answer "" ¬
        buttons {{{buttons}}} default button "Not sure" with icon {icon}{wait}{gave_up}
    return (button returned of r) & linefeed & (text returned of r)
end run'''


def dialog(title, text, serious, give_up, osascript="osascript"):
    """Show the dialog; (answer, note)."""
    cmd = [osascript, "-e", script("stop" if serious else "caution", give_up), title, text]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = p.communicate()
    finally:
        if p.poll() is None:   # stopped while the dialog was up
            p.kill()
    if p.returncode:
        raise RuntimeError("osascript: " + err.strip()[-300:])
    button, _, note = out.rstrip("\n").partition("\n")
    return BUTTONS.get(button, "none"), note.strip()


def ask(review, show, give_up=0):
    """The feedback line for a review, from the answer `show` gets."""
    found = part(review, "review")
    try:
        title, text = wording(review)
        answer, note = show(title, text, found.get("verdict") == "malicious", give_up)
    except Exception as e:   # no screen to ask on is its own line, not the end of the run
        answer, note = "none", "could not ask: " + str(e)
    return {"ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": "macos_feedback", "session": part(review, "session"),
            "judge": part(review, "judge").get("warrants_investigation"),
            "review": found.get("verdict") or "error", "reviewed": review.get("ts"),
            "answer": answer, "note": note}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--follow", metavar="FILE", help="ask about each review added to FILE from now on, instead of stdin's")
    ap.add_argument("--all", action="store_true", help="ask about every review, the ones called benign too")
    ap.add_argument("--give-up", type=int, default=0, metavar="SECONDS",
                    help="close an unanswered dialog after this many whole seconds, as answer `none` (default: wait)")
    a = ap.parse_args()
    # told to stop, it asks about what the file already holds, then ends;
    # told again, it ends now, and the dialog is closed
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0) if stopping else stopping.append(True))
    for line in lines(a.follow, stopping=lambda: bool(stopping)):
        try:
            review = json.loads(line)
        except ValueError:
            continue
        if not isinstance(review, dict) or "review" not in review:
            continue
        if a.all or stands(review):
            print(json.dumps(ask(review, dialog, a.give_up), ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
