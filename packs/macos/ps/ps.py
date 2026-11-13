"""ps.py: the processes already running, one JSON line each, for packs/macos.

The sensor shows a process when it forks, execs or does something the pack
subscribes to. What was running before the capture began (the terminal, the
apps, an agent left open) never forks into view, so the programs it started
have no one above them and no name for the app macOS holds responsible. This
script lists what is running now:

  {"time": "...Z", "ps": {"pid": 412, "ppid": 1, "start": "2026-03-02T09:00:00Z",
   "path": "/Applications/Ghostty.app/Contents/MacOS/ghostty"}}

Run it once, as yourself, right after the sensor starts:

  python3 ps.py | nc -U es.sock

The plugin takes a line only for a process it does not know, so a late or
repeated snapshot changes nothing an event already said. `start` is when the
process began: a pid the plugin knows from an earlier run, started at another
time, is another process, and the line takes its place.

Standard library only, so it runs on the Python macOS ships.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone


def started(words):
    """ps's `lstart` (`Mon Mar  2 09:00:00 2026`, this Mac's time) in UTC; None if it is not one."""
    try:
        at = time.mktime(time.strptime(" ".join(words), "%a %b %d %H:%M:%S %Y"))
    except (ValueError, OverflowError):
        return None
    return datetime.fromtimestamp(at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def lines(out, now):
    """`ps -axo pid=,ppid=,lstart=,comm=` output as the pack's lines."""
    for row in out.splitlines():
        f = row.split(None, 7)
        if len(f) < 8 or not (f[0].isdigit() and f[1].isdigit()):
            continue
        # a login shell's argv[0] is its path after a dash
        path = f[7].strip().removeprefix("-")
        ps = {"pid": int(f[0]), "ppid": int(f[1]), "path": path}
        start = started(f[2:7])
        if start:
            ps["start"] = start
        yield {"time": now, "ps": ps}


def main():
    out = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,lstart=,comm="], capture_output=True, text=True, check=True,
        env={**os.environ, "LC_ALL": "C"},   # the date in English, whatever the Mac's language
    ).stdout
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    for line in lines(out, now):
        sys.stdout.write(json.dumps(line) + "\n")


if __name__ == "__main__":
    main()
