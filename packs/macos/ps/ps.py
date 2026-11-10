"""ps.py: the processes already running, one JSON line each, for packs/macos.

eslogger shows a process when it forks, execs or does something the pack
subscribes to. What was running before the capture began (the terminal, the
apps, an agent left open) never forks into view, so the programs it started
have no one above them and no name for the app macOS holds responsible. This
script lists what is running now:

  {"time": "...Z", "ps": {"pid": 412, "ppid": 1, "path": "/Applications/Ghostty.app/Contents/MacOS/ghostty"}}

Run it once, as yourself, right after eslogger starts:

  python3 ps.py | nc -U es.sock

The plugin takes a line only for a process it does not know, so a late or
repeated snapshot changes nothing an event already said.

Standard library only, so it runs on the Python macOS ships.
"""

import json
import subprocess
import sys
from datetime import datetime, timezone


def lines(out, now):
    """`ps -axo pid=,ppid=,comm=` output as the pack's lines."""
    for row in out.splitlines():
        f = row.split(None, 2)
        if len(f) < 3 or not (f[0].isdigit() and f[1].isdigit()):
            continue
        # a login shell's argv[0] is its path after a dash
        path = f[2].strip().removeprefix("-")
        yield {"time": now, "ps": {"pid": int(f[0]), "ppid": int(f[1]), "path": path}}


def main():
    out = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,comm="], capture_output=True, text=True, check=True
    ).stdout
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    for line in lines(out, now):
        sys.stdout.write(json.dumps(line) + "\n")


if __name__ == "__main__":
    main()
