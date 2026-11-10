"""prompt.py: what a person asked an AI coding agent, one JSON line, for packs/macos.

Endpoint Security shows what an agent ran, never why. The same `aws` calls
are a person's request or an injected instruction, and only the prompt tells
them apart. Claude Code runs a hook on every prompt the person submits, with
the prompt as JSON on stdin; this script is that hook. It writes one line to
the pack's socket:

  {"time": "...Z", "prompt": {"agent": "claude-code", "session": "<the agent's
   session id>", "cwd": "/Users/dev/code/x", "text": "look at our AWS spend",
   "pids": [4242, 4241, 4100]}}

`pids` is this process, its parent and its grandparent, nearest first: the
agent is one of the last two, and the plugin places the prompt in the
session of the first it knows. In `~/.claude/settings.json`:

  {"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command",
    "command": "python3 /path/to/packs/macos/agent/prompt.py /path/to/es.sock"}]}]}}

It prints nothing (a prompt hook's output is added to the agent's context),
never fails the prompt, and gives up after a second if nothing is listening.

Standard library only, so it runs on the Python macOS ships.
"""

import json
import os
import socket
import subprocess
import sys
from datetime import datetime, timezone

# Enough of a prompt to say what was asked; a pasted file is not the request.
TEXT = 4000


def line(hook, pids, now):
    """The pack's line for a hook's input, or None when it holds no prompt."""
    text = hook.get("prompt")
    if not isinstance(text, str) or not text.strip():
        return None
    return {
        "time": now,
        "prompt": {
            "agent": "claude-code",
            "session": hook.get("session_id"),
            "cwd": hook.get("cwd"),
            "text": text[:TEXT],
            "pids": pids,
        },
    }


def above(pid):
    """A process's parent, or None."""
    try:
        out = subprocess.run(
            ["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True, text=True, timeout=1
        ).stdout.strip()
        return int(out) if out else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def main():
    try:
        made = line(
            json.load(sys.stdin),
            [p for p in (os.getpid(), os.getppid(), above(os.getppid())) if p],
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )
        if made is None or len(sys.argv) < 2:
            return
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect(sys.argv[1])
            s.sendall((json.dumps(made) + "\n").encode())
    except Exception:  # the person's prompt goes ahead whatever happens here
        pass


if __name__ == "__main__":
    main()
