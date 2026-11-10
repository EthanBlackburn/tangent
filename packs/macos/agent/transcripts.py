"""transcripts.py: what a person asked Claude Code, one JSON line a prompt, for packs/macos.

Endpoint Security shows what an agent ran, never why. The same `aws` calls
are a person's request or an injected instruction, and only the prompt tells
them apart. Claude Code writes every session to a transcript,
`~/.claude/projects/<project>/<session id>.jsonl`, and marks the entries a
person typed; it also keeps `~/.claude/sessions/<pid>.json` for each running
agent, which says whose session a process is. This script follows the
transcripts and writes each prompt as it is typed:

  {"time": "...Z", "prompt": {"agent": "claude-code", "session": "<session id>",
   "cwd": "/Users/dev/code/x", "text": "look at our AWS spend", "pids": [4100]}}

`pids` is the agent's process, which is how the plugin places the prompt in
a session; a prompt of a session no running agent claims has none. Run it as
yourself beside eslogger:

  python3 transcripts.py | nc -U es.sock

It starts with the latest prompt of each session touched in the last two
hours, under its own time, since what an agent is doing now was asked for
before the capture began; then it reads only what is appended. Nothing in
Claude Code's settings changes, and sessions already open are covered. The
transcript's format is Claude Code's own and may change with a release: a
line this script cannot read is skipped.

Standard library only, so it runs on the Python macOS ships.
"""

import json
import os
import sys
import time

# Enough of a prompt to say what was asked; a pasted file is not the request.
TEXT = 4000
# A session touched this recently has its latest prompt sent at the start.
RECENT = 2 * 3600
# How much of a transcript's end is searched for that prompt.
TAIL = 8 << 20
POLL = 1.0


def prompt(entry):
    """What the person typed in a transcript entry, or None.

    An entry of type `user` is also a tool's result, a notice from the system
    or the agent's own prompt to a subagent; `origin.kind` is `human` on the
    ones a person wrote.
    """
    if not isinstance(entry, dict) or entry.get("type") != "user":
        return None
    origin = entry.get("origin")
    if not isinstance(origin, dict) or origin.get("kind") != "human":
        return None
    if entry.get("isSidechain") or entry.get("isMeta") or entry.get("isCompactSummary"):
        return None
    content = (entry.get("message") or {}).get("content")
    if isinstance(content, list):
        content = "\n".join(
            b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
        )
    if not isinstance(content, str) or not content.strip():
        return None
    return content


def line(entry, text, pid):
    """The pack's line for a typed entry."""
    made = {
        "agent": "claude-code",
        "session": entry.get("sessionId"),
        "cwd": entry.get("cwd"),
        "text": text[:TEXT],
    }
    if pid:
        made["pids"] = [pid]
    return {"time": entry.get("timestamp"), "prompt": made}


def entries(data):
    """The JSON objects in a run of whole lines; what does not parse is skipped."""
    for raw in data.splitlines():
        try:
            yield json.loads(raw)
        except ValueError:
            continue


class Follower:
    """The transcripts under a Claude Code home, read as they grow."""

    def __init__(self, home):
        self.projects = os.path.join(home, "projects")
        self.sessions = os.path.join(home, "sessions")
        self.at = {}  # transcript path -> bytes read
        self.left = {}  # transcript path -> the bytes of an unfinished line
        self.started = False

    def pids(self):
        """Session id -> the pid of the running agent that holds it."""
        out = {}
        try:
            names = os.listdir(self.sessions)
        except OSError:
            return out
        for name in names:
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.sessions, name), encoding="utf-8") as f:
                    s = json.load(f)
                out[s["sessionId"]] = int(s["pid"])
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return out

    def transcripts(self):
        try:
            projects = [e.path for e in os.scandir(self.projects) if e.is_dir()]
        except OSError:
            return
        for project in projects:
            try:
                for e in os.scandir(project):
                    if e.name.endswith(".jsonl") and e.is_file():
                        yield e.path, e.stat()
            except OSError:
                continue

    def latest(self, path, size):
        """The last typed entry in a transcript's end, or None."""
        start = max(0, size - TAIL)
        try:
            with open(path, "rb") as f:
                f.seek(start)
                data = f.read(size - start)
        except OSError:
            return None
        if start:  # the first line is cut
            data = data.split(b"\n", 1)[-1]
        last = None
        for entry in entries(data.decode("utf-8", "replace")):
            if prompt(entry) is not None:
                last = entry
        return last

    def poll(self, now=None):
        """The lines for what was typed since the last poll."""
        now = time.time() if now is None else now
        found = []
        for path, st in self.transcripts():
            if path not in self.at:
                if self.started:
                    self.at[path] = 0  # a session begun since: all of it
                else:
                    # one already there: its latest prompt, then what follows
                    self.at[path] = st.st_size
                    if now - st.st_mtime <= RECENT:
                        entry = self.latest(path, st.st_size)
                        if entry is not None:
                            found.append(entry)
                    continue
            if st.st_size < self.at[path]:  # rewritten
                self.at[path] = 0
                self.left.pop(path, None)
            if st.st_size == self.at[path]:
                continue
            try:
                with open(path, "rb") as f:
                    f.seek(self.at[path])
                    data = self.left.pop(path, b"") + f.read(st.st_size - self.at[path])
            except OSError:
                continue
            self.at[path] = st.st_size
            whole, _, rest = data.rpartition(b"\n")
            if rest:
                self.left[path] = rest
            found.extend(
                e for e in entries(whole.decode("utf-8", "replace")) if prompt(e) is not None
            )
        self.started = True
        if not found:
            return []
        pids = self.pids()
        found.sort(key=lambda e: str(e.get("timestamp")))
        return [line(e, prompt(e), pids.get(e.get("sessionId"))) for e in found]


def main():
    home = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/.claude")
    follower = Follower(home)
    try:
        while True:
            for made in follower.poll():
                sys.stdout.write(json.dumps(made) + "\n")
            sys.stdout.flush()
            time.sleep(POLL)
    except (KeyboardInterrupt, BrokenPipeError):
        pass


if __name__ == "__main__":
    main()
