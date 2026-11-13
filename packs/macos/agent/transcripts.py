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
yourself beside the sensor:

  python3 transcripts.py | nc -U es.sock

A message typed while the agent is working is marked `during`: Claude Code
counts it as part of the turn under way, and so does the pack, which cuts an
agent's session at the prompts that start a turn.

It starts with the latest three prompts of each session touched in the last
two hours, under their own times, since what an agent is doing now was asked
for before the capture began; then it reads only what is appended. A prompt
typed while the agent works is taken too, and each carries `after`, the end
of what the agent last said before it: "yes, the second one" says nothing alone. Nothing in
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
# What the agent last said before a prompt, which the prompt replies to:
# "yes, the second one" says nothing without it. Its start says what it was about
# and its end holds the question, so a long one is sent as both.
SAID_START, SAID_END = 400, 800
# A session touched this recently has its latest prompts sent at the start,
RECENT = 2 * 3600
# this many of them.
START = 3
# How much of a transcript's end is searched for them.
TAIL = 8 << 20
POLL = 1.0


def prompt(entry):
    """What the person typed in a transcript entry, or None.

    A prompt that starts a turn is an entry of type `user`, as are a tool's
    result, a notice from the system and the agent's own prompt to a
    subagent. A message typed while the agent is working never becomes one:
    it is an `attachment` of type `queued_command`, as a finished task's
    notice is too. `origin.kind` is `human` on what a person wrote, in both.
    """
    if not isinstance(entry, dict):
        return None
    if entry.get("isSidechain") or entry.get("isMeta") or entry.get("isCompactSummary"):
        return None
    if entry.get("type") == "attachment":
        held = entry.get("attachment")
        if not isinstance(held, dict) or held.get("type") != "queued_command":
            return None
        origin, content = held.get("origin"), held.get("prompt")
    elif entry.get("type") == "user":
        origin, content = entry.get("origin"), (entry.get("message") or {}).get("content")
    else:
        return None
    if not isinstance(origin, dict) or origin.get("kind") != "human":
        return None
    if isinstance(content, list):
        content = "\n".join(
            b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
        )
    if not isinstance(content, str) or not content.strip():
        return None
    return content


def said(entry):
    """What the agent wrote to the person in a transcript entry, or None."""
    if not isinstance(entry, dict) or entry.get("type") != "assistant" or entry.get("isSidechain"):
        return None
    content = (entry.get("message") or {}).get("content")
    if not isinstance(content, list):
        return None
    texts = [
        b["text"]
        for b in content
        if isinstance(b, dict) and b.get("type") == "text" and str(b.get("text", "")).strip()
    ]
    return texts[-1] if texts else None


def line(entry, text, pid, after=None):
    """The pack's line for a typed entry, with what the agent last said before it.

    `during` marks a message typed while the agent was working: it adds to the
    turn under way and starts none, as Claude Code itself counts turns.
    """
    made = {
        "agent": "claude-code",
        "session": entry.get("sessionId"),
        "cwd": entry.get("cwd"),
        "text": text[:TEXT],
    }
    if entry.get("type") == "attachment":
        made["during"] = True
    if after:
        after = after.strip()
        made["after"] = (
            after
            if len(after) <= SAID_START + SAID_END
            else f"{after[:SAID_START]} … {after[-SAID_END:]}"
        )
    if pid:
        made["pids"] = [pid]
    return {"time": entry.get("timestamp"), "prompt": made}


def read(data, last=None):
    """The typed entries in a run of whole lines, each with what the agent
    last said before it, and what it last said by the end."""
    found = []
    for entry in entries(data):
        spoke = said(entry)
        if spoke is not None:
            last = spoke
        elif prompt(entry) is not None:
            found.append((entry, last))
    return found, last


def entries(data):
    """The JSON objects in a run of whole lines; what does not parse is skipped.
    A line ends at a newline alone: a prompt may hold the other characters
    `splitlines` breaks at (U+2028, U+0085), unescaped."""
    for raw in data.split("\n"):
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
        self.last = {}  # transcript path -> what the agent last said
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
        """The last [`START`] typed entries in a transcript's end."""
        start = max(0, size - TAIL)
        try:
            with open(path, "rb") as f:
                f.seek(start)
                data = f.read(size - start)
        except OSError:
            return []
        if start:  # the first line is cut
            data = data.split(b"\n", 1)[-1]
        found, self.last[path] = read(data.decode("utf-8", "replace"))
        return found[-START:]

    def poll(self, now=None):
        """The lines for what was typed since the last poll."""
        now = time.time() if now is None else now
        found = []
        for path, st in self.transcripts():
            if path not in self.at:
                if self.started:
                    self.at[path] = 0  # a session begun since: all of it
                else:
                    # one already there: its latest prompts, then what follows
                    self.at[path] = st.st_size
                    if now - st.st_mtime <= RECENT:
                        found.extend(self.latest(path, st.st_size))
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
            new, self.last[path] = read(whole.decode("utf-8", "replace"), self.last.get(path))
            found.extend(new)
        self.started = True
        if not found:
            return []
        pids = self.pids()
        found.sort(key=lambda f: str(f[0].get("timestamp")))
        return [line(e, prompt(e), pids.get(e.get("sessionId")), after) for e, after in found]


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
