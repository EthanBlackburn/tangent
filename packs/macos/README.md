# macos

One developer's Mac, where AI coding agents run: the machine the [Endpoint AI
Agent Abuse catalog](https://github.com/0x4D31/endpoint-ai-agent-abuse)
describes, where a package script plants a hook in the agent's settings,
poisons its instructions, adds an MCP server, reads its transcripts, or starts
it with its API traffic pointed elsewhere. The telemetry is `eslogger`,
Apple's Endpoint Security command-line tool, already on every Mac. The pack
is two plugins: `macos` turns eslogger's events into records, which go to the
lake, and `macos_sessions` sums up each session's records, a few minutes at a
time, for the [judge](../judge). [examples/macos](/examples/macos) runs it,
one config:

```bash
cd examples/macos
tangent plugin compile --config tangent.yaml
tangent run --config haiku.yaml &               # or tangent.yaml: a local model
sudo eslogger exec fork exit open close create rename unlink btm_launch_item_add tcc_modify | nc -U es.sock
sudo tcpdump -i pktap,all -k NP -n -l -tt -X "$(python3 ../../packs/macos/net/net.py --filter)" \
  | python3 ../../packs/macos/net/net.py | nc -U net.sock    # optional: network connections
tail -f alerts.ndjson
```

`eslogger` needs root, and the terminal it runs in needs Full Disk Access
(System Settings → Privacy & Security), restarted after the grant. It writes
to stdout only, and tangent reads sockets, so `nc -U` joins them: root writes
the socket, tangent owns it, and nothing listens on a port.

[`sensor/`](sensor) is an Endpoint Security client of the pack's own that
takes eslogger's place on that line and writes the same events in the same
shape, at about half the size. It needs an entitlement Apple grants to a
developer team; eslogger needs nothing, and stays the default.

## What the plugin keeps

Endpoint Security reports everything: on a developer's Mac, about 13,000
`open` and 2,000 `close` events a minute, 7 GB a day of JSON. The plugin,
`macos`, keeps what a verdict can turn on and drops the rest before any model
sees it:

| event | kept when |
|---|---|
| `exec` | always: every program run, with its arguments and working directory; its environment cut to the names that steer a program (an agent's `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `GOOGLE_GEMINI_BASE_URL`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `GEMINI_CLI_HOME`, the `OTEL_EXPORTER_OTLP_*` endpoints, and the headers they set by name only, their values being keys; code every process loads, `NODE_OPTIONS`, `DYLD_INSERT_LIBRARIES` and the other `DYLD_*` paths, `PYTHONPATH`, `PYTHONSTARTUP`, `PERL5OPT`, `RUBYOPT`, `BASH_ENV`, `GIT_SSH_COMMAND`; where traffic goes and whom it trusts, the `*_PROXY` variables without their passwords, `NODE_TLS_REJECT_UNAUTHORIZED`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`; and npm's `npm_lifecycle_event`, `npm_lifecycle_script`, `npm_package_name` and `npm_package_version`, which name the package script running) and counted, since a program's environment is where its keys are |
| `open` | a write to any group below, or a read of any of them but what runs at login, which every shell reads |
| `close` | `modified`, on a group |
| `create`, `rename`, `unlink` | on a group (`rename` by either name) |
| `fork`, `exit` | never: they build the process tree |
| anything else (`btm_launch_item_add`, `tcc_modify`) | always, as it came, less its `stat` blocks |

The agent groups are the catalog's; credentials and what runs on its own are
what any attack on a developer goes for: a supply-chain worm's token sweep, a
Mac stealer's browser stores and wallets (`src/paths.rs` has the paths):

| `_facts` key | files |
|---|---|
| `agent_settings` | `.claude/settings*.json`, `.gemini/settings.json`, `.codex/`, `.vscode/tasks.json`, `.aider.conf.yml` |
| `agent_instructions` | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `~/.claude/projects/*/memory/`, `~/.codex/memories/`, `.cursor/rules/`, `.cursorrules`, `.windsurf/rules/`, `.windsurfrules`, `.github/copilot-instructions.md` |
| `agent_mcp` | `~/.claude.json` (and its `.tmp.*`), `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, VS Code's and Claude Desktop's configs, Windsurf's `mcp_config.json`, `.kiro/settings/mcp.json`, `.amazonq/mcp.json`, `opencode.json` |
| `agent_state` | `~/.claude/projects/` (the store itself too: a listing opens it), `~/.claude/history.jsonl`, `~/.codex/sessions/`, `~/.codex/history.jsonl`, `~/.gemini/tmp/`, `~/.cursor/chats/` |
| `agent_extensions` | `~/.claude/plugins/`, `~/.claude/skills/`, `~/.codex/skills/`, `~/.gemini/extensions/`, `~/.cursor/extensions/`, `~/.vscode/extensions/` |
| `credentials` | `~/.aws/`, `~/.ssh/`, `~/.gnupg/`, `~/.npmrc`, `~/.netrc`, `~/.docker/config.json`, `~/.kube/config`, `~/.config/gh/`, `~/.codex/auth.json`, gcloud, Azure, `.pypirc`, gem, cargo and git credentials, Terraform and Vault tokens, the 1Password CLI's, the keychains, `.env` and `.env.*`; every browser's saved passwords, cookies, cards and `Local State`, Firefox's and Safari's; wallet apps and wallet extensions' storage; 1Password's and Bitwarden's vaults, `.kdbx` files; Telegram's and Discord's sessions |
| `persistence` | `~/.zshrc` and the other rc files, `~/Library/LaunchAgents/`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/`, `/Library/StartupItems/`, `.git/hooks/`, `.git/config`, `~/.gitconfig`, `.github/workflows/`, Python's `.pth` files and `sitecustomize.py`, cron, `/etc/periodic/`, `/etc/sudoers`, `/etc/hosts` |

Each record carries the program that acted (`process`: path, signing
identity, Developer ID team, platform, uid, tty, the responsible app, and for
node, Python, bun or a shell running a file the script it runs as `name`)
and `parents`, the programs above it nearest first, each by its name (else
its path) and the arguments it was given after it, cut at 80 bytes, so
the npm above a package's script says `test` or `install`, and `lineage`,
the same programs without their arguments. Both are the whole chain, to 16,
and say where it ends: `/sbin/launchd`, which starts every app and service;
`(unknown)`, a process the tree does not know (older than the log and in no
snapshot, or long gone); or `…`, with more above. A record with no `parents` reads as a program
from nowhere, and four in five programs on a Mac are launchd's own children.
`responsible` names the process macOS holds responsible, when it is another
(the app a helper works for, the terminal a command was typed in). All from a process
tree the plugin keeps in state from `fork`, `exec` and `exit` (the pack
runs the pipeline on one worker, which keeps the events in order; an entry
lasts a day, or ten minutes once its process exits, so what it left running
still has it among its `parents`, and is written again every ten minutes its
process is at work, with the entries above it, so a shell open for a week
stays; an entry holds when its process started, and one whose pid has
another start in a later event or snapshot is of an earlier process, from
before a restart, and is replaced). `session` is the entry point the
process's session started from, as ECS's entry leader, which a process takes
from its parent when it forks and keeps when that parent exits; for a
process whose fork was not seen, walking up the tree, the first process whose
parent is launchd (a service or an app) or a login or sshd (a terminal tab, a
remote shell), else the oldest the tree knows; a terminal tab, an agent
started before the log, or an app, with everything it went on to run. It has
the entry's pid (`id`), who it is (`entry`) and the five minutes the event
falls in (`window`). `_norm.actor` is the job the
record belongs to, as Elastic's group leader and Apple's responsible process
say: the leader of its process group, which a shell makes of a command line
(`claude`, `npm install`) and an app of itself, so Claude Code's `git` and
`security` are read as Claude Code's and a postinstall as its `npm`'s; for a
process in launchd's group (a service, an XPC helper), or one whose leader
the tree never saw, the process macOS holds responsible; else the process
itself. A job is named for its program: an interpreter's `name`, the script it
runs; else a vendor-signed program's signing identity, so Claude Code is one
actor across updates; else its path (Apple's command-line tools share one
identity, and an ad hoc signature is the binary's hash). `_norm.target` is
the file; `_facts` adds `steering_env`,
`scratch_program` (it, or the script it runs, is in /tmp, a cache, Downloads
or a project's node_modules, not a global install), `unsigned` and
`rename_over`. Command lines are cut, 400 bytes an argument and 1,500 in
all, with the rest counted. About 700 bytes a record.

## What was already running

eslogger shows a process when it forks, execs or does something the pack
subscribes to. The terminal, the apps and an agent left open were started
before the capture, so the programs they run have no one above them and
`responsible` has a pid and no name: in a ten-minute run 68 of 249 programs'
chains ended in `(unknown)`, and the judge read one as "no known launcher".
`ps/ps.py`, standard library only and run as you, lists what is running
(`ps -axo pid=,ppid=,lstart=,comm=`) as one JSON line each; sent to the
eslogger socket once, right after eslogger starts, it gives the tree each
process's parent, path and start. The plugin takes a line only for a process
it does not know, or knows by another start, and a process's first event replaces what the snapshot said (its
signature, and its parent unless launchd has taken it since), so a late or
repeated snapshot does no harm. `ps/ps_test.py` checks it.

## The capture's own processes

The script that runs the capture (examples/macos/run.sh) writes one line to
the eslogger socket, `{"monitor": {"pid": N}}`, with its own pid. From then
on the plugin drops the records of that process and everything under it
(tcpdump, net.py, the snapshot and the transcript reader), though the tree
still knows them. A name or a command line could not exempt them, since a
look-alike is worth a flag. The declaration is itself a record, in the
session of the process it names: anything running as the person can write
the line, and a program that is called the monitor is seen being so. A line
that names a pid the tree does not know is not taken, since it would exempt
whatever took that pid next with no record of it.

## What the agent was asked

Endpoint Security shows what an AI coding agent ran and never why: the same
`aws` calls are the person's request or an injected instruction, and only the
prompt tells them apart. Claude Code writes each session to a transcript
(`~/.claude/projects/<project>/<session id>.jsonl`), marks the entries a
person typed (`origin.kind` is `human`; a tool's result, a system notice and
the agent's prompt to a subagent are entries too), and keeps
`~/.claude/sessions/<pid>.json` for each running agent. `agent/transcripts.py`,
standard library only and run as you, follows the transcripts and writes each
typed prompt (to 4000 characters) with the agent's session id, working
directory and pid as one JSON line. A message typed while the agent is
working never becomes a `user` entry: Claude Code queues it as an attachment
(`queued_command`, its `origin.kind` `human` too), and the script takes
those as well, marked `during`. Each line carries `after`, what the agent
had last said before the prompt, its first 400 characters and its last 800:
"yes, the second one" says nothing alone.

    python3 agent/transcripts.py | nc -U es.sock

It starts with the latest three prompts of each session touched in the last two
hours, since what an agent is doing was asked for before the capture began,
and then reads what is appended. Nothing in Claude Code's settings changes,
and sessions already open are covered. The plugin makes each line a `prompt`
record in the session of the agent's process, and the summary shows the
session's latest five prompts in the order they were typed, each to 600
bytes with its time, as `asked`: this window's and, from state for two hours,
the ones before, since what an agent runs for an hour was asked for once. A
prompt has `replying_to` (what the agent had last said) on the summary it
first appears in, and `while_working` when it was typed mid-turn. A window that holds only a prompt
is not judged alone. The transcript's format is Claude Code's own and may
change with a release; a line the script cannot read is skipped. Anything
running as the person can write a transcript or a line to the socket, so a
prompt is what was recorded, not proof. `agent/transcripts_test.py` checks it.

## Network

Endpoint Security has no network event, so the pack reads connections from
`tcpdump`, which on macOS tags each packet with the process that sent it
(`-k NP` on the `pktap` interface): 148 of 153 new connections in a minute
of this Mac's traffic carried the tag. `net/net.py`, standard library only
and run as you (only tcpdump is root), takes what starts a connection (TCP
SYNs, TLS ClientHellos, QUIC Initials, DNS answers: `net.py --filter`) and
writes one JSON line each: the process and pid, the app a system daemon
connected for (`eproc`), the address, port and protocol, and the host, from
the hello's server name or a DNS answer it saw before. The `macos` plugin
makes each a `connect` record, joined to the process tree and session like
any event, and the summary lists each program's destinations in
`connected`. The plugin has the enrichment tables describe each address
(`_facts.ips`, from packs/enrich-ip: GeoLite2's network owner and country,
and the hosting, Tor and VPN ranges), and the summary puts the owner and
those labels in brackets after the destination,
`evil.example:443 [Example Hosting B.V.; datacenter]`: a host name says what
was asked for, and a bare address says nothing, so the owner is what a
reader has to go on. The country stays in the record and out of the summary:
a CDN's edge is wherever it is. Without the tables' files
(`examples/enrich/setup.sh data`) there are no brackets. A hello that a post-quantum key share makes longer than one
segment may hold its server name in the second, which the filter does not
take: on a 30-second capture, half of a browser's and an Electron app's
connections; curl, node and Python name it in the first. QUIC's hello is
encrypted, so a QUIC connection is named by DNS or not at all. Nothing past
a hello is read: no URL, no payload, no bytes counted. `net/net_test.py`
checks it (`python3 -m unittest net_test` in `net/`).

## What a program usually does

Claude Code reads its own credential from the keychain at every start,
Chrome connects everywhere, and Spotlight opens every file. That is true of
every Mac, and each drew a flag. `profiles.yaml` says what some programs do
as a matter of course: the hosts a program connects to (`*` is anywhere, a
leading dot every host under a domain), the paths it reads and writes, and
the programs it runs for itself. A program is matched by its code identity,
never its name or path: its Developer ID team and signing identifier, or for
a part of macOS `platform` and the identifier, so a binary called Chrome
that someone else signed gets nothing. The summary names the profile on the
program (`profile`), puts ` (usual)` after each destination and file the
profile lists, and marks a helper the program runs for itself (`started`).
Nothing is taken out: the judge reads the fact with the note beside it, and
what a profiled program does beyond its profile is unmarked. The `macos`
plugin keeps each process's signing identity in its tree, so a connection,
which tcpdump reports by pid alone, is matched as well. The pack's
ingest.yaml loads the file as the `programs` table. It has Claude Code,
Google Chrome, Spotify, Cursor, Spotlight and macOS password AutoFill,
written from captures of one Mac: a release that adds an endpoint is
unmarked until the file says so.

## The judge

The judge reads sessions, not records. `macos_sessions` is grouped by
`session.id` and `session.window`: a session's events within five minutes of
each other, closed live fifteen minutes after the first or after a minute of
quiet. An agent's session is cut at the person's prompts instead: a prompt
that sets the agent to work opens a turn (`session.turn`, the prompt's
time), a message typed while it works joins the turn under way, and the
turn's events are summed up five minutes of their own time at a time
(`session.window` is the turn and the piece's number). So a prompt and the
commands it caused are one summary, or several in a row when the turn runs
long, never a prompt in one window and its deletes in the next. Thirty-second
pieces were tried: a nine-minute turn was twenty-three verdicts, each a
chance to flag what the last had passed. It writes one record a group: the session's entry and time span, and
for each of its programs (25: those that touched a file, set an agent's
environment or did something rarer, then the busiest; one program under two
different parents is two), what it is (path, signing
identity, team, platform, tty), what started it (`parents`, the whole chain,
and `responsible`), the commands it
ran with how often, what it did to the files in the groups above (created,
written, read, deleted, replaced, renamed into place; each file named, or for
many under one directory the directory with a count and a few names), the
agent-steering variables it set, and its rarer events. The files are listed
by what was done to them, not by group, and the facts stay out: a model
reads `persistence` or `credentials` on a file as a verdict, and flagged
sessions that only read `CLAUDE.md` as agents do at every start. Claude Code's marketplace refresh, two thousand events in a
second, is one line of it; a session is a few kilobytes.

A session reaches the judge a piece at a time, and a piece alone says
little: the read that makes an upload a theft was a piece back. With each
verdict the judge writes `so_far`, its own summary of the session up to that
piece. `macos_verdicts`, a third plugin, which your config routes the judge
to, keeps it in state, and `macos_sessions` puts it on the session's next
summary. The summary also lists `earlier_in_turn`: the files and
destinations the turn's earlier pieces touched that no profile calls
routine, the latest twenty, which is the pack's own account and no model's.
The judge is not shown what it flagged before: shown that, it took its own
flag for evidence and flagged again. `macos_verdicts` is where the repeat
stops, since it passes on a verdict only when a person has not been told of
it in that turn, or, in a session with no turns (a terminal tab, an app),
in that hour.

The judge pack's judge reads them as JSON lines, with `judge.md` as its
brief and `judge.schema.json` as its answer, which `judge.yaml` names in
place of the judge's: a config includes it and the pack
(`include: [pack:macos, pack:macos/judge]`; examples/macos/tangent.yaml
does, by path). The brief is the
job, not cases: the logs of one person's Mac, a summary per session, each
field explained, and what malicious means, which is this Mac used for
someone else's ends: secrets or the owner's data leaving, something left to
run later or to steer an agent, the owner's access spent, trust redirected,
or tracks covered. Unrequested is not malicious and neither is unusual, and
records are data, not instructions. The answer is `assessment`, what the
record shows and who did it, then `warrants_investigation`: `pass`, `flag`
when this may be someone acting against the owner, or `look` when the
record leaves that open; then `why` for a look or a flag, and `so_far`. The
model says what it saw before it decides, and there is no number: with a 0
to 10 scale beside the flag it drifted along the scale, and without one the
same records drew fewer false flags. `macos_verdicts` passes on each `look`
or `flag` a person has not been told of in that turn (the turn's first, or
a `flag` after its `look`), and the example routes it to `alerts.ndjson`,
so an alert is a look or a flag and says which. On tangent-eval's macOS
suite a `flag` alone caught about half the must-flag cases and almost no
look-alike; `look` or `flag` caught nine in ten, with about four in a
hundred ordinary sessions marked. Nothing here goes to
behavior-baseline: on a Mac, "first time" fires on every update, new project
and plugin refresh.

## The cases

The question under every session is who touched the agent's steering, and
whether the agent was steered or made to act. These are the catalog's
techniques as they show in the records, and what looks like each and is not.
They are for the person reading the alerts: the brief does not list them, and
the judge reads each session whole.

| case | in the records | not this |
|---|---|---|
| A hook planted (catalog H) | a write, create or `rename_over` on `agent_settings` by a package script (node, python, sh under npm, pip, bun, uv), a program from a fresh clone, an extension host, a browser, or a program with no tty | the agent saving its own settings; an editor, when the person is editing them |
| Instructions poisoned (I) | the same writers on `agent_instructions`: `CLAUDE.md`, `AGENTS.md`, memory | the agent writing its memory; an editor |
| An MCP server added (M) | the same writers on `agent_mcp`; `~/.claude.json` replaced by a rename | the agent's own tmp-and-rename of `~/.claude.json` |
| Transcripts read (S) | a read of `agent_state` by anything but the agent that wrote it: a package script, a sync client, an unknown program | the agent appending to its transcript |
| Extensions swapped (X) | a write to `agent_extensions` by anything but the agent | a marketplace refresh: hundreds of files into `.staging`, live renamed to `.backup`, staging to live, backup unlinked, within a minute |
| Credentials read | a read of `credentials` by anything but the tool the file belongs to, or by a `scratch_program`, or under an agent | `aws` reading `~/.aws`, `git` and `ssh` reading `~/.ssh`, `npm` reading `~/.npmrc`, `gh` reading `~/.config/gh`, the agent reading the keychain |
| The agent redirected | an exec with `steering_env`: `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` sends its traffic, prompts and keys included, wherever the URL points; `CLAUDE_CONFIG_DIR` or `CODEX_HOME` makes it read another config; an `OTEL_EXPORTER_OTLP_*_ENDPOINT` sends its telemetry away | the vendor's own URL; a well-known local proxy port |
| The agent run headless | an exec of the agent with `--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--yolo`, `--trust-all-tools` or `-p`, with node, a package manager or a script among its parents, or no tty | the person typing it in a shell |
| The agent made to act | under an agent (it is in `parents`), a child that reads credentials or transcripts, writes `persistence`, runs curl or a shell with a URL, pushes, publishes or installs | the agent running `git`, `security`, the shell and the build for its own commands |
| Persistence | a write to `persistence`: rc files, LaunchAgents, LaunchDaemons, git hooks, `.git/config`, `.github/workflows/`; a `btm_launch_item_add` | an editor on `~/.zshrc`; `git` writing `.git/config` on clone; an installer the person ran |
| A program from nowhere | a `scratch_program` (from `/tmp`, a cache, Downloads, `node_modules`) or `unsigned` program that then touches any group | a build tool's children |
| Covering tracks | `rename_over` or an unlink on a transcript; writes to two vendors' agent files from one process | the agent rotating its own files |
| A permission changed | `tcc_modify` | an installer the person plainly ran |

A session holds the chain: what a terminal tab, an agent or an app ran and
what each program touched, with `parents` on every program. One worked case, Shai-Hulud, the npm worm of 2025: `npm
install` runs its preinstall script, so the judge sees node from
`node_modules` under `sh ← npm ← zsh` (an exec, `scratch_program`), then bun,
then a TruffleHog binary from a temp directory. The scanner opens `~/.npmrc`,
`~/.aws/credentials`, `~/.config/gh/hosts.yml` and `.env` files: credential
reads by bun, not by npm, aws or gh, flagged at the first one, before
anything leaves. Its attempt to drive Claude Code, Gemini CLI or Codex is an
exec of the agent with `-p` and the skip flag under node, tty or not, and the
agent's children then read credentials under it. `git push`, `curl` to GitHub
and `npm publish` are execs with the worm's node in their parents; a workflow
file committed for persistence is a write to `.github/workflows/`; the wipe
it runs when it finds no token is unlinks of transcripts, settings and
credentials by bun. With net.py, the worm's calls to GitHub's API and to
its own servers are `connected` on the program that made them; what they
sent, and the package's contents, are not in these records.

## Tests

`tests/input.json` is thirty-eight synthetic eslogger records, two of
net.py's lines, two of ps.py's and one of transcripts.py's (version 10,
schema 1, the shapes of a macOS 26 capture, no real values): a shell, an agent
started from it with `ANTHROPIC_BASE_URL` set, the person's prompt to it, the agent saving its config and
reading the keychain, a package install under it whose `node` reads
credentials and a transcript, plants a settings file and `CLAUDE.md`, and runs
an unsigned program from `/tmp` that installs a LaunchAgent, which, once
the package script and the agent above it have exited, reads an SSH key and
calls evil.example; a browser's QUIC connection made by its helper, and the
helper saving cookies; the terminal and the login above the shell, known only
from the snapshot; and around them the noise the plugin drops.
`tests/expected.json` is the twenty-five records the plugin keeps, written
against `tests/addresses.yaml` and `tests/networks.csv`, the tables' answers
for the fixture's two addresses. `make test` in `packs/` runs it; `cargo test` here runs the
path groups' unit tests, and in `sessions/` the summary's, one of them over
`tests/expected.json` as one session (the plugin test harness calls a plugin
a record at a time, without its grouping). The plugin drops records, so `make fixtures-macos`
refuses to rewrite `expected.json`; after a change, run the test and copy
`test_out.ndjson` into it once you have read the diff.

## Not here

Network is read from tcpdump (above), so a connection's payload, and a
browser's hosts that DNS did not name, are not in these records. The
capture this was built against
shows what an agent does to its own files; how Codex, Gemini and Cursor write
theirs, and what an agent's own exec looks like when a script starts it, are
written from the catalog, not seen. `btm_launch_item_add` and `tcc_modify`
have not been captured either: they pass through whole.
