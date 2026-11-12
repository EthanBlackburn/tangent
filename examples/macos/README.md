# macos

A Mac where AI coding agents run, read by
[packs/macos](/packs/macos) and judged by [packs/judge](/packs/judge), as
[cloud-infra](../cloud-infra) is for a company's cloud: each record goes to
the lake, and each session (a terminal tab, an app, an agent, with
everything it ran) is summed up five minutes at a time for the judge, whose
answer is pass, look or flag; each look or flag goes to `alerts.ndjson`,
once a turn. One config, one process.

```bash
../enrich/setup.sh data                        # once: the address tables that name a connection's network owner
tangent plugin compile --config tangent.yaml   # once
./run.sh                                       # everything below, in one command; Ctrl-C stops it all
```

`run.sh` starts tangent and what feeds it in the order that matters (the
snapshot, eslogger, the snapshot again, the network capture, the transcript
reader), with one sudo prompt. It names its own pid as the capture's, and
the plugin leaves out what it and the programs under it do: a packet capture
piped to a socket is what a sniffer looks like, and the judge said so of
this one in every run. `SAVE=1 ./run.sh` also keeps eslogger's and net.py's
lines beside the config, to replay.

`REVIEW=1 ./run.sh` runs review.yaml, which also gives each alert a second
look (packs/macos/README.md, "The second reviewer"): a stage of the
pipeline in which Claude Opus 5.5 on Bedrock (REVIEW_MODEL for another)
reads the alert, queries the lake,
and writes what happened and whether it was malicious to
`reviews.ndjson`, about seven minutes after the alert, once the lake has
its records. It uses the AWS credentials the Haiku judge does.

Each review that stands (not called `benign`, or of something the judge
flagged) then comes up as a dialog on this Mac: what the reviewer found,
what it says to check, and three buttons, "Not me", "Not sure" and "That
was me", with room for a note. Your answer goes to `feedback.ndjson`. The
dialog waits for you, the next behind it. `ASK=0` leaves the dialogs out,
and `jq 'select(.review.verdict != "benign")' reviews.ndjson` is then what
is left to read.

By hand, the same is:

```bash
tangent plugin compile --config tangent.yaml
tangent run --config haiku.yaml &              # Claude Haiku on Bedrock, AWS_PROFILE set; or tangent.yaml, a local model
sudo eslogger exec fork exit open close create rename unlink btm_launch_item_add tcc_modify | nc -U es.sock
python3 ../../packs/macos/ps/ps.py | nc -U es.sock           # once, after eslogger starts: what was already running
python3 ../../packs/macos/agent/transcripts.py | nc -U es.sock   # optional: what you asked Claude Code
sudo tcpdump -i pktap,all -k NP -n -l -tt -X "$(python3 ../../packs/macos/net/net.py --filter)" \
  | python3 ../../packs/macos/net/net.py | nc -U net.sock    # optional: network connections
tail -f alerts.ndjson
```

`eslogger` needs root, and the terminal it runs in needs Full Disk Access
(System Settings, Privacy & Security), restarted after the grant.

`transcripts.py` shows the judge what you asked Claude Code, beside what it
then ran (packs/macos/README.md, "What the agent was asked"). Your prompts
then reach the model that judges, and the lake, with the command lines that
already do.

- `tangent.yaml`: the judge pack, the macos pack's two plugins, the socket
  `nc` writes, the lake, and packs/macos's brief and answer schema in place
  of the judge's, the summaries sent as JSON lines; a local
  OpenAI-compatible model by default (`JUDGE_URL`, `JUDGE_MODEL`,
  packs/judge/README.md). The judge pack brings behavior-baseline's two
  plugins, which nothing routes to here: `tangent run` says so, and they
  never run.
- `haiku.yaml`: the same on Claude Haiku 5.5 through Bedrock,
  `us.anthropic.claude-haiku-5-5` (the cross-region profile; Converse refuses
  the bare model id on demand), thinking briefly before each verdict (adaptive,
  low effort). It includes the judge pack's
  `hosted.yaml` after `tangent.yaml`, which takes out the local model's
  sampling settings: Haiku 5.5 refuses them.
- `review.yaml`: haiku.yaml with the second reviewer as a stage: plugin
  `macos_review` after `macos_verdicts`, and `reviews.ndjson`.

The pack runs the pipeline on one worker, which keeps a process's events in
order, so the model gets one request at a time: a few sessions' summaries,
48 KB at most. A session is held in memory until its five minutes close, and
a restart loses the open ones.

What is kept stays here: `lake/` every record as Parquet (the pack's
`lake.yaml`; `tangent query --table lake=lake/logs "SELECT …"` reads it;
delete old hours to trim it), `state.sqlite` the process tree the plugin keeps, `verdicts.ndjson`
every session's verdict. The records hold command lines, and with the prompt
transcript reader, your prompts.
