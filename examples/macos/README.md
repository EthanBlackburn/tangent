# macos

A Mac where AI coding agents run, read by
[packs/macos](/packs/macos) and judged by [packs/judge](/packs/judge), as
[cloud-infra](../cloud-infra) is for a company's cloud: each record goes to
the lake, and each session (a terminal tab, an app, an agent, with
everything it ran) is summed up five minutes at a time for the judge, whose
answer is pass, look or flag; each look or flag goes to `alerts.ndjson`,
once a turn. One config, one process.

`tangent watch mac` runs this pipeline with nothing to keep, and `tangent init mac` writes it as one file ([Try it](/docs/try-it.md#this-mac-tangent-watch-mac)). This directory is the same pipeline from the packs, for working on them:

```bash
../enrich/setup.sh data                        # once: the address tables that name a connection's network owner
tangent plugin compile --config review.yaml    # once: the pack's plugins, and the reviewer's
tangent run --config haiku.yaml                # Claude Haiku on Bedrock, AWS_PROFILE set; or tangent.yaml, a local model
tail -f alerts.ndjson                          # in another terminal
```

`tangent run` is the whole capture: the `macos` source in tangent.yaml
(packs/macos/README.md) asks for your password once, through sudo, starts
the sensor and macOS's tcpdump as root, and reads what was already running,
each new connection, and what you ask Claude Code, from the transcripts
under `~/.claude`. Tangent runs as you and names itself as the capture, so
the plugin leaves out what it and the programs under it do. Ctrl-C stops it
all; tangent finishes the sessions it holds first. The terminal it runs in
needs Full Disk Access (System Settings, Privacy & Security), restarted
after the grant.

The sensor is [packs/macos/sensor](/packs/macos/sensor), the pack's
Endpoint Security client. A release has it built, signed and notarized, as
`tangent-sensor-macos.zip` beside the binaries: download it, unzip it, and
name the binary inside,

```bash
SENSOR=/path/to/TangentSensor.app/Contents/MacOS/tangent-sensor tangent run --config haiku.yaml
```

It runs on any Mac, with nothing to ask of Apple. Building it yourself takes
an entitlement Apple grants to a developer team (the sensor's README), and
with no `SENSOR` the config looks for it where that build leaves it.

Your prompts to Claude Code reach the model that judges, and the lake, with
the command lines that already do (packs/macos/README.md, "What the agent
was asked").

`tangent run --config review.yaml` also gives each alert a second look
(packs/macos/README.md, "The second reviewer"): a stage of the pipeline in
which Claude Sonnet 5.5 on Bedrock (REVIEW_MODEL for another) reads the
alert, queries the lake, reads the scripts and the agent settings the log
points to (never credentials or transcripts), and writes what happened and
whether it was malicious to `reviews.ndjson`, about seven minutes after the
alert, once the lake has its records. It uses the AWS credentials the Haiku
judge does.

Each review that stands (not called `benign`) then comes up as a dialog on
this Mac: what the reviewer found, what it says to check, and three
buttons, "Not me", "Not sure" and "That was me", with room for a note. Your
answer goes to `feedback.ndjson`. The dialog waits for you, the next behind
it. It is sink `ask` in review.yaml, an `exec` sink whose command is
packs/macos/review/ask.py: take the sink out and nothing asks, and
`jq 'select(.review.verdict != "benign")' reviews.ndjson` is then what is
left to read. When tangent stops, the dialogs for the reviews written as it
stopped still come up; tangent waits two minutes for them and then leaves
ask.py to finish.

To keep what the source reads, for reading through the pipeline again, add
a sink that takes the source itself (packs/macos/README.md has the lines).

- `tangent.yaml`: the judge pack, the macos pack's two plugins, the `macos`
  source, the lake, and packs/macos's brief and answer schema in place
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
  `macos_review` after `macos_verdicts`, `reviews.ndjson`, and the dialog.

The pack runs the pipeline on one worker, which keeps a process's events in
order, so the model gets one request at a time: a few sessions' summaries,
48 KB at most. A session is held in memory until its five minutes close, and
a restart loses the open ones.

What is kept stays here: `lake/` every record as Parquet (the pack's
`lake.yaml`; `tangent query --table lake=lake/logs "SELECT …"` reads it;
delete old hours to trim it), `state.sqlite` the process tree the plugin keeps, `verdicts.ndjson`
every session's verdict. The records hold command lines and your prompts.
