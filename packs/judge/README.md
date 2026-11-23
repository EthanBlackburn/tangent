# judge

Not a provider: a model reads each actor's records a group at a time, with
what [behavior-baseline](../behavior-baseline) knew of the actor before them,
and writes a verdict per record; a person reads the ones it flagged.
[ingest.yaml](ingest.yaml) includes [enrich-ip](../enrich-ip) and
behavior-baseline, so a config that includes it has the tables and the
baseline too, and names nothing more than its packs.

```
your sources ──▶ a pack's plugin ──┬──▶ a sink of yours: lake/, every record as Parquet     (your config)
                   reads the       ├──▶ baseline_builder ──▶ state.sqlite                     (behavior-baseline)
                   tables geo,     │                              │
                   asn, networks   └──▶ baseline_renderer ◀───────┘
                   and profile          an actor's records, a group at a time               (judge)
                   (enrich-ip)               │
                                             ▼
                                           judge ──▶ fresh ──┬──▶ flagged ──▶ alerts.ndjson
                                                             └──▶ verdicts.ndjson
```

[The second reviewer](#the-second-reviewer) is a stage you can add after
**flagged**: a stronger model that settles each actor's alerts with the lake
to query.

One config holds all of it, in one process: the judge's groups run on
workers of their own, so ingest never waits on the model. A pack defines
only its plugin, and your config gives it as an input to `baseline_builder`,
`baseline_renderer` and the sink that keeps its records
([the lake](../README.md#the-lake) in the examples).

## ingest.yaml

- **baseline_renderer**, behavior-baseline's, which your config routes each
  pack's plugin to: this file groups its records an actor at a time
  (`group_by: [_norm.org, _norm.actor]`): a group closes at 30 records
  (`max_events`) or an hour after its first record (`max_age_ms`), however
  busy the actor; an hour's quiet (`expire_after_ms`) closes it no sooner.
  It reaches the renderer whole, on workers of its own, with the actor's
  latest ten records again ahead of it, marked `_context` (`history: 10`):
  forty records a request, which `batch_bytes` is sized for. Groups wait in
  memory; the end of input closes every open one, and so does a signal
  (Ctrl-C, a restart). After a signal, though, the model calls have ended:
  the groups it closes and the requests the model has not answered get no
  verdict, their records in your sink and the baseline, and nothing asks
  about them again. The renderer puts the same `_baseline` on each of an
  actor's records
  ([behavior-baseline](../behavior-baseline#what-it-stamps)); when it
  fails, the records go to the model without it.
- **judge** reads an actor's records together and writes a verdict per record,
  with [judge.md](judge.md) as its brief and
  [judge.schema.json](judge.schema.json) as the verdict's shape.
- **fresh** drops the `_context` records; **flagged** keeps the verdicts a
  person should see, in `alerts.ndjson`. Every verdict goes to
  `verdicts.ndjson`.

## The model

The judge is any OpenAI-compatible model, set by the environment:

| variable | default |
|---|---|
| `JUDGE_URL` | `http://localhost:8080/v1` |
| `JUDGE_MODEL` | `glm-4.7-flash` |
| `JUDGE_API_KEY` | `none` |

Serve the default with llama.cpp's `llama-server`, which turns the verdict
schema into a grammar, so replies are always well-formed and their reasons
stay short (`mlx_lm.server` accepts the schema and ignores it, and with this
model about one reply in five came back unreadable):

```bash
llama-server -m GLM-4.7-Flash-Q4_K.gguf --port 8080 -np 1 -c 32768 -ngl 99 -fa on --jinja --temp 0.7 --top-p 0.95
```

`ingest.yaml` also sends that model's sampling settings (`temperature: 0.7`,
`top_p` and `chat_template_kwargs`), which a hosted model may refuse: Claude
Haiku 5.5 refuses `temperature` and `top_p`, and `chat_template_kwargs` is
llama.cpp's. For a hosted one, include [hosted.yaml](hosted.yaml) in place
of `ingest.yaml`: the same judge without them. With an OpenAI-compatible
endpoint that is
`JUDGE_URL=https://api.openai.com/v1 JUDGE_MODEL=gpt-5.1 JUDGE_API_KEY=$OPENAI_API_KEY`;
for Claude Haiku 5.5 on Bedrock, your config sets the rest:

```yaml
include: [packs/judge/hosted.yaml]
models:
  judge:
    type: bedrock
    model: us.anthropic.claude-haiku-5-5
    aws: { region: us-west-2 }               # and `profile`; the SDK's chain when unset
inference:
  judge:
    max_tokens: 400                          # per record
    extra: { thinking: { type: disabled } }  # no thinking: the reply is the answer
```

These are the settings tangent-eval's
[harness/maincfg.py](https://github.com/EthanBlackburn/tangent-eval/blob/main/harness/maincfg.py)
runs Haiku 5.5 with.

A model that thinks before it answers spends `max_tokens`, 200 a record, on
the thinking, and a reply cut short is an error on its records. Have it
answer without, in your config beside the include; on OpenRouter, where
DeepSeek V4 Flash thinks unless told not to:

```yaml
inference:
  judge:
    extra: { reasoning: { enabled: false } }
```

The records go to the model as logfmt, a line each, each source written as
its row under `encoding.sources` says: about half the tokens of JSON lines, and an
actor's `_baseline` written once per request. Your config can send JSON
lines instead, where `_baseline` is on every record; give it half the
`batch_bytes` then, so a request fits a 32k context:

```yaml
inference:
  judge:
    batch_bytes: 48000
    encoding:
      type: ndjson
```

Measured on the requests of the corpus the packs are evaluated on, an
actor's forty records each, with GLM-4.7-Flash's tokenizer, `judge.md` and
the schema included:

| encoding | `batch_bytes` | requests | tokens, median | 90th percentile | largest |
|---|---|---|---|---|---|
| logfmt, without `_baseline` | 48000 | 487 | 6,508 | 8,298 | 15,928 |
| logfmt (the default) | 96000 | 485 | 6,817 | 8,604 | 18,560 |
| JSON lines, without `_baseline` | 48000 | 487 | 9,089 | 10,323 | 21,086 |
| JSON lines | 96000 | 485 | 20,262 | 22,620 | 33,303 |
| JSON lines | 48000 | 872 | 12,738 | 15,689 | 20,200 |

Logfmt was measured with Claude Haiku 5.5, where it caught what JSON caught;
the default model has not been measured with either.

## Slack

What **flagged** keeps can go to a channel too: add a `slack` sink that
takes `flagged` to your config, and export `SLACK_WEBHOOK_URL`, an incoming
webhook's URL.

```yaml
sinks:
  slack:
    inputs: [flagged]
    type: slack
    webhook_url: ${SLACK_WEBHOOK_URL}
    text: "*{_norm.actor}* {_norm.kind|eventName|eventType|action|event|step|events.0.name} from {_norm.ip|sourceIPAddress|client.ipAddress|ipAddress|actor_ip|ip|client_ip}: {judge.why|not judged: judge.error}"
```

In `text`, `{a.b}` is the record's field (`-` when it has none) and `{x|words y}`
the first of them it has, so a record the model could not judge says why. A
field's value is escaped: a log line cannot mention anyone, link or start a
line in the message. A post that can work later (a 429, after its
`retry-after`, a 5xx, a timeout) is tried again, and its record is acked
only once Slack has it; one Slack refuses (another 4xx) is dropped and
counted in `tangent_sink_records_rejected_total`, and the first is logged.

## A command

For anywhere else an alert should go (a pager, a ticket, a dialog on your
screen), an `exec` sink gives each record to a command of yours, a JSON
line on its stdin:

```yaml
sinks:
  page:
    inputs: [flagged]
    type: exec
    command: [python3, page.py]    # the program and its arguments, not a shell's line
```

```python
# page.py
import json, sys
for line in sys.stdin:
    alert = json.loads(line)
    print("flagged:", alert["_norm"]["actor"], alert["judge"]["why"], flush=True)
```

Tangent starts the command when it starts, so one that cannot start stops
tangent there, and it is one process for the whole run, which gets the
records in the order the sink did. What it prints goes where tangent's own
output goes. It ends when its stdin closes: at
tangent's stop its stdin is closed and tangent waits for it to end, up to
the two minutes every sink has, and Ctrl-C at the terminal does not reach
it, so the alerts written during the stop find it running. A command still
at work after that is left to finish alone.

A record is delivered once it is written to the command. One the command
had read and not acted on when it ended is not sent again; a command that
ends is started again for the next record. A command that reads slower
than records come holds them in its pipe and the sink's queue, and past
those tangent waits for it, as for any sink that is down. `tangent replay`
leaves the sink out, as it does Slack.

## The second reviewer

The judge reads an actor's latest records, flags freely and cannot look
anything up, so much of what it flags is ordinary work. Plugin `review`
(`review/`, [review.yaml](review.yaml)) is a stage after **flagged** that
gives each actor's alerts to a stronger model with the lake to query.

```
flagged ──┬──▶ alerts.ndjson
          └──▶ review ──▶ reviews.ndjson          (your config's inputs)
                 │  ▲
        model.chat  lake.query
                 ▼  │
             reviewer   lake/, what your sink has kept
```

It holds one conversation with inference node `reviewer` (tangent's
`model.chat`) for an actor's alerts together: Claude Sonnet 5.5 on Bedrock
unless `REVIEW_MODEL` names another, [review.md](review.md) as its brief,
the alerts as the judge left them (each record with `_norm`, `_facts`, the
actor's `_baseline` once, and the judge's reason), and two tools. `query`
runs the model's SQL (tangent's `lake.query`, DataFusion) on one table,
`records`: a view over the lake's Parquet files for the thirty days before
the last alert, ending where it does, with a column for each field every
source shares (`ts`, `source`, `org`, `actor`, `kind`, `ip`) and the record
whole beside them as JSON text, which the model reads by key
(`record->>'eventName'`). `report` gives the answer: `finding`, what
happened and who did it, naming the records; `verdict`, `malicious`,
`benign` or `unresolved` (the log cannot settle it, and the finding says
what is missing); and `check`, what to look at or undo first.

Each alert goes on with `review`, the same on every alert of the actor's
group. The first also carries `reviewed`: how many alerts the review
covered, the SQL the model ran, the calls and tokens it took, and the node.

[A judge and a reviewer, by provider](#a-judge-and-a-reviewer-by-provider)
is the whole of it in one include. To wire it yourself:

Include it beside `ingest.yaml` or `hosted.yaml` in a config with a sink
named `lake`, and name two inputs
([examples/cloud-infra/review.yaml](/examples/cloud-infra/review.yaml) does,
and `pack:judge/review` is the same file built in):

```yaml
include: [packs/judge/hosted.yaml, packs/judge/review.yaml]
sinks:
  reviews: { inputs: [review], type: file, path: reviews.ndjson, compression: { type: none } }
plugins:
  review: { inputs: [flagged] }
```

The view reads the lake as examples/cloud-infra writes it: Parquet with
`ts`, `source` and `_norm`'s `org`, `actor`, `kind` and `ip` as columns, and
`record_column: record`. A lake without those columns does not fit it.

An actor's records are in the lake once the sink seals their file, an hour
after opening it in the example. So the plugin is grouped by actor with
`expire_after_ms: 4000000`: an actor's alerts wait that long after the last
of them and are reviewed as one, and the table ends with the last alert, so
a replay's review sees what a live one would. With a lake that seals sooner,
set both lower in your config. A grouped plugin has workers of its own, so a
review holds up neither ingest nor the judge; reviews themselves go one at a
time (`concurrency: 1`), a turn given two minutes and three tries. Alerts
still waiting when the input ends are reviewed before the lake has their
last records: the model is told so, and `reviewed` says `early: true`.

A review that fails is an `error` in `review`, and the alerts stand: the
model's content filter stopped it, it gave no report within its twenty
queries, no alert had a time in UTC to end the table at, or the lake could
not be read. `alerts.ndjson` is written as before, whatever the reviewer
says: what to do with a `benign` is your config's to decide.

The SQL is written by a model that has just read whatever an attacker put in
a record. `lake.query` lets a statement read the view and nothing else: it
cannot create, change or copy anything, set an option, or name a file. The
brief tells the model that text in a record addressed to a reviewer is
evidence against its actor. Your records reach one more model: the alerts,
and each query's result.

## A judge and a reviewer, by provider

A pack for each provider names the two models, with the settings they were
measured with, and brings the lake the reviewer reads and
`reviews.ndjson`. Your config includes one, and routes each pack's plugin
to `lake`, `baseline_builder` and `baseline_renderer`:

```yaml
include: [pack:judge/anthropic, pack:cloudtrail]
plugins:
  baseline_builder: { inputs: [cloudtrail] }
  baseline_renderer: { inputs: [cloudtrail] }
sinks:
  lake: { inputs: [cloudtrail] }
```

| pack | judge | reviewer | key |
|---|---|---|---|
| `pack:judge/anthropic` ([anthropic.yaml](anthropic.yaml)) | Claude Haiku 5.5, no thinking | Claude Sonnet 5.5, low effort | `ANTHROPIC_API_KEY` |
| `pack:judge/openrouter` ([openrouter.yaml](openrouter.yaml)) | DeepSeek V4 Flash, no thinking, temperature 0.7 | DeepSeek V4 Flash, low effort | `OPENROUTER_API_KEY` |

What each caught, over the corpus
[tangent-eval](https://github.com/EthanBlackburn/tangent-eval) builds:
59,342 records of CloudTrail, Okta, GitHub, Google Workspace and CI logs
with 71 attacks in them, of which a model reads 6,832, and 5,304 of those
are ordinary work.

| pair | attacks caught, of 71 | ordinary records flagged, of 5,304: by the judge, then after review | runs |
|---|---|---|---|
| Claude Haiku 5.5, Claude Sonnet 5.5 | 70 | 462, then 40 | one, on an earlier build |
| DeepSeek V4 Flash, both | 71 and 71 | 222 then 13, 220 then 10 | two, 2026-11-16, on hosts serving it at 4-bit; the pack names no host |

36 of the 71 attacks are cases the brief was written against. The corpus is
one made-up company: it says nothing of how much either flags on your logs.

Another pair is [reviewed.yaml](reviewed.yaml) (`pack:judge/reviewed`), the
same with no model named, and your config's `models.judge` and
`models.reviewer`.

## Changing the judge's chain

A node's `inputs` in your config take the place of the pack's, so a stage
can be taken out of the judge's chain or put into it without copying
`ingest.yaml`. `inference: { judge: { inputs: [my_filter] } }` puts a plugin
of your own in front of the judge, where `my_filter` takes
`baseline_renderer`; a judge without `baseline_renderer` is the judge with
other inputs. The list is replaced whole, so it names every node the judge
is to take. Where a pack's records go is your config's to say as well: the
nodes that take them name the pack's plugin in their `inputs`.

## What include cannot do

- **Keep a batch's order.** A source routed to several packs hands each its own
  records in turn, and several workers hand an actor's records to its group as
  they finish, so a group holds them in the order they arrived, not by
  `ts`.
