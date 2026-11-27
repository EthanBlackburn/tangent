# Try it

`tangent init cloud` writes the whole pipeline for your cloud and SaaS audit logs to `tangent.yaml`: what you watch, and the models that judge it.

To watch without a config to keep, [`tangent watch cloud`](#tangent-watch-cloud-both-steps-in-one) does steps 2 and 3 in one command.

1. Install tangent:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/EthanBlackburn/tangent/releases/latest/download/tangent-cli-installer.sh | sh
```

2. Write the config, in an empty directory:

```bash
tangent init cloud --sources cloudtrail,github --provider anthropic
```

`--sources` is what to watch, one or more of:

| `--sources` | reads | it needs |
|---|---|---|
| `cloudtrail` | AWS: CloudTrail | an AWS profile that can read CloudTrail (`cloudtrail:LookupEvents`): `$AWS_PROFILE`, or `default` |
| `github` | GitHub: an organization's audit log | `GITHUB_ORG`, and `GITHUB_TOKEN` with `read:audit_log` |
| `okta` | Okta: the System Log | `OKTA_ORG_URL`, `OKTA_API_TOKEN` |
| `google_workspace` | Google Workspace: login, token, Drive and admin activity | `GOOGLE_APPLICATION_CREDENTIALS`, a service account's key file with domain-wide delegation, and `GOOGLE_ADMIN_EMAIL`, the admin it acts as |
| `supabase` | Supabase: a project's Auth log | `SUPABASE_PROJECT_REF`, `SUPABASE_ACCESS_TOKEN` |

Without it, init writes the pipeline with no source yet.

Two models read the records: one judges every record and flags freely, and the other reviews each actor's alerts, with the records to query, and clears what turns out to be ordinary work. You say who serves them, since every record is sent there to be judged: `--provider`, or `--local` for a model on this machine. Init picks neither for you. With no flag it writes nothing, and lists the command for each provider with whether its key is in your environment already:

```
$ tangent init cloud --sources okta
Error: say who judges your records. A hosted provider is sent every one:

  tangent init cloud --sources okta --provider openai       (OPENAI_API_KEY is set)
  tangent init cloud --sources okta --provider anthropic    (needs ANTHROPIC_API_KEY)
  tangent init cloud --sources okta --provider bedrock      (AWS_PROFILE is not set: your AWS profile `default`)
  tangent init cloud --sources okta --provider openrouter   (needs OPENROUTER_API_KEY)
  tangent init cloud --sources okta --local                 (Inkling 2 Mini on this Mac: no record leaves it)
```

`--provider` alone is the pair measured with that provider, in the table below. `--model` with it names other models, each by the exact name the provider takes. One name judges and reviews, and two with a comma are the judge's, then the reviewer's:

```bash
tangent init cloud --sources okta --provider openrouter
tangent init cloud --sources okta --provider openai --model gpt-6-luna,gpt-6.1-terra
```

Each provider's settings were measured with the models below, over the logs [tangent-eval](https://github.com/EthanBlackburn/tangent-eval) builds: 71 attacks, and 5,304 ordinary records a model reads.

| `--provider` | its pair: judge, then reviewer, and their names for `--model` | attacks caught, of 71 | ordinary records flagged after review, of 5,304 | it needs |
|---|---|---|---|---|
| `anthropic` | Claude Haiku 5.5, Claude Sonnet 5.5, through Anthropic's API: `claude-haiku-5-5,claude-sonnet-5-5` | 70 (one run) | 40 | `ANTHROPIC_API_KEY` |
| `bedrock` | the same two on Amazon Bedrock: `us.anthropic.claude-haiku-5-5,us.anthropic.claude-sonnet-5-5` | | | an AWS profile with Bedrock access to both models in every US region: the models are called in us-west-2, and their `us.` profiles may serve a call from another |
| `openrouter` | DeepSeek V4 Flash, open weights, as both, through OpenRouter: `deepseek/deepseek-v4-flash-0731` | 71 (two runs) | 10 to 13 | `OPENROUTER_API_KEY` |
| `openai` | GPT-6 Luna, GPT-6.1 Terra, through OpenAI's API: `gpt-6-luna,gpt-6.1-terra` | 71 (one run) | 20 | `OPENAI_API_KEY` |

`--local` is a model on this machine, and no record leaves it:

```bash
tangent init cloud --sources okta --local                         # Inkling 2 Mini, on a server tangent starts
tangent init cloud --sources okta --local --model glm-4.7-flash   # a model server of your own
```

| `--local` | the model | measured | it needs |
|---|---|---|---|
| alone | Inkling 2 Mini, open weights, judges and reviews, on Ollama. `tangent watch` starts the server, waits until it answers and stops it after | not on the corpus above | an Apple Silicon Mac with 32 GB of memory or more (on another machine `--local` stops and says so, before anything is downloaded). An Ollama of tangent's own and the model (20 GB) are downloaded into tangent's cache, each checked, apart from any Ollama of yours: init offers to, and `tangent model fetch` does it later |
| with `--model` | the model a server you run gives at `http://localhost:8080/v1` (llama-server, mlx_lm.server, Ollama, vLLM), by the name it gives it | not measured | the server running before tangent |

The corpus is one made-up company, and 36 of its attacks are cases the judge's brief was written against: it says nothing of how much a model flags on your logs.

Init writes over nothing, so the flags are for a new file. [Editing tangent.yaml by hand](config.md) is how to change one already written: to add a source, or change who serves the models.

Init then fetches the plugins the config names, checks each against the attestation of its build, and writes four files:

| | |
|---|---|
| `tangent.yaml` | the pipeline: every source, plugin, model and sink with its settings, each node naming the nodes it reads from as `inputs` and each model's node the model it asks |
| `judge.md`, `judge.schema.json` | what the judge is told, and the shape its answer is held to |
| `review.md` | what the reviewer is told |

Nothing else is kept anywhere: what the files say is what runs, and they are yours to edit. Init writes over nothing, and when a plugin cannot be fetched or checked it writes nothing.

3. Run it. Init prints the command for what you chose:

```bash
tangent replay --config tangent.yaml --from 1d   # the last day of CloudTrail
tangent watch --config tangent.yaml                # the other sources, from an hour back and as it happens
```

Replay reads a past range of CloudTrail from the account's Event history, up to 90 days back, and no other source. `tangent watch` reads the others as they happen, and CloudTrail too once `queue_url` in tangent.yaml names the SQS queue your trail's bucket notifies.

The models' calls are billed to your model account: replay prints about how many records the range holds before it judges any, and Ctrl-C stops it. The reference manual's [Volume and cost](reference.md#volume-and-cost) prices a day.

What the judge flagged is in alerts.ndjson and every verdict in verdicts.ndjson. Each alert is in reviews.ndjson too, with `review`: a verdict (`malicious`, `benign` or `unresolved`), a finding and what to check first; those are the ones to read. Tangent warns that four enrichment files are missing and runs without them; tangent.yaml says where they come from.

## `tangent watch cloud`: both steps in one

```bash
tangent watch cloud --sources okta,github --provider anthropic
```

It takes init's flags, and runs the pipeline init would write for them, leaving no file where you are. The config goes to tangent's own directory, `~/.local/share/tangent/cloud` (under `$XDG_DATA_HOME` when that is set), written again at each start, and tangent runs there: the alerts, their reviews, the lake and each actor's history are kept there too, and the next start goes on from them. It prints where they are.

While it runs, the terminal shows what it finds: each alert as the judge marks it (`#1`, `#2`, ... with a short summary while the reviewer works on it), an actor's alerts that wait for one review as one line and one number, with their count, each settled review (`cleared`, `MALICIOUS`, `ALERT`, or `REVIEW FAILED` tied back to `#1`, `#2`, ...), and each minute a quiet `checked` count with how many alerts are still in review. Runtime logs go to `watch.log` in the pipeline's directory (only errors reach stderr; set `RUST_LOG=info` for verbose terminal logs). A model wrote the alert text after reading whatever an attacker put in a record, so control characters are taken out of it before it is printed.

On a Mac, a review that upholds its alert is a notification too: `malicious` with a sound, `unresolved` without one, and a click on it shows the finding and what to check. A Mac's review also asks whether the session was your doing, with three buttons, and keeps the answer in `feedback.ndjson` beside the reviews. A review that clears its alert is not a notification, and neither is the judge's flag before its review. macOS asks once whether Tangent may show notifications, and they come from tangent's signed app, which `watch` fetches once per version. `--no-notify` shows none, and over ssh there are none.

```
#1  03:09Z  flagged  okta  ana@acme.example  a sign-in from a Tor exit  (reviewing)

#1  MALICIOUS  ana@acme.example (3 alerts)
    ...
    check: ...
checked 41 activities · 1 flagged
```

It starts only with what it needs. A variable from the table above that is not set stops it, with the list, where `tangent watch --config` would leave the source idle. With `--local` it downloads the model first, after asking. One `watch cloud` runs at a time.

It reads each source as it happens, from an hour back. CloudTrail is among them only when `CLOUDTRAIL_QUEUE_URL` holds its trail's queue; its last day is step 3's replay, on a config of your own.

To change more than the flags do, `tangent init cloud` with the same flags writes the same pipeline for you to edit.

## This Mac: `tangent watch mac`

```bash
tangent watch mac
```

It watches the Mac it runs on: what each program runs, opens and connects to, and what you ask Claude Code, a session (a terminal tab, an app, an agent) at a time. There is nothing to choose but who judges:

| | judges and reviews | where your records go | it needs |
|---|---|---|---|
| alone | Inkling 2 Mini, on a server tangent starts | nowhere: the model runs on this Mac | Apple Silicon with 32 GB of memory or more; the model (20 GB) is downloaded first, after asking. On another Mac tangent stops before it downloads anything and lists the command for each provider, with whether its key is in your environment already: it does not send your records to a hosted model unasked |
| `--provider anthropic` | Claude Haiku 5.5 judges, Claude Sonnet 5.5 reviews, through Anthropic's API | each session's summary is sent there, with its command lines, its paths and your prompts; a review sends the records it queries and the files it reads | `ANTHROPIC_API_KEY` |
| `--provider bedrock` | the same two on Amazon Bedrock | the same, to Bedrock | an AWS profile with Bedrock access to both models in the US regions (`AWS_PROFILE`, or `default`) |
| `--provider openai` | GPT-6 Luna judges, GPT-6.1 Terra reviews, through OpenAI's API. Not measured on the recorded Mac attacks | the same, to OpenAI | `OPENAI_API_KEY` |
| `--provider openrouter` | DeepSeek V4 Flash, open weights, judges and reviews, through OpenRouter. Not measured on the recorded Mac attacks | the same, to OpenRouter | `OPENROUTER_API_KEY` |

Inkling's settings here are the ones measured on cloud logs, with room for the longer answer a session takes. Its results on the recorded Mac attacks in [tangent-eval](https://github.com/EthanBlackburn/tangent-eval/tree/main/macos) are not published yet. Claude Haiku 5.5 with Claude Sonnet 5.5 is the pair measured there. OpenAI's and OpenRouter's models are each provider's cloud pair, asked with the room a session's verdict takes, and have not been run on those attacks.

Two things are yours to do:

- **Your password,** once, when it starts: sudo runs the sensor and macOS's tcpdump as root.
- **Full Disk Access** for the terminal it runs in (System Settings, Privacy & Security), and a restart of the terminal after the grant.

The sensor, which reads what each program does, is the release's: tangent downloads it once per version, and before each start checks that it is the one tangent's team signed and Apple notarized, since it runs as root.

It keeps its pipeline in `~/.local/share/tangent/mac`, as `watch cloud` keeps its own, and says each alert as the judge marks a session `look` or `flag`, and each review as soon as the reviewer has settled it, a minute or so after its alert.

### See it catch something: `tangent simulate`

```bash
tangent simulate              # in another terminal, while `tangent watch mac` runs: lists the attacks and asks which
tangent simulate credentials  # or name one
tangent simulate agent
```

It runs an attack for real, of the kind a poisoned package carries, and lists each step as it does. Both start with a script piped from curl into bash:

- **`credentials`** asks the Mac who it is, finds a project's `.env` files, archives and encrypts them, uploads them and removes its traces.
- **`agent`** takes over a project's AI coding agent: it gives it a hook that sends every tool call to its server, lets it run curl unasked, points its traffic at that server, adds an MCP server of its own, and writes an instruction to fetch and run a script into the project's `CLAUDE.md`.

It is safe to run on the Mac you work on. The project is a directory made for the run, its `.env` files hold made-up keys and its agent files are its own, and the server it downloads from and reports to is the command itself, which keeps nothing: no file of yours is opened or changed, nothing leaves the Mac, and nothing is left behind.

That server listens on your Mac's own address on its network and not on 127.0.0.1, since an upload to 127.0.0.1 is one that went nowhere. What is sent still goes from your Mac to your Mac, but for the few seconds the attack takes another device on that network could reach the server, to fetch the script or to send it something it throws away. So the command says so and asks before it runs, and runs only from a terminal.

`tangent watch mac` then says what it makes of it, in its own terminal: the session is flagged about half a minute later (up to five minutes in a busy terminal) and reviewed in the half minute or so after that. With the hosted pair the judge flagged both and the reviewer then called them benign, rightly: it worked out from the records that the files were made by the command that took or changed them and went no further than this Mac. That is the two passes doing their work, and the alert is the thing to look for.

`tangent init mac` writes the same pipeline where you are, to edit and to run with `tangent watch --config tangent.yaml`: tangent.yaml, the two briefs, and profiles.yaml, which says what each known program is expected to read, start and connect to. [packs/macos](../packs/macos) describes each part.
