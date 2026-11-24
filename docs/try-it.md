# Try it

`tangent init cloud` writes the whole pipeline for your cloud and SaaS audit logs to `tangent.yaml`: what you watch, and the models that judge it.

To watch without a config to keep, [`tangent watch cloud`](#tangent-watch-cloud-both-steps-in-one) does steps 2 and 3 in one command.

1. Install tangent:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/EthanBlackburn/tangent/releases/latest/download/tangent-cli-installer.sh | sh
```

2. Write the config, in an empty directory:

```bash
tangent init cloud --sources cloudtrail,github
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

Two models read the records: one judges every record and flags freely, and the other reviews each actor's alerts, with the records to query, and clears what turns out to be ordinary work. Init writes models served for you: Claude Haiku 5.5 as the judge and Claude Sonnet 5.5 as the reviewer, through Anthropic's API, with `ANTHROPIC_API_KEY`. Every record is sent there to be judged, and the file and init's last lines say so.

`--provider` and `--model`, given together, name others: who serves the models, and each model by the exact name the provider takes. One name judges and reviews, and two with a comma are the judge's, then the reviewer's:

```bash
tangent init cloud --sources okta --provider openrouter --model deepseek/deepseek-v4-flash-0731
tangent init cloud --sources okta --provider openai --model gpt-6-luna,gpt-6.1-terra
```

Each provider's settings were measured with the models below, over the logs [tangent-eval](https://github.com/EthanBlackburn/tangent-eval) builds: 71 attacks, and 5,304 ordinary records a model reads.

| `--provider` | measured with: judge, then reviewer, and their names for `--model` | attacks caught, of 71 | ordinary records flagged after review, of 5,304 | it needs |
|---|---|---|---|---|
| `anthropic` | Claude Haiku 5.5, Claude Sonnet 5.5, through Anthropic's API: `claude-haiku-5-5,claude-sonnet-5-5`, and what init writes without the two flags | 70 (one run) | 40 | `ANTHROPIC_API_KEY` |
| `bedrock` | the same two on Amazon Bedrock: `us.anthropic.claude-haiku-5-5,us.anthropic.claude-sonnet-5-5` | | | an AWS profile with Bedrock access to both models in every US region: the models are called in us-west-2, and their `us.` profiles may serve a call from another |
| `openrouter` | DeepSeek V4 Flash, open weights, as both, through OpenRouter: `deepseek/deepseek-v4-flash-0731` | 71 (two runs) | 10 to 13 | `OPENROUTER_API_KEY` |
| `openai` | GPT-6 Luna, GPT-6.1 Terra, through OpenAI's API: `gpt-6-luna,gpt-6.1-terra` | 71 (one run) | 20 | `OPENAI_API_KEY` |

`--local` is a model on this machine in place of a hosted one, and no record leaves it:

```bash
tangent init cloud --sources okta --local                         # Inkling 2 Mini, on a server tangent starts
tangent init cloud --sources okta --local --model glm-4.7-flash   # a model server of your own
```

| `--local` | the model | measured | it needs |
|---|---|---|---|
| alone | Inkling 2 Mini, open weights, judges and reviews, on MTPLX. `tangent run` starts the server, waits until it answers and stops it after | not on the corpus above | an Apple Silicon Mac with 32 GB of memory or more (init warns under it). MTPLX and the model (17 GB) are downloaded into tangent's cache, each file checked: init offers to, and `tangent model fetch` does it later |
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
tangent run --config tangent.yaml                # the other sources, from an hour back and as it happens
```

Replay reads a past range of CloudTrail from the account's Event history, up to 90 days back, and no other source. `tangent run` reads the others as they happen, and CloudTrail too once `queue_url` in tangent.yaml names the SQS queue your trail's bucket notifies.

The models' calls are billed to your model account: replay prints about how many records the range holds before it judges any, and Ctrl-C stops it. The README's [Volume and cost](../README.md#volume-and-cost) prices a day.

What the judge flagged is in alerts.ndjson and every verdict in verdicts.ndjson. Each alert is in reviews.ndjson too, with `review`: a verdict (`malicious`, `benign` or `unresolved`), a finding and what to check first; those are the ones to read. Tangent warns that four enrichment files are missing and runs without them; tangent.yaml says where they come from.

## `tangent watch cloud`: both steps in one

```bash
tangent watch cloud --sources okta,github
```

It takes init's flags, and runs the pipeline init would write for them, leaving no file where you are. The config goes to tangent's own directory, `~/.local/share/tangent/cloud` (under `$XDG_DATA_HOME` when that is set), written again at each start, and tangent runs there: the alerts, their reviews, the lake and each actor's history are kept there too, and the next start goes on from them. It prints where they are.

While it runs, the terminal shows what it finds and little else: each alert as the judge flags it (when, from which log, who, and why), each review as it is written (the verdict, the finding, what to check first), and every few minutes how many records were judged. The runtime's own lines are kept to its warnings; `RUST_LOG=info` brings the rest back. A model wrote that text after reading whatever an attacker put in a record, so control characters are taken out of it before it is printed.

```
flagged   2026-11-24 03:09Z  okta  ana@acme.example
          a sign-in from a Tor exit, with no second factor
reviewed  ana@acme.example, 3 alerts: malicious
          ...
          check: ...
```

It starts only with what it needs. A variable from the table above that is not set stops it, with the list, where `tangent run` would leave the source idle. With `--local` it downloads the model first, after asking. One `watch cloud` runs at a time.

It reads what `tangent run` reads: each source as it happens, from an hour back. CloudTrail is among them only when `CLOUDTRAIL_QUEUE_URL` holds its trail's queue; its last day is step 3's replay, on a config of your own.

To change more than the flags do, `tangent init cloud` with the same flags writes the same pipeline for you to edit.
