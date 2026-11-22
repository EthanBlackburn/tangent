# Try it

`tangent init` asks what you want to watch and which models judge it, and writes the whole pipeline to `tangent.yaml`.

1. Install tangent:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/EthanBlackburn/tangent/releases/latest/download/tangent-cli-installer.sh | sh
```

2. Write the config, in an empty directory:

```bash
tangent init
```

It asks two questions. The first is what to watch, one or more of:

| source | reads | it needs |
|---|---|---|
| `cloudtrail` | AWS: CloudTrail | an AWS profile that can read CloudTrail (`cloudtrail:LookupEvents`): `$AWS_PROFILE`, or `default` |
| `github` | GitHub: an organization's audit log | `GITHUB_ORG`, and `GITHUB_TOKEN` with `read:audit_log` |
| `okta` | Okta: the System Log | `OKTA_ORG_URL`, `OKTA_API_TOKEN` |
| `google_workspace` | Google Workspace: login, token, Drive and admin activity | `GOOGLE_APPLICATION_CREDENTIALS`, a service account's key file with domain-wide delegation, and `GOOGLE_ADMIN_EMAIL`, the admin it acts as |
| `supabase` | Supabase: a project's Auth log | `SUPABASE_PROJECT_REF`, `SUPABASE_ACCESS_TOKEN` |

The second is who serves the models. Each provider brings its pair: one judges every record and flags freely, and the other reviews each actor's alerts, with the records to query, and clears what turns out to be ordinary work. Each pair is written with the settings it was measured with, over the logs [tangent-eval](https://github.com/EthanBlackburn/tangent-eval) builds: 71 attacks, and 5,304 ordinary records a model reads.

| provider | judge, then reviewer | attacks caught, of 71 | ordinary records flagged after review, of 5,304 | it needs |
|---|---|---|---|---|
| `anthropic` | Claude Haiku 5.5, Claude Sonnet 5.5, through Anthropic's API | 70 (one run) | 40 | `ANTHROPIC_API_KEY` |
| `bedrock` | the same pair on Amazon Bedrock | | | an AWS profile with Bedrock access to both models in every US region: the models are called in us-west-2, and their `us.` profiles may serve a call from another |
| `openrouter` | DeepSeek V4 Flash, open weights, as both, through OpenRouter | 71 (two runs) | 10 to 13 | `OPENROUTER_API_KEY` |
| `openai` | GPT-6 Luna, GPT-6.1 Terra, through OpenAI's API | 71 (one run) | 20 | `OPENAI_API_KEY` |
| `local` | a model on this machine as both: a server you run at `http://localhost:8080/v1` (llama-server, mlx_lm.server, Ollama, vLLM) | not measured | | the server running; nothing leaves the machine |

The corpus is one made-up company, and 36 of its attacks are cases the judge's brief was written against: it says nothing of how much a pair flags on your logs.

At a terminal the two questions are menus. Away from one, for a script or an agent, init prints them with the names above and reads the answers from stdin, a line each:

```bash
printf 'cloudtrail,github\nanthropic\n' | tangent init
```

Run with nothing on stdin, it prints the questions and writes nothing.

Init then fetches the plugins the config names, checks each against the attestation of its build, and writes four files:

| | |
|---|---|
| `tangent.yaml` | the pipeline: every source, plugin, model and sink with its settings, each naming the nodes it reads from as `inputs` |
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
