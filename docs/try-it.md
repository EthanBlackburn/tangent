# Try it

Your AWS account's last day of CloudTrail, judged by Claude Haiku 5.5 with your Anthropic API key, or by another model you choose.

1. Install tangent, and gh (GitHub's CLI, 2.90 or later), which checks the plugins tangent fetches:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/EthanBlackburn/tangent/releases/latest/download/tangent-cli-installer.sh | sh
brew install gh    # or see https://cli.github.com
```

2. Write the config, and give the model's key:

```bash
tangent init
export ANTHROPIC_API_KEY=...    # a key from console.anthropic.com
```

It reads CloudTrail as `$AWS_PROFILE`, or your default AWS profile when that is unset. To use another, open tangent.yaml in any editor and set it on the line marked EDIT.

`tangent init --model` writes the config for another model:

| | the model | it needs |
|---|---|---|
| `anthropic` (the default) | Claude Haiku 5.5, Anthropic's API | `ANTHROPIC_API_KEY` |
| `bedrock` | Claude Haiku 5.5 on Amazon Bedrock | the same AWS profile, with Bedrock access to the model in every US region |
| `openrouter` | DeepSeek V4 Flash, open weights, or any model OpenRouter lists | `OPENROUTER_API_KEY` |
| `openai` | GPT-6 Luna, OpenAI's API | `OPENAI_API_KEY` |
| `local` | a local model: a server you run at `http://localhost:8080/v1` (llama-server, mlx_lm.server, Ollama, vLLM) | the server running; nothing leaves the machine |

3. Replay the last day:

```bash
tangent replay --config tangent.yaml --from 1d
```

The judge's calls are billed to your model account: replay prints about how many records the range holds before it judges any, and Ctrl-C stops it. The README's [Volume and cost](../README.md#volume-and-cost) prices a day.

What it flagged is in alerts.ndjson, every verdict in verdicts.ndjson. The first run fetches the packs' plugins for this version of tangent; gh checks each without a login, and if it asks for one, `gh auth login`. Replay warns that four enrichment files are missing and runs without them; tangent.yaml says where they come from. Your AWS identity needs cloudtrail:LookupEvents. With `--model bedrock` it also needs Bedrock access to Claude Haiku 5.5 in every US region: the judge calls us-west-2, and the model's `us.` profile may serve a call from another.
