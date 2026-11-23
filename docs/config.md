# Editing tangent.yaml by hand

`tangent init` writes the whole pipeline to tangent.yaml, and asks nothing. Its flags say what goes in:

```bash
tangent init                                # the pipeline, with no source yet
tangent init --sources cloudtrail,github    # with those two watched
tangent init --sources okta --provider openrouter --model deepseek/deepseek-v4-flash-0731
tangent init --sources okta --provider openai --model gpt-6-luna,gpt-6.1-terra
```

| flag | names | without it |
|---|---|---|
| `--sources` | what to watch, one or more of `cloudtrail`, `github`, `okta`, `google_workspace`, `supabase` | the pipeline has no source yet |
| `--provider` and `--model`, together | who serves the models (`anthropic`, `bedrock`, `openrouter`, `openai`, `local`), and each model by the exact name the provider takes: one name judges and reviews, and two with a comma are the judge's, then the reviewer's | Claude Haiku 5.5 judges and Claude Sonnet 5.5 reviews, through Anthropic's API |

Init writes over nothing, so the flags are for a new file. This page is how to change one already written: to add or take out a source, and to change who serves the models.

Every block below is what init writes, with its indentation: paste it as it is. To check an edit, `tangent config --config tangent.yaml` loads the file and prints it, or says what is wrong with it. A plugin the file names is fetched, and its build's attestation checked, the first time `tangent replay` or `tangent run` reads the file.

## Watch another source

A source is in four places in the file:

1. Its node, under `sources:`.
2. Its plugin, under `plugins:`, beside the other sources' plugins.
3. Its plugin's name in three `inputs` lists: `baseline_builder`'s and `baseline_renderer`'s under `plugins:`, and `lake`'s under `sinks:`. With CloudTrail and GitHub watched, each is `inputs: [cloudtrail, github]`.
4. Its rows, under `inference.judge.encoding.sources:`. A row is named for the `source` value its records carry, which is not always the plugin's name.

To stop watching a source, take it out of the same four places. A file written with no source has `{}` where its nodes and rows go, and `(none yet)` where its plugin goes: put the blocks in their place. The order of the nodes does not matter.

The comment at the top of the file says what it watches, who serves the models and how to run it. Nothing reads it: bring it up to date for whoever opens the file next.

`tangent replay --config tangent.yaml --from 1d` reads CloudTrail's past and no other source. `tangent run --config tangent.yaml` reads the others from an hour back and as it happens, and CloudTrail too once `queue_url` names the SQS queue the trail's bucket notifies.

### AWS: CloudTrail

It reads from the environment:

- `AWS_PROFILE`: the AWS profile that reads CloudTrail; `default` when unset

Its node, under `sources:`:

```yaml
  aws_audit:                     # AWS: CloudTrail
    type: cloudtrail
    profile: "${AWS_PROFILE:-default}"   # the AWS profile (~/.aws/config) that reads CloudTrail; EDIT to name another
    region: us-east-1            # for looking up its credentials; replay reads every region
    queue_url: ${CLOUDTRAIL_QUEUE_URL}   # for `tangent run`: the SQS queue the trail's bucket notifies; replay needs none
```

Its plugin, under `plugins:`:

```yaml
  cloudtrail:
    inputs: [aws_audit]
    module_type: rust
    prebuilt: { repo: EthanBlackburn/tangent, workflow: .github/workflows/attest-packs.yml }
```

Its name in the three `inputs` lists: `cloudtrail`.

Its rows, under `inference.judge.encoding.sources:`:

```yaml
        cloudtrail:
          principal: [_norm.actor, userIdentity.arn]
          time: [eventTime, ts]
          keep: [eventName, requestParameters, responseElements, errorCode, errorMessage, userIdentity.mfaAuthenticated, additionalEventData.MFAUsed, _facts.root, _facts.world_open]
```

### GitHub: an organization's audit log

It reads from the environment:

- `GITHUB_ORG`: the organization's login
- `GITHUB_TOKEN`: a token with read:audit_log

Its node, under `sources:`:

```yaml
  github_audit:                  # GitHub: the organization's audit log
    type: github_audit
    org: ${GITHUB_ORG}           # the organization's login
    token: ${GITHUB_TOKEN}       # a token with read:audit_log
```

Its plugin, under `plugins:`:

```yaml
  github:
    inputs: [github_audit]
    module_type: rust
    prebuilt: { repo: EthanBlackburn/tangent, workflow: .github/workflows/attest-packs.yml }
```

Its name in the three `inputs` lists: `github`.

Its rows, under `inference.judge.encoding.sources:`:

```yaml
        github_audit:
          principal: [_norm.actor, actor]
          time: ["@timestamp", created_at, ts]
          keep: [action, repo, visibility, permission, programmatic_access_type, token_scopes, operation_type]
```

### Okta: the System Log

It reads from the environment:

- `OKTA_ORG_URL`: the org's address, https://acme.okta.com
- `OKTA_API_TOKEN`: an API token

Its node, under `sources:`:

```yaml
  okta_audit:                    # Okta: the System Log
    type: okta
    org_url: ${OKTA_ORG_URL}     # https://acme.okta.com
    token: ${OKTA_API_TOKEN}
```

Its plugin, under `plugins:`:

```yaml
  okta:
    inputs: [okta_audit]
    module_type: rust
    prebuilt: { repo: EthanBlackburn/tangent, workflow: .github/workflows/attest-packs.yml }
```

Its name in the three `inputs` lists: `okta`.

Its rows, under `inference.judge.encoding.sources:`:

```yaml
        okta:
          principal: [_norm.actor, actor.alternateId]
          time: [published, ts]
          keep: [eventType, outcome, target, authenticationContext.credentialType, securityContext.isProxy, debugData.threatSuspected]
```

### Google Workspace: login, token, Drive and admin activity

It reads from the environment:

- `GOOGLE_APPLICATION_CREDENTIALS`: a service account's key file, with domain-wide delegation
- `GOOGLE_ADMIN_EMAIL`: the admin the service account acts as

Its node, under `sources:`:

```yaml
  workspace_audit:               # Google Workspace: login, token, Drive and admin activity
    type: google_workspace
    credentials_file: ${GOOGLE_APPLICATION_CREDENTIALS}   # a service account's key file, with domain-wide delegation
    subject: ${GOOGLE_ADMIN_EMAIL}                         # the admin it acts as
```

Its plugin, under `plugins:`:

```yaml
  google_workspace:
    inputs: [workspace_audit]
    module_type: rust
    prebuilt: { repo: EthanBlackburn/tangent, workflow: .github/workflows/attest-packs.yml }
```

Its name in the three `inputs` lists: `google_workspace`.

Its rows, under `inference.judge.encoding.sources:`:

```yaml
        google_workspace:
          principal: [_norm.actor, actor.email]
          time: [id.time, ts]
          keep: [events]
```

### Supabase: a project's Auth log

It reads from the environment:

- `SUPABASE_PROJECT_REF`: the project's reference
- `SUPABASE_ACCESS_TOKEN`: an access token that can read its logs

Its node, under `sources:`:

```yaml
  supabase_auth:                 # Supabase: a project's Auth log
    type: supabase
    project_ref: ${SUPABASE_PROJECT_REF}   # Project Settings, General
    token: ${SUPABASE_ACCESS_TOKEN}        # Account, Access Tokens
```

Its plugin, under `plugins:`:

```yaml
  supabase:
    inputs: [supabase_auth]
    module_type: rust
    prebuilt: { repo: EthanBlackburn/tangent, workflow: .github/workflows/attest-packs.yml }
```

Its name in the three `inputs` lists: `supabase`.

Its rows, under `inference.judge.encoding.sources:`:

```yaml
        supabase:
          principal: [_norm.actor, auth_event.actor_username]
          time: [ts]
          keep: [log, auth_event.action, auth_event.traits.provider, auth_audit_event.action, path, status, error]
```

## Have other models judge and review

Two entries under `models:` say who serves the models, and two nodes under `inference:` say how each is asked: `judge` reads every record, and `reviewer` settles what the judge flagged. A provider's lines are in four places:

- Under `models:`, in `judge`, the lines above `timeout_ms: 90000`.
- Under `models:`, in `reviewer`, the lines above `timeout_ms: 120000`.
- Under `inference:`, in `judge`, the lines between `model: judge` and `prompt_file: judge.md`.
- Under `inference:`, in `reviewer`, the lines between `model: reviewer` and `prompt_file: review.md`.

Replace those lines with the blocks below, and leave the rest as it is. Each block has the model its provider was measured with: for another, change the `model` line under `models:`, which is all `--model` does: the judge's entry for its first name, the reviewer's for its second. A block is whole: a line the old one had and the new one has not, such as `url`, goes. judge.md, judge.schema.json and review.md, beside the file, are the same whoever serves the models.

[Try it](try-it.md) has what each pair caught and flagged in tangent's evals.

### Claude Haiku 5.5 judges, Claude Sonnet 5.5 reviews (Anthropic's API)

It reads from the environment:

- `ANTHROPIC_API_KEY`: a key from console.anthropic.com

The judge's model, under `models:`:

```yaml
    type: anthropic
    api_key: "${ANTHROPIC_API_KEY}"   # a key from console.anthropic.com
    model: claude-haiku-5-5
```

The reviewer's model, under `models:`:

```yaml
    type: anthropic
    api_key: "${ANTHROPIC_API_KEY}"
    model: claude-sonnet-5-5
```

The judge's lines, under `inference:`:

```yaml
    max_tokens: 400              # per record
    extra: { thinking: { type: disabled } }   # no thinking: the reply is the answer
```

The reviewer's lines, under `inference:`:

```yaml
    extra:
      thinking: { type: adaptive }   # it thinks before each query and its report, briefly
      output_config: { effort: low }
```

### Claude Haiku 5.5 judges, Claude Sonnet 5.5 reviews (Amazon Bedrock)

It reads from the environment:

- `AWS_PROFILE`: the AWS profile that calls Bedrock, with access to both models in the US regions; `default` when unset

The judge's model, under `models:`:

```yaml
    type: bedrock
    model: us.anthropic.claude-haiku-5-5
    aws: { profile: "${AWS_PROFILE:-default}", region: us-west-2 }   # a US region: Bedrock serves this model there
```

The reviewer's model, under `models:`:

```yaml
    type: bedrock
    model: us.anthropic.claude-sonnet-5-5
    aws: { profile: "${AWS_PROFILE:-default}", region: us-west-2 }
```

The judge's lines, under `inference:`:

```yaml
    max_tokens: 400              # per record
    extra: { thinking: { type: disabled } }   # no thinking: the reply is the answer
```

The reviewer's lines, under `inference:`:

```yaml
    extra:
      thinking: { type: adaptive }   # it thinks before each query and its report, briefly
      output_config: { effort: low }
```

### DeepSeek V4 Flash, open weights, judges and reviews (OpenRouter)

It reads from the environment:

- `OPENROUTER_API_KEY`: a key from openrouter.ai/keys

The judge's model, under `models:`:

```yaml
    type: openai                 # an OpenAI-compatible server
    url: https://openrouter.ai/api/v1
    api_key: "${OPENROUTER_API_KEY}"   # a key from openrouter.ai/keys
    model: deepseek/deepseek-v4-flash-0731
```

The reviewer's model, under `models:`:

```yaml
    type: openai                 # an OpenAI-compatible server
    url: https://openrouter.ai/api/v1
    api_key: "${OPENROUTER_API_KEY}"
    model: deepseek/deepseek-v4-flash-0731
```

The judge's lines, under `inference:`:

```yaml
    max_tokens: 200              # per record
    temperature: 0.7             # with top_p, the sampling it was measured with
    extra:
      top_p: 0.95
      reasoning: { enabled: false }            # no thinking: the reply is the answer
      provider: { require_parameters: true }   # only hosts that hold the reply to its schema
```

The reviewer's lines, under `inference:`:

```yaml
    extra:
      reasoning: { effort: low }   # it thinks before each query and its report, briefly
```

### GPT-6 Luna judges, GPT-6.1 Terra reviews (OpenAI's API)

It reads from the environment:

- `OPENAI_API_KEY`: a key from platform.openai.com

The judge's model, under `models:`:

```yaml
    type: responses              # OpenAI's Responses API
    api_key: "${OPENAI_API_KEY}"   # a key from platform.openai.com
    model: gpt-6-luna
```

The reviewer's model, under `models:`:

```yaml
    type: responses
    api_key: "${OPENAI_API_KEY}"
    model: gpt-6.1-terra
```

The judge's lines, under `inference:`:

```yaml
    max_tokens: 400              # per record, its thinking included
    extra:
      reasoning: { effort: low }   # little thinking: the reply is the answer
```

The reviewer's lines, under `inference:`:

```yaml
    extra:
      reasoning: { effort: low }   # it thinks before each query and its report, briefly
```

### A model on this machine judges and reviews (llama-server, mlx_lm.server, Ollama, vLLM)

Start the model's server before tangent, and set the two lines marked EDIT to the name the server gives its model. Nothing leaves the machine.

The judge's model, under `models:`:

```yaml
    type: openai                 # an OpenAI-compatible server
    url: http://localhost:8080/v1   # llama-server, mlx_lm.server or vLLM; Ollama is http://localhost:11434/v1
    model: glm-4.7-flash         # EDIT to the name your server gives its model
```

The reviewer's model, under `models:`:

```yaml
    type: openai                 # an OpenAI-compatible server
    url: http://localhost:8080/v1
    model: glm-4.7-flash         # EDIT, as the judge's
```

The judge's lines, under `inference:`:

```yaml
    max_tokens: 200              # per record
    temperature: 0.7
    extra:
      top_p: 0.95
      chat_template_kwargs: { enable_thinking: false }   # no thinking: the reply is the answer
```

The reviewer has no lines of its own under `inference:`: take out the ones that were there.
