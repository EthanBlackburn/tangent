# inference-anthropic

Claude through Anthropic's API reads every record; a plugin keeps what it flagged.

Same pipeline as [../inference-local](../inference-local), with the
`anthropic` backend: the `judge` node calls Anthropic's Messages API with your
key. The filter is the same [flagged](../inference-local/flagged/src/lib.rs)
plugin, referenced by path.

```yaml
inference:
  judge:
    backend: anthropic
    api_key: "${ANTHROPIC_API_KEY}"
    model: claude-haiku-5-5
    prompt_file: judge.md
    batch_bytes: 4000
    max_tokens: 300
    concurrency: 8
    timeout_ms: 60000
    extra:
      thinking: { type: disabled }
plugins:
  flagged:
    module_type: rust
    path: ../inference-local/flagged
```

## The key

```bash
export ANTHROPIC_API_KEY=...    # from console.anthropic.com
```

Without it tangent stops before it starts, naming the variable.
`thinking: { type: disabled }` has Claude Haiku 5.5 answer without thinking
first, which a verdict of a line does not need and `max_tokens` would
otherwise be spent on.

A request that fails is retried twice, then each of its records goes on with
`{"error": ...}` as `judge` and tangent logs `inference failed`; the plugin
keeps those, so a wrong key shows up in `flagged.ndjson` as every record.

## Run

In this directory:

```bash
tangent plugin compile --config tangent.yaml    # builds ../inference-local/flagged into plugins/
tangent run --config tangent.yaml
```

In another shell:

```bash
nc -w 1 localhost 9000 < events.ndjson
cat flagged.ndjson
```

The events and the prompt are inference-local's; what to expect is in
[its README](../inference-local/README.md#run). The file sink appends:
`rm flagged.ndjson` before running again.
