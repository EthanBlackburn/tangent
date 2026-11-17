# inference-openai

A model on OpenAI's API reads every record; a plugin keeps what it flagged.

Same pipeline as [../inference-local](../inference-local): the default backend
is OpenAI's chat completions API, here at OpenAI's own address with your key.
The filter is the same [flagged](../inference-local/flagged/src/lib.rs)
plugin, referenced by path.

```yaml
inference:
  judge:
    url: https://api.openai.com/v1
    api_key: "${OPENAI_API_KEY}"
    model: gpt-6-luna
    prompt_file: judge.md
    batch_bytes: 4000
    max_tokens: 300
    concurrency: 8
    timeout_ms: 60000
    extra:
      reasoning_effort: low
plugins:
  flagged:
    module_type: rust
    path: ../inference-local/flagged
    prebuilt: { repo: EthanBlackburn/tangent, workflow: .github/workflows/attest-packs.yml }
```

## The key

```bash
export OPENAI_API_KEY=...    # from platform.openai.com
```

`reasoning_effort: low` keeps the model's thinking short: a verdict of a line
does not need more, and thinking is paid for out of `max_tokens`.

A request that fails is retried twice, then each of its records goes on with
`{"error": ...}` as `judge` and tangent logs `inference failed`; the plugin
keeps those, so a wrong key shows up in `flagged.ndjson` as every record.

## Run

In this directory:

```bash
tangent run --config tangent.yaml
```

Nothing is compiled: `tangent run` fetches the `flagged` plugin from the tangent
release of its own version, once, and `gh attestation verify` checks that this
repository's release workflow built it ([Prebuilt plugins](/README.md#prebuilt-plugins));
it needs `gh`, not a login. To build it from [../inference-local/flagged](../inference-local/flagged)
instead, as after changing it: `tangent plugin compile --config tangent.yaml`,
which needs the Rust WASM toolchain.

In another shell:

```bash
nc -w 1 localhost 9000 < events.ndjson
cat flagged.ndjson
```

The events and the prompt are inference-local's; what to expect is in
[its README](../inference-local/README.md#run). The file sink appends:
`rm flagged.ndjson` before running again.
