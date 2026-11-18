# inference-openrouter

A model on OpenRouter reads every record; a plugin keeps what it flagged.

Same pipeline as [../inference-local](../inference-local). OpenRouter speaks
the OpenAI chat completions API, so this is the default backend at
OpenRouter's address, with your key, and any model it lists: here DeepSeek V4
Flash, whose weights are open. The filter is the same
[flagged](../inference-local/flagged/src/lib.rs) plugin, referenced by path.

```yaml
inference:
  judge:
    url: https://openrouter.ai/api/v1
    api_key: "${OPENROUTER_API_KEY}"
    model: deepseek/deepseek-v4-flash-0731
    prompt_file: judge.md
    batch_bytes: 4000
    max_tokens: 300
    concurrency: 8
    timeout_ms: 60000
    extra:
      reasoning: { enabled: false }
plugins:
  flagged:
    module_type: rust
    path: ../inference-local/flagged
    prebuilt: { repo: EthanBlackburn/tangent, workflow: .github/workflows/attest-packs.yml }
```

## The key, and what `extra` is for

```bash
export OPENROUTER_API_KEY=...    # from openrouter.ai/keys
```

Without it tangent stops before it starts, saying `api_key` is empty.
`extra` is merged into the request as it is, so it carries what is
OpenRouter's own: `reasoning: { enabled: false }` has the model answer without
thinking first, and a `provider` object picks who serves it, as in
`provider: { require_parameters: true }` for only the hosts that honour every
parameter sent, or `provider: { order: [deepinfra] }` for one by name. Your
records go to whichever host serves the request.

A request that fails is retried twice, then each of its records goes on with
`{"error": ...}` as `judge` and tangent logs `inference failed`; the plugin
keeps those, so a wrong key shows up in `flagged.ndjson` as every record.

## Run

In this directory:

```bash
tangent run --config tangent.yaml
```

Nothing is compiled: `tangent run` fetches the `flagged` plugin from the tangent
release of its own version, once, and checks that this repository's release
workflow built it ([Prebuilt plugins](/README.md#prebuilt-plugins)). To build it from [../inference-local/flagged](../inference-local/flagged)
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
