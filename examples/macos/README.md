# macos

A Mac where AI coding agents run, read by
[packs/macos](/packs/macos) and judged by [packs/judge](/packs/judge), as
[cloud-infra](../cloud-infra) is for a company's cloud: each record goes to
the lake, and each session (a terminal tab, an app, an agent, with
everything it ran) is summed up five minutes at a time for the judge, which
writes what it flags to `alerts.ndjson`. One config, one process.

```bash
tangent plugin compile --config tangent.yaml
tangent run --config haiku.yaml &              # Claude Haiku on Bedrock, AWS_PROFILE set; or tangent.yaml, a local model
sudo eslogger exec fork exit open close create rename unlink btm_launch_item_add tcc_modify | nc -U es.sock
tail -f alerts.ndjson
```

`eslogger` needs root, and the terminal it runs in needs Full Disk Access
(System Settings, Privacy & Security), restarted after the grant.

- `tangent.yaml`: the judge pack, the macos pack's two plugins, the socket
  `nc` writes, the lake, and packs/macos's brief and answer schema in place
  of the judge's, the summaries sent as JSON lines; a local
  OpenAI-compatible model by default (`JUDGE_URL`, `JUDGE_MODEL`,
  packs/judge/README.md). The judge pack brings behavior-baseline's two
  plugins, which nothing routes to here: `tangent run` says so, and they
  never run.
- `haiku.yaml`: the same on Claude Haiku 5.5 through Bedrock,
  `us.anthropic.claude-haiku-5-5` (the cross-region profile; Converse refuses
  the bare model id on demand), thinking off. It includes the judge pack's
  `hosted.yaml` after `tangent.yaml`, which takes out the local model's
  sampling settings: Haiku 5.5 refuses them.

The pack runs the pipeline on one worker, which keeps a process's events in
order, so the model gets one request at a time: a few sessions' summaries,
48 KB at most. A session is held in memory until its five minutes close, and
a restart loses the open ones.

What is kept stays here: `lake/` every record as Parquet (delete old hours to
trim it), `state.sqlite` the process tree the plugin keeps, `verdicts.ndjson`
every session's verdict. The records hold command lines.
