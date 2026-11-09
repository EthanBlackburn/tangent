# supabase

One Supabase project's Auth log, watched: every sign-in, sign-up, recovery
and refused request read from the project, described (who, what, from which
network), kept in a lake, and judged a user at a time by a model. One
config, one process, two variables.

```bash
export SUPABASE_PROJECT_REF=abcdefghijklmnopqrst   # Project Settings → General
export SUPABASE_ACCESS_TOKEN=sbp_...               # Account → Access Tokens; it reads the project's logs
make run
```

`make run` fetches the address data once (GeoLite2, cloud ranges, Tor
exits) and the plugins prebuilt, then reads the last hour of the log and
keeps reading, a poll a minute. `SUPABASE_SINCE=1d make run` starts a day
back.

| it writes | what |
|---|---|
| `lake/logs/<year>/<month>/<day>/<hour>/` | every finished record, as Parquet |
| `verdicts.ndjson` | the judge's verdict on each record |
| `alerts.ndjson` | the records it flagged |
| `state.sqlite` | where the source stopped, so a restart resumes |

The judge is any OpenAI-compatible model, a local one on `:8080` by default:

```bash
JUDGE_URL=https://api.openai.com/v1 JUDGE_MODEL=gpt-5.1 JUDGE_API_KEY=$OPENAI_API_KEY make run
```

Without a project, `make test` runs the pack's made-up rows through the
plugin and shows nothing is broken: no token, no model.

From a tangent built from this checkout, where no release has the plugins
yet, build them here: `make run PLUGINS=compile TANGENT=../../target/debug/tangent`.

[profile/profile.yaml](profile/profile.yaml) is two lines: your name, and
that this log is yours. [packs/supabase](/packs/supabase) says what a record
holds and what was dropped; [packs/judge](/packs/judge) has the judge's
settings and Slack.
