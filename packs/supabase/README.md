# supabase

A Supabase project's logs into finished records, by one plugin, `supabase`.
It takes the records whose `source` is `supabase`: the rows tangent's
`supabase` source reads from the Management API, or the same rows sent as
NDJSON. It knows the Auth server's logs by name (`auth_logs`, the source's
default, and `auth_audit_logs`): who signed in, signed up, recovered or
changed an account, from where, and the requests it refused. A row of any
other log passes with its attributes kept.

To see it run, [examples/supabase](/examples/supabase) is the whole pipeline
for one project: two variables and `make run`.

## What it writes

`_norm` ([the record](../README.md#the-record) has the contract):

| field | from (`log_attributes`) |
|---|---|
| `actor` | `auth_event.actor_username`, else `auth_audit_event.actor_username`, else `auth_event.traits.user_email`; a refused request names nobody |
| `org` | none of its own: your org when `supabase` is in the profile's `own_sources` |
| `kind` | `auth_event.action` (`login`, `user_signedup`, `token_refreshed`, ...), else `auth_audit_event.action`, else the request's `path` (`/token`) |
| `ip` | `remote_addr` |

`_facts` is what the profile and the tables say, with one thing of its own:
`principal` is `user`. The actor is one of your product's users, not one of
your people, so the profile's `members` are not asked who they are, and
`countries`, where your people are, is not held against them. Their address
is still described (`_facts.ip`), and a Tor exit or a VPN still gets its
note.

[behavior-baseline](../behavior-baseline) does not know `supabase` yet: its
records pass through unlearned, with no `_baseline`, so the judge reads each
user's records without their history.

## What it drops

Supabase stores a row's fields flat, `auth_event.action` beside `path`, every
value as text. The record has them by name instead, `auth_event: {action}`,
beside `log`, the log the row is from.

Dropped: the row's `id` and `timestamp` (`ts` has the time),
`severity_text` (`level` says it), `event_message` (the line the attributes
were read from; kept, with `severity_text`, only for a row that has none),
and the attributes that are per-event or per-user ids, timings, or the row's
host and time again: `actor_id`, `user_id`, `audit_log_id`, `request_id`,
`created_at`, `timestamp`, `time`, `duration`, `host`, `referer`,
`user_agent`. An attribute named for one of the record's own keys (`ts`,
`source`, `log`, or anything starting `_`) is dropped too, so a row cannot
speak for the pipeline.

## What it enriches

`remote_addr`, as `_norm.ip`: its country, network and owner, hosting, Tor
and VPN, and whether it is one of yours (`_facts.ip`).

## Use it

In your config, beside [judge](../judge), which brings enrich-ip and
behavior-baseline:

```yaml
include:
  - pack:judge
  - pack:supabase

enrichment_tables:                  # your company: packs/README.md#the-profile
  profile: { type: document, path: profile/profile.yaml, required: true }

sinks:
  lake:                          # every finished record, kept: Parquet files, a directory an hour; delete old hours to trim it
    type: rolling_file
    path: lake/logs/%Y/%m/%d/%H
    wal_path: lake/wal
    max_file_age_seconds: 3600
    compression: { type: zstd, level: 3 }
    encoding:
      type: parquet
      record_column: record      # each record whole, for the fields the schema leaves out
      schema:
        ts: timestamp
        source: string
        _norm: { org: string, actor: string, kind: string, ip: string }

sources:
  supabase_auth:
    type: supabase
    project_ref: ${SUPABASE_PROJECT_REF}      # abcdefghijklmnopqrst
    token: ${SUPABASE_ACCESS_TOKEN}

dag:
  - from: supabase_auth
    to: [supabase]
  - from: supabase   # kept, judged
    to: [lake, baseline_builder, baseline_renderer]
```

and `supabase` in your profile's `own_sources`, so its records are your
org's.

`SUPABASE_PROJECT_REF` is the project's reference (Project Settings →
General, or the dashboard URL). `SUPABASE_ACCESS_TOKEN` is a Management API
access token (Account → Access Tokens) that can read the project's logs
(`analytics:read`). The source keeps its place in the runtime's state store,
so a restart resumes where it stopped; on first start it reads the last hour
(`since`). Left without a token, it says so once and stays idle. Another log
is another source: `log: auth_audit_logs`, `log: edge_logs`.

Kinds worth the profile's `watch`: `user_deleted`, `factor_deleted`.

## Test it

[tests/input.json](tests/input.json): rows as the source emits them, made
up: a sign-in, a refused one and a sign-in after it from a Tor exit, an
audit event, a sign-up carrying the keys only the pipeline writes, and a row
of another log. [tests/expected.json](tests/expected.json) is what the
plugin makes of them against the tables in `tests/` (the company, GeoLite2's
answers for their addresses, their labels), which `ingest.yaml` names for
the test in any config.

```bash
make -C packs test-supabase
make -C packs fixtures-supabase   # after a change; read the diff
```

No case in [tangent-eval](https://github.com/EthanBlackburn/tangent-eval)
has Supabase records yet, and the fixtures' rows are written from Supabase's
field reference, not captured from a project.
