//! `macos_review`: a second look at each alert, by a stronger model that can
//! query the lake. The judge reads a summary of a session's few minutes and
//! marks freely, so much of what it marks is ordinary work. This plugin sits
//! after `macos_verdicts`: for each alert it holds a conversation with the
//! inference node its config names (`model.chat`), which gets the brief in
//! ../review.md as the node's prompt, the alert, and two tools:
//!
//! - `query` runs the model's SQL on the lake (`lake.query`), as one table,
//!   `records`: a view over the lake's Parquet files for the `days` before
//!   the alert, a column for each field a question is likely to turn on
//!   ([`COLUMNS`]) and the record whole beside them, ending where the alert
//!   does (`settle_seconds` later), so a replay's review sees what a live one
//!   would. The SQL is written by a model that has just read whatever an
//!   attacker put in a command line, and `lake.query` lets a statement read
//!   the view and nothing else.
//! - `report` gives the answer.
//!
//! Each alert goes on with `review` (`verdict`: malicious, benign or
//! unresolved, with `finding` and `check`), the SQL the model ran and what
//! the review took. A review that fails (the model's content filter stops
//! it, which what an attack leaves in a log can set off; no report within
//! the queries allowed) is an `error` in `review`, and the alert stands.
//!
//! The lake has an alert's own records once their file is sealed, minutes
//! after the alert. The config holds each alert back that long by grouping:
//! `group_by` an alert's session and window, `expire_after_ms` the wait. A
//! grouped plugin has workers of its own, so a review that takes minutes
//! holds up neither the capture nor the judge.

wit_bindgen::generate!({
    path: ".tangent/wit",
    world: "processor",
    generate_all,
});

use exports::tangent::logs::mapper::{Guest, Meta, Pred, Selector};
use serde_json::{json, Map, Value};
use tangent::logs::log::{Logview, Scalar};
use tangent::logs::{config, lake, model};

struct Component;

export!(Component);

/// Characters of one query's result the model is shown.
const RESULT_LIMIT: usize = 12_000;
/// Rows of one query's result, and characters of one cell.
const ROWS: u32 = 500;
const CELL: u32 = 500;
const QUERY_MS: u32 = 30_000;

/// The table: a column's name, the SQL that makes it from the lake's columns
/// (../lake.yaml), and what the model is told it holds.
const COLUMNS: &[(&str, &str, &str)] = &[
    ("ts", "ts", "when, in UTC"),
    ("event", "event",
     "`exec` (a program started), `open`, `close`, `create`, `rename`, `unlink` (a file), `connect` (a network \
      connection opened), `prompt` (what the person typed to an AI coding agent), or a rarer Endpoint Security \
      event as it came (`btm_launch_item_add`, a login item added; `tcc_modify`, a privacy permission changed)"),
    ("session", "\"session\"['id']", "the session the record belongs to: `session.id` in the alert"),
    ("entry", "\"session\"['entry']", "the session's entry point"),
    ("turn", "\"session\"['turn']", "in an agent's session, when the turn the record is part of began"),
    ("piece", "\"session\"['window']",
     "the few minutes of the session the record was summed up with: `session.window` in the alert"),
    ("pid", "process['pid']", "the process that acted"),
    ("ppid", "process['ppid']", "its parent"),
    ("program", "process['path']", "its program's path"),
    ("script", "process['name']",
     "for an interpreter (a shell, node, Python, bun) running a file, its name and the file, written from `~`: \
      `python ~/tools/sync.py`"),
    ("signer", "process['signer']", "its code-signing identity"),
    ("team", "process['team']",
     "its Developer ID team; null for an ad hoc or absent signature and for macOS's own programs"),
    ("platform", "process['platform']", "whether it is part of macOS"),
    ("tty", "process['tty']", "its terminal; null when no person typed it"),
    ("parents", "parents",
     "a list: the programs above it, nearest first, each with the start of its arguments; ends at `/sbin/launchd`, \
      at `(unknown)` where the log cannot say, or at `…` when the chain is longer; `array_to_string(parents, ' < ')` \
      is the chain as text"),
    ("responsible", "responsible", "the app macOS holds responsible for it, when that is another program"),
    ("args", "exec['args']", "`exec`: the command line, a list (long ones are cut)"),
    ("command", "array_to_string(exec['args'], ' ')", "`exec`: the command line as one string, to search with LIKE"),
    ("cwd", "exec['cwd']", "`exec`: the working directory"),
    ("env", "json_get_json(record, 'exec', 'env')",
     "`exec`: the few environment variables kept, those that steer a program, as JSON text; the rest are never stored"),
    ("file", "file", "file events: the file"),
    ("renamed_from", "\"from\"", "`rename`: the name it had"),
    ("access", "access", "`open`: `read` or `write`"),
    ("modified", "modified", "`close`: whether it was written"),
    ("host", "\"connect\"['host']", "`connect`: the name the TLS hello or a DNS answer gave"),
    ("dst", "\"connect\"['dst']", "`connect`: the address"),
    ("port", "\"connect\"['port']", "`connect`: the port"),
    ("prompt", "prompt['text']", "`prompt`: the text typed"),
    ("facts", "_facts",
     "a struct of marks the pack made, null when not set: which kept group a file is in (`credentials`, `persistence`, \
      `agent_settings`, `agent_instructions`, `agent_mcp`, `agent_state`, `agent_extensions`), `scratch_program` \
      (the program or its script is in /tmp, a cache, Downloads or node_modules), `unsigned`, `steering_env`, \
      `rename_over`; read one as `facts['credentials']`"),
    ("record", "record",
     "the whole record, as JSON text, for what has no column: `record->>'key'`, `record->'detail'->>'key'`, \
      `json_get_str(record, 'a', 'b')`"),
];

/// The tools the model is given.
fn tools() -> Value {
    json!([
        {
            "name": "query",
            "description": "Run one SQL statement (Apache DataFusion's SQL) on the `records` table and get the result as a \
                            table. A large result is cut, so select the columns you need and filter, group or limit. \
                            A list is indexed from 1 (`args[1]`), tested with `array_has(args, 'x')`, and does not cast \
                            to text: use `array_to_string`. Write a time whole, `'2026-03-02T10:05:00Z'`, and name \
                            each GROUP BY column. `->` and `->>` read JSON text and bind loosely: put them in \
                            brackets to compare, `(env->>'HTTPS_PROXY') IS NOT NULL`.",
            "parameters": {"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]},
        },
        {
            "name": "report",
            "description": "Give your answer on the alert. This ends the review.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding": {"type": "string",
                                "description": "What happened and who caused it, in a few sentences, naming the records it rests on."},
                    "verdict": {"type": "string", "enum": ["malicious", "benign", "unresolved"]},
                    "check": {"type": "string",
                              "description": "When the verdict is malicious or unresolved: what the owner should check or undo first."},
                },
                "required": ["finding", "verdict"],
            },
        },
    ])
}

/// A time as the alert gives it (`2026-03-02T10:05:00.123Z`), to the second,
/// as SQL can cast it; None when it is not one. Only digits and the marks of
/// a time pass, so it is safe inside a statement.
fn sql_time(t: &str) -> Option<String> {
    let s = t.get(..19)?;
    let shaped = s.bytes().enumerate().all(|(i, b)| match i {
        4 | 7 => b == b'-',
        10 => b == b'T',
        13 | 16 => b == b':',
        _ => b.is_ascii_digit(),
    });
    shaped.then(|| format!("{s}+00:00"))
}

/// The `records` view over table `table`: the columns, for the `days` up to
/// `until` and `settle` seconds past it.
fn view(table: &str, until: Option<&str>, days: u64, settle: u64) -> String {
    let cols: Vec<String> = COLUMNS
        .iter()
        .map(|(name, sql, _)| format!("{sql} AS {name}"))
        .collect();
    let mut select = format!("SELECT {} FROM {table}", cols.join(", "));
    if let Some(at) = until.and_then(sql_time) {
        let end = format!(
            "arrow_cast('{at}', 'Timestamp(Millisecond, Some(\"+00:00\"))') + INTERVAL '{} seconds'",
            settle + 1 // the alert's last second whole
        );
        select.push_str(&format!(
            " WHERE ts <= {end} AND ts >= {end} - INTERVAL '{days} days'"
        ));
    }
    select
}

/// The first message: what the table holds, its columns, and the alert.
fn first_message(alert: &Value, held: &Value) -> String {
    let guide: Vec<String> = COLUMNS
        .iter()
        .map(|(name, _, says)| format!("- `{name}`: {says}"))
        .collect();
    let at = |k: &str| {
        held.get(k)
            .map(Value::to_string)
            .unwrap_or_else(|| "null".into())
    };
    format!(
        "The `records` table holds {} records, from {} to {}. Its columns:\n\n{}\n\nThe alert:\n\n{alert}",
        at("n"),
        at("first").trim_matches('"'),
        at("last").trim_matches('"'),
        guide.join("\n")
    )
}

/// What is wrong with a `report`, or None.
fn checked(answer: &Value) -> Option<&'static str> {
    let finding = answer.get("finding").and_then(Value::as_str).unwrap_or("");
    if finding.trim().is_empty() {
        return Some("`finding` is missing");
    }
    match answer.get("verdict").and_then(Value::as_str) {
        Some("malicious" | "benign" | "unresolved") => None,
        _ => Some("`verdict` is one of malicious, benign, unresolved"),
    }
}

/// A query's result as the model is shown it: cut at [`RESULT_LIMIT`].
fn shown(mut text: String) -> String {
    if text.trim().is_empty() {
        return "(no rows)".into();
    }
    let total = text.chars().count();
    if total > RESULT_LIMIT {
        let cut = text
            .char_indices()
            .nth(RESULT_LIMIT)
            .map_or(text.len(), |(i, _)| i);
        text.truncate(cut);
        text.push_str(&format!(
            "\n[cut: {} more characters; select fewer columns or rows]",
            total - RESULT_LIMIT
        ));
    }
    text
}

/// What a review took.
#[derive(Default)]
struct Took {
    calls: u64,
    failed_queries: u64,
    input_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    output_tokens: u64,
}

impl Took {
    fn add(&mut self, usage: &Value) {
        let n = |k: &str| usage.get(k).and_then(Value::as_u64).unwrap_or(0);
        self.input_tokens += n("input_tokens");
        self.cache_read_tokens += n("cached_input_tokens");
        self.cache_write_tokens += n("cache_creation_input_tokens");
        self.output_tokens += n("output_tokens");
    }

    fn json(&self) -> Value {
        json!({"calls": self.calls, "failed_queries": self.failed_queries,
               "input_tokens": self.input_tokens, "cache_read_tokens": self.cache_read_tokens,
               "cache_write_tokens": self.cache_write_tokens, "output_tokens": self.output_tokens})
    }
}

/// The model's review of one alert: its report or `{"error"}`, the SQL it
/// ran, and what it took. `converse` is one turn with the model (the request
/// and the reply as `model.chat` has them); `run_query` the model's SQL on
/// the view, the text to show and whether it ran.
fn review(
    alert: &Value,
    held: &Value,
    max_queries: usize,
    alert_with_prompt: bool,
    mut run_query: impl FnMut(&str) -> (String, bool),
    mut converse: impl FnMut(&Value) -> Result<Value, String>,
) -> (Value, Vec<String>, Took) {
    let first = first_message(alert, held);
    let tools = tools();
    let mut messages = if alert_with_prompt {
        vec![
            json!({"role": "system", "text": first}),
            json!({"role": "user", "text": "Review the alert."}),
        ]
    } else {
        vec![json!({"role": "user", "text": first})]
    };
    let mut took = Took::default();
    let mut ran: Vec<String> = Vec::new();
    let mut nudged = 0;
    while (took.calls as usize) < max_queries + 6 {
        let reply = match converse(&json!({"messages": messages, "tools": tools, "cache": true})) {
            Ok(reply) => reply,
            Err(e) => return (json!({"error": e}), ran, took),
        };
        took.calls += 1;
        took.add(&reply["usage"]);
        if reply["message"].is_null() {
            return (json!({"error": "the model gave an empty turn"}), ran, took);
        }
        messages.push(reply["message"].clone());
        let calls = reply["calls"].as_array().cloned().unwrap_or_default();
        let mut results = Vec::new();
        for call in &calls {
            let given = &call["arguments"];
            let (text, ok) = if call["name"] == "report" {
                match checked(given) {
                    None => return (given.clone(), ran, took),
                    Some(wrong) => (wrong.to_string(), false),
                }
            } else if ran.len() >= max_queries {
                (
                    "No queries are left. Call `report` with what you have.".to_string(),
                    false,
                )
            } else {
                let sql = given.get("sql").and_then(Value::as_str).unwrap_or("");
                ran.push(sql.to_string());
                let (mut text, ok) = run_query(sql);
                took.failed_queries += u64::from(!ok);
                if ran.len() == max_queries {
                    text.push_str("\n\nThat was the last query. Call `report` with what you have.");
                }
                (text, ok)
            };
            results
                .push(json!({"id": call["id"], "name": call["name"], "text": text, "error": !ok}));
        }
        if calls.is_empty() {
            if reply["stop"] == "length" || nudged >= 2 {
                break;
            }
            nudged += 1;
            messages.push(json!({"role": "user", "text": "Answer by calling `report`."}));
        } else {
            messages.push(json!({"role": "user", "results": results}));
        }
    }
    (json!({"error": "the model gave no report"}), ran, took)
}

/// A setting of the plugin's `config`, or its default.
fn setting(key: &str, default: u64) -> u64 {
    config::get(key)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// Seconds since 1970 as an RFC 3339 time in UTC.
fn rfc3339(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // civil from days (Howard Hinnant's algorithm)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The alert with its review, as the record that goes on.
fn reviewed(alert: &Value) -> Value {
    let began = now();
    let node = config::get("model").unwrap_or_else(|| "reviewer".into());
    let table = config::get("table").unwrap_or_else(|| "lake".into());
    let session = alert.get("session").cloned().unwrap_or(Value::Null);
    let until = session
        .get("to")
        .and_then(Value::as_str)
        .or_else(|| alert.get("ts").and_then(Value::as_str));
    let views = vec![(
        "records".to_string(),
        view(
            &table,
            until,
            setting("days", 7),
            setting("settle_seconds", 0),
        ),
    )];
    let ask = |sql: &str, json: bool, max_rows: u32| {
        lake::query(&lake::Statement {
            views: views.clone(),
            sql: sql.to_string(),
            max_rows,
            json,
            max_cell: CELL,
            timeout_ms: Some(QUERY_MS),
        })
    };
    let held = ask(
        "SELECT count(*) AS n, min(ts) AS first, max(ts) AS last FROM records",
        true,
        1,
    )
    .and_then(|rows| {
        serde_json::from_str::<Value>(rows.lines().next().unwrap_or("{}"))
            .map_err(|e| e.to_string())
    });
    let (answer, ran, took) = match held {
        Err(e) => (
            json!({"error": format!("reading the lake: {e}")}),
            Vec::new(),
            Took::default(),
        ),
        Ok(held) => review(
            alert,
            &held,
            setting("queries", 20) as usize,
            config::get("alert_with_prompt").is_some_and(|v| v.trim() == "true"),
            |sql| {
                if sql.trim().is_empty() {
                    return ("error: one SQL statement, please".to_string(), false);
                }
                match ask(sql, false, ROWS) {
                    Ok(rows) => (shown(rows), true),
                    Err(e) => (shown(format!("error: {e}")), false),
                }
            },
            |request| {
                let reply = model::chat(&node, &request.to_string())?;
                serde_json::from_str(&reply).map_err(|e| format!("the model's reply: {e}"))
            },
        ),
    };
    let mut took = took.json();
    took["seconds"] = json!(now().saturating_sub(began));
    let mut judge = alert.get("judge").cloned().unwrap_or(Value::Null);
    if let Some(j) = judge.as_object_mut() {
        j.remove("so_far");
    }
    let mut out = Map::new();
    out.insert("ts".into(), json!(rfc3339(now())));
    out.insert("source".into(), json!("macos_review"));
    out.insert("session".into(), session);
    out.insert("judge".into(), judge);
    out.insert("review".into(), answer);
    out.insert("queries".into(), json!(ran));
    out.insert("took".into(), took);
    out.insert("model".into(), json!(node));
    Value::Object(out)
}

impl Guest for Component {
    fn metadata() -> Meta {
        Meta {
            name: "macos_review".to_string(),
            version: "0.1.0".to_string(),
        }
    }

    fn probe() -> Vec<Selector> {
        vec![Selector {
            any: Vec::new(),
            all: vec![
                Pred::Eq((
                    "source".to_string(),
                    Scalar::Str("macos_session".to_string()),
                )),
                Pred::Has("judge.warrants_investigation".to_string()),
            ],
            none: vec![Pred::Has("_context".to_string())],
        }]
    }

    fn process_logs(input: Vec<Logview>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for lv in input {
            let Ok(alert) = serde_json::from_str::<Value>(&lv.log()) else {
                continue;
            };
            out.extend(reviewed(&alert).to_string().into_bytes());
            out.push(b'\n');
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert() -> Value {
        json!({"source": "macos_session",
               "session": {"id": "501", "entry": "zsh", "from": "2026-03-02T10:00:00.000Z", "to": "2026-03-02T10:05:00.250Z"},
               "judge": {"warrants_investigation": "look", "why": "a key was read by a package script"}})
    }

    /// A model that answers with these turns in order: each a list of
    /// (tool, arguments), or none for prose.
    fn model(
        turns: Vec<Vec<(&'static str, Value)>>,
    ) -> impl FnMut(&Value) -> Result<Value, String> {
        let mut turns = turns.into_iter();
        let mut n = 0;
        move |_request| {
            let calls: Vec<Value> = turns
                .next()
                .unwrap_or_default()
                .into_iter()
                .map(|(name, arguments)| {
                    n += 1;
                    json!({"id": {"provider": format!("call_{n}")}, "name": name, "arguments": arguments})
                })
                .collect();
            let stop = if calls.is_empty() { "stop" } else { "tool_use" };
            Ok(
                json!({"message": {"role": "assistant", "content": []}, "text": "", "calls": calls,
                      "stop": stop, "usage": {"input_tokens": 10, "output_tokens": 2, "cached_input_tokens": 4}}),
            )
        }
    }

    fn held() -> Value {
        json!({"n": 3, "first": "2026-03-01T00:00:00Z", "last": "2026-03-02T10:05:00Z"})
    }

    fn report(verdict: &str) -> (&'static str, Value) {
        (
            "report",
            json!({"finding": "node read ~/.ssh/id_ed25519 under npm install.", "verdict": verdict}),
        )
    }

    #[test]
    fn queries_then_a_report() {
        let mut asked = Vec::new();
        let (answer, ran, took) = review(
            &alert(),
            &held(),
            20,
            false,
            |sql| {
                asked.push(sql.to_string());
                ("| n |\n| 3 |".into(), true)
            },
            model(vec![
                vec![("query", json!({"sql": "SELECT count(*) FROM records"}))],
                vec![("query", json!({"sql": "SELECT nope"}))],
                vec![report("malicious")],
            ]),
        );
        assert_eq!(answer["verdict"], "malicious");
        assert_eq!(ran, asked);
        assert_eq!(ran.len(), 2);
        let took = took.json();
        assert_eq!(
            (took["calls"].as_u64(), took["input_tokens"].as_u64()),
            (Some(3), Some(30))
        );
        assert_eq!(took["cache_read_tokens"], 12);
    }

    #[test]
    fn the_conversation_is_the_alert_then_each_turn_and_its_results() {
        let mut seen = Vec::new();
        let mut answers = model(vec![
            vec![("query", json!({"sql": "SELECT 1"}))],
            vec![report("benign")],
        ]);
        review(
            &alert(),
            &held(),
            20,
            false,
            |_| ("(no rows)".into(), false),
            |request| {
                seen.push(request.clone());
                answers(request)
            },
        );
        let first = seen[0]["messages"][0]["text"].as_str().unwrap();
        assert!(first.starts_with("The `records` table holds 3 records, from 2026-03-01T00:00:00Z to 2026-03-02T10:05:00Z."));
        assert!(first.contains("- `parents`: a list"));
        assert!(first.contains("a key was read by a package script"));
        assert_eq!(seen[0]["cache"], true);
        assert_eq!(seen[0]["tools"][1]["name"], "report");
        // the second request: the model's turn as it came, then the result under the call's id
        let messages = seen[1]["messages"].as_array().unwrap();
        assert_eq!(messages[1]["role"], "assistant");
        let result = &messages[2]["results"][0];
        assert_eq!(result["id"], json!({"provider": "call_1"}));
        assert_eq!(
            (result["name"].as_str(), result["error"].as_bool()),
            (Some("query"), Some(true))
        );
    }

    #[test]
    fn a_report_with_no_such_verdict_is_sent_back() {
        let (answer, _, took) = review(
            &alert(),
            &held(),
            20,
            false,
            |_| unreachable!(),
            model(vec![vec![report("suspicious")], vec![report("unresolved")]]),
        );
        assert_eq!(answer["verdict"], "unresolved");
        assert_eq!(took.calls, 2);
    }

    #[test]
    fn queries_past_the_limit_are_not_run() {
        let mut run = 0;
        let query = || ("query", json!({"sql": "SELECT 1"}));
        let (answer, ran, _) = review(
            &alert(),
            &held(),
            2,
            false,
            |_| {
                run += 1;
                ("ok".into(), true)
            },
            model(vec![
                vec![query(), query(), query()],
                vec![report("benign")],
            ]),
        );
        assert_eq!((run, ran.len()), (2, 2));
        assert_eq!(answer["verdict"], "benign");
    }

    #[test]
    fn an_answer_in_prose_is_asked_for_as_a_report_and_never_reporting_is_an_error() {
        let (answer, _, _) = review(
            &alert(),
            &held(),
            20,
            false,
            |_| unreachable!(),
            model(vec![vec![], vec![report("benign")]]),
        );
        assert_eq!(answer["verdict"], "benign");
        let (answer, _, took) = review(
            &alert(),
            &held(),
            20,
            false,
            |_| unreachable!(),
            model(vec![]),
        );
        assert_eq!(answer["error"], "the model gave no report");
        assert_eq!(took.calls, 3);
    }

    #[test]
    fn a_model_that_fails_is_the_error_and_the_alert_stands() {
        let (answer, ran, _) = review(
            &alert(),
            &held(),
            20,
            false,
            |_| unreachable!(),
            |_| Err("the model failed the turn: content filtered".to_string()),
        );
        assert_eq!(
            answer["error"],
            "the model failed the turn: content filtered"
        );
        assert!(ran.is_empty());
    }

    #[test]
    fn the_view_ends_where_the_alert_does() {
        let v = view("lake", Some("2026-03-02T10:05:00.250Z"), 7, 400);
        assert!(v.starts_with("SELECT ts AS ts, event AS event, \"session\"['id'] AS session, "));
        assert!(v.contains(
            "WHERE ts <= arrow_cast('2026-03-02T10:05:00+00:00', 'Timestamp(Millisecond, Some(\"+00:00\"))') + INTERVAL '401 seconds'"
        ));
        assert!(v.ends_with("- INTERVAL '7 days'"));
        // a time that is not one bounds nothing, and is never put in the SQL
        assert!(!view("lake", Some("x' OR 1=1 --........"), 7, 0).contains("WHERE"));
        assert!(!view("lake", None, 7, 0).contains("WHERE"));
        assert_eq!(
            sql_time("2026-03-02T10:05:00Z").as_deref(),
            Some("2026-03-02T10:05:00+00:00")
        );
        assert_eq!(sql_time("2026-03-02 10:05:00Z"), None);
    }

    #[test]
    fn a_long_result_is_cut_and_an_empty_one_says_so() {
        let cut = shown("é".repeat(RESULT_LIMIT + 40));
        assert!(cut.ends_with("[cut: 40 more characters; select fewer columns or rows]"));
        assert_eq!(shown("  \n".into()), "(no rows)");
        assert_eq!(shown("| n |".into()), "| n |");
    }

    #[test]
    fn a_time_is_written_in_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_772_445_900), "2026-03-02T10:05:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }
}
