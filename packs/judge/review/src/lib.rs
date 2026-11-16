//! `review`: a second look at what the judge flagged, by a stronger model
//! that can query the lake. The judge reads an actor's latest records and
//! flags freely, so much of what it flags is ordinary work. This plugin sits
//! after `flagged`: for each actor's alerts (the records the judge flagged,
//! grouped by the config's `group_by`) it holds one conversation with the
//! inference node its config names (`model.chat`), which gets the brief in
//! ../review.md as the node's prompt, the alerts, and two tools:
//!
//! - `query` runs the model's SQL on the lake (`lake.query`), as one table,
//!   `records`: a view over the lake's Parquet files for the `days` before
//!   the last alert, a column for each field every source shares
//!   ([`COLUMNS`]) and the record whole beside them, ending where the alerts
//!   do (`settle_seconds` later), so a replay's review sees what a live one
//!   would. The SQL is written by a model that has just read whatever an
//!   attacker put in a record, and `lake.query` lets a statement read the
//!   view and nothing else.
//! - `report` gives the answer.
//!
//! Each alert goes on with `review` (`verdict`: malicious, benign or
//! unresolved, with `finding` and `check`), the same on every alert of the
//! group; the first also carries `reviewed`: how many alerts the review
//! covered, the SQL the model ran, what the review took and the node. A
//! review that fails is an `error` in `review`, and the alerts stand.
//!
//! The lake has an alert's own records once their file is sealed. The config
//! holds an actor's alerts back that long by grouping (`expire_after_ms`),
//! which also gathers them into one review, on workers of the plugin's own.

wit_bindgen::generate!({
    path: ".tangent/wit",
    world: "processor",
    generate_all,
});

use exports::tangent::logs::mapper::{Guest, Meta, Pred, Selector};
use serde_json::{json, Map, Value};
use tangent::logs::log::Logview;
use tangent::logs::{config, lake, model};

struct Component;

export!(Component);

/// Characters of one query's result the model is shown.
const RESULT_LIMIT: usize = 12_000;
/// Rows of one query's result, and characters of one cell.
const ROWS: u32 = 500;
const CELL: u32 = 2000;
const QUERY_MS: u32 = 30_000;

/// The table: a column's name, the SQL that makes it from the lake's columns
/// (examples/cloud-infra's sink `lake`), and what the model is told it holds.
const COLUMNS: &[(&str, &str, &str)] = &[
    ("ts", "ts",
     "when, in UTC; null for the rare record the lake could not read into columns, which has only `record` and is in \
      the table whatever its time"),
    ("source", "source", "which log the record is from: `source` in an alert"),
    ("org", "_norm['org']", "the organization: `_norm.org` in an alert"),
    ("actor", "_norm['actor']", "who acted, named the same in every source: `_norm.actor` in an alert"),
    ("kind", "_norm['kind']", "what was done, when the source's own field does not say: `_norm.kind`"),
    ("ip", "_norm['ip']", "the address it came from, when the record has one"),
    ("record", "record",
     "the whole record as its source wrote it, with `_norm` and `_facts`, as JSON text: `record->>'eventName'`, \
      `record->'requestParameters'->>'roleArn'`, `json_get_str(record, 'actor', 'alternateId')`"),
];

fn tools() -> Value {
    json!([
        {
            "name": "query",
            "description": "Run one SQL statement (Apache DataFusion's SQL) on the `records` table and get the result as a \
                            table. A large result is cut, and so is a cell over 2000 characters (read on into one with `substr`), \
                            so select the fields you need and filter, group or limit. Write a time whole, \
                            `'2026-03-02T10:05:00Z'`, and name each GROUP BY column. `->` and `->>` read JSON text and \
                            bind loosely: put them in brackets to compare, `(record->>'errorCode') IS NOT NULL`.",
            "parameters": {"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]},
        },
        {
            "name": "report",
            "description": "Give your answer on the alerts. This ends the review.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding": {"type": "string",
                                "description": "What happened and who did it, in a few sentences, naming the records it rests on."},
                    "verdict": {"type": "string", "enum": ["malicious", "benign", "unresolved"]},
                    "check": {"type": "string",
                              "description": "When the verdict is malicious or unresolved: what to check or undo first."},
                },
                "required": ["finding", "verdict"],
            },
        },
    ])
}

/// A time as the alert gives it, in UTC (`2026-03-02T10:05:00.123Z`), to the
/// second, as SQL can cast it; None when it is not one, a time with another
/// offset included. Only digits and the marks of a time pass, so it is safe
/// inside a statement.
fn sql_time(t: &str) -> Option<String> {
    let (s, rest) = (t.get(..19)?, t.get(19..)?);
    let shaped = s.bytes().enumerate().all(|(i, b)| match i {
        4 | 7 => b == b'-',
        10 => b == b'T',
        13 | 16 => b == b':',
        _ => b.is_ascii_digit(),
    });
    let fraction = rest.strip_suffix('Z')?;
    let utc = fraction.is_empty()
        || fraction
            .strip_prefix('.')
            .is_some_and(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()));
    (shaped && utc).then(|| format!("{s}+00:00"))
}

/// `at` (from [`sql_time`]) as a timestamp in a statement.
fn sql_timestamp(at: &str) -> String {
    format!("arrow_cast('{at}', 'Timestamp(Millisecond, Some(\"+00:00\"))')")
}

/// The `records` view over table `table`: the columns, for the `days` up to
/// `until` (from [`sql_time`]) and `settle` seconds past it. A record whose
/// time the lake could not read has none to be left out by, and stays.
fn view(table: &str, until: &str, days: u64, settle: u64) -> String {
    let cols: Vec<String> = COLUMNS
        .iter()
        .map(|(name, sql, _)| format!("{sql} AS {name}"))
        .collect();
    let end = format!(
        "{} + INTERVAL '{} seconds'",
        sql_timestamp(until),
        settle + 1 // the alert's last second whole
    );
    format!(
        "SELECT {} FROM {table} WHERE ts IS NULL OR (ts <= {end} AND ts >= {end} - INTERVAL '{days} days')",
        cols.join(", ")
    )
}

/// The alerts as the model reads them, a line each: `_baseline`, which an
/// actor's records share, on the first that has each.
fn lines(alerts: &[Value]) -> String {
    let mut said: Vec<&Value> = Vec::new();
    let mut out = Vec::new();
    for alert in alerts {
        let mut a = alert.clone();
        if let Some(b) = alert.get("_baseline") {
            if said.contains(&b) {
                a.as_object_mut().map(|o| o.remove("_baseline"));
            } else {
                said.push(b);
            }
        }
        out.push(a.to_string());
    }
    out.join("\n")
}

/// The first message: what the table holds, its columns, and the alerts.
fn first_message(alerts: &[Value], held: &Value) -> String {
    let guide: Vec<String> = COLUMNS
        .iter()
        .map(|(name, _, says)| format!("- `{name}`: {says}"))
        .collect();
    let at = |k: &str| {
        held.get(k)
            .map(Value::to_string)
            .unwrap_or_else(|| "null".into())
    };
    let early = if held["whole"] == true {
        ""
    } else {
        " It does not yet hold the last alert's records, which were not written when this review began: \
         if the answer turns on them, the verdict is `unresolved`."
    };
    format!(
        "The `records` table holds {} records, from {} to {}.{early} Its columns:\n\n{}\n\nThe alerts, {} of them:\n\n{}",
        at("n"),
        at("first").trim_matches('"'),
        at("last").trim_matches('"'),
        guide.join("\n"),
        alerts.len(),
        lines(alerts)
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

/// The model's review of one actor's alerts: its report or `{"error"}`, the
/// SQL it ran, and what it took. `converse` is one turn with the model (the
/// request and the reply as `model.chat` has them); `run_query` the model's
/// SQL on the view, the text to show and whether it ran.
fn review(
    alerts: &[Value],
    held: &Value,
    max_queries: usize,
    mut run_query: impl FnMut(&str) -> (String, bool),
    mut converse: impl FnMut(&Value) -> Result<Value, String>,
) -> (Value, Vec<String>, Took) {
    let tools = tools();
    let mut messages = vec![json!({"role": "user", "text": first_message(alerts, held)})];
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
            let (text, ok) = match call["name"].as_str() {
                // a report beside queries was written before their results
                Some("report") if calls.len() > 1 => (
                    "Call `report` on its own, once you have read your queries' results."
                        .to_string(),
                    false,
                ),
                Some("report") => match checked(given) {
                    None => return (given.clone(), ran, took),
                    Some(wrong) => (wrong.to_string(), false),
                },
                Some("query") if ran.len() >= max_queries => (
                    "No queries are left. Call `report` with what you have.".to_string(),
                    false,
                ),
                Some("query") => {
                    let sql = given.get("sql").and_then(Value::as_str).unwrap_or("");
                    ran.push(sql.to_string());
                    let (mut text, ok) = run_query(sql);
                    took.failed_queries += u64::from(!ok);
                    if ran.len() == max_queries {
                        text.push_str("\n\nThat was the last query. Call `report` with what you have.");
                    }
                    (text, ok)
                }
                _ => (
                    "There is no such tool: call one of those you were given.".to_string(),
                    false,
                ),
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One actor's alerts, each with the review of them all.
fn reviewed(alerts: Vec<Value>) -> Vec<Value> {
    let began = now();
    let node = config::get("model").unwrap_or_else(|| "reviewer".into());
    let table = config::get("table").unwrap_or_else(|| "lake".into());
    // the latest alert's time ends the table: without one it would hold the
    // days after the alerts too
    let until = alerts
        .iter()
        .filter_map(|a| a.get("ts").and_then(Value::as_str).and_then(sql_time))
        .max();
    let (answer, ran, took, early) = match until {
        None => (
            json!({"error": "no alert has a time in UTC (`ts`) to end the table at"}),
            Vec::new(),
            Took::default(),
            false,
        ),
        Some(until) => {
            let views = vec![(
                "records".to_string(),
                view(&table, &until, setting("days", 30), setting("settle_seconds", 0)),
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
            // `whole`: the lake has records as late as the last alert
            let held = ask(
                &format!(
                    "SELECT count(*) AS n, min(ts) AS first, max(ts) AS last, \
                     coalesce(max(ts) >= {}, false) AS whole FROM records",
                    sql_timestamp(&until)
                ),
                true,
                1,
            )
            .and_then(|rows| {
                serde_json::from_str::<Value>(rows.lines().next().unwrap_or("{}"))
                    .map_err(|e| e.to_string())
            });
            match held {
                Err(e) => (
                    json!({"error": format!("reading the lake: {e}")}),
                    Vec::new(),
                    Took::default(),
                    false,
                ),
                Ok(held) => {
                    let (answer, ran, took) = review(
                        &alerts,
                        &held,
                        setting("queries", 20) as usize,
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
                            serde_json::from_str(&reply)
                                .map_err(|e| format!("the model's reply: {e}"))
                        },
                    );
                    (answer, ran, took, held["whole"] != true)
                }
            }
        }
    };
    let mut took = took.json();
    took["seconds"] = json!(now().saturating_sub(began));
    let mut about = Map::new();
    about.insert("alerts".into(), json!(alerts.len()));
    if early {
        about.insert("early".into(), json!(true));
    }
    about.insert("queries".into(), json!(ran));
    about.insert("took".into(), took);
    about.insert("model".into(), json!(node));
    let mut about = Some(Value::Object(about));
    alerts
        .into_iter()
        .map(|mut alert| {
            if let Some(a) = alert.as_object_mut() {
                a.insert("review".into(), answer.clone());
                if let Some(about) = about.take() {
                    a.insert("reviewed".into(), about);
                }
            }
            alert
        })
        .collect()
}

impl Guest for Component {
    fn metadata() -> Meta {
        Meta {
            name: "review".to_string(),
            version: "0.1.0".to_string(),
        }
    }

    fn probe() -> Vec<Selector> {
        vec![Selector {
            any: Vec::new(),
            all: vec![Pred::Has("judge.why".to_string())], // what the judge flagged
            none: vec![Pred::Has("_context".to_string())],
        }]
    }

    /// The input is a group, one actor's alerts, when the config groups; a
    /// batch that mixes actors is reviewed an actor at a time.
    fn process_logs(input: Vec<Logview>) -> Result<Vec<u8>, String> {
        let mut groups: Vec<(Value, Vec<Value>)> = Vec::new();
        for lv in input {
            let Ok(alert) = serde_json::from_str::<Value>(&lv.log()) else {
                continue;
            };
            let key = alert.get("_norm").map_or(Value::Null, |n| json!([n.get("org"), n.get("actor")]));
            match groups.iter_mut().find(|(k, _)| *k == key) {
                Some((_, alerts)) => alerts.push(alert),
                None => groups.push((key, vec![alert])),
            }
        }
        let mut out = Vec::new();
        for (_, alerts) in groups {
            for alert in reviewed(alerts) {
                out.extend(alert.to_string().into_bytes());
                out.push(b'\n');
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(ts: &str, kind: &str) -> Value {
        json!({"ts": ts, "source": "cloudtrail", "eventName": kind,
               "_norm": {"org": "acme", "actor": "dana@acme.example", "ip": "203.0.113.7"},
               "_baseline": {"seen_days": 120},
               "judge": {"flag": true, "why": "a key made from an address never seen"}})
    }

    fn alerts() -> Vec<Value> {
        vec![
            alert("2026-03-02T10:01:00Z", "CreateAccessKey"),
            alert("2026-03-02T10:05:00.250Z", "AttachUserPolicy"),
        ]
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
        json!({"n": 3, "first": "2026-02-01T00:00:00Z", "last": "2026-03-02T10:05:00Z", "whole": true})
    }

    fn report(verdict: &str) -> (&'static str, Value) {
        (
            "report",
            json!({"finding": "dana made a key for herself from 203.0.113.7.", "verdict": verdict}),
        )
    }

    fn query(sql: &str) -> (&'static str, Value) {
        ("query", json!({"sql": sql}))
    }

    #[test]
    fn queries_then_a_report() {
        let mut asked = Vec::new();
        let (answer, ran, took) = review(
            &alerts(),
            &held(),
            20,
            |sql| {
                asked.push(sql.to_string());
                (
                    if sql.contains("nope") { "error: no column nope" } else { "| n |\n| 3 |" }.into(),
                    !sql.contains("nope"),
                )
            },
            model(vec![
                vec![query("SELECT count(*) FROM records")],
                vec![query("SELECT nope")],
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
        assert_eq!(took["failed_queries"], 1);
    }

    #[test]
    fn the_conversation_is_the_alerts_then_each_turn_and_its_results() {
        let mut seen = Vec::new();
        let mut answers = model(vec![vec![query("SELECT 1")], vec![report("benign")]]);
        review(
            &alerts(),
            &held(),
            20,
            |_| ("(no rows)".into(), false),
            |request| {
                seen.push(request.clone());
                answers(request)
            },
        );
        let first = seen[0]["messages"][0]["text"].as_str().unwrap();
        assert!(first.starts_with(
            "The `records` table holds 3 records, from 2026-02-01T00:00:00Z to 2026-03-02T10:05:00Z. Its columns:"
        ));
        assert!(first.contains("- `actor`: who acted"));
        assert!(first.contains("The alerts, 2 of them:"));
        assert!(first.contains("AttachUserPolicy"));
        assert_eq!(seen[0]["cache"], true);
        assert_eq!(
            (seen[0]["tools"][0]["name"].as_str(), seen[0]["tools"][1]["name"].as_str()),
            (Some("query"), Some("report"))
        );
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

    /// An actor's records share `_baseline`: the model reads it once.
    #[test]
    fn a_baseline_the_alerts_share_is_written_once() {
        let mut other = alert("2026-03-02T10:06:00Z", "PutUserPolicy");
        other["_baseline"] = json!({"seen_days": 121});
        let mut all = alerts();
        all.push(other);
        let text = lines(&all);
        let rows: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["_baseline"]["seen_days"], 120);
        assert!(rows[1].get("_baseline").is_none());
        assert_eq!(rows[2]["_baseline"]["seen_days"], 121);
        assert_eq!(rows[1]["eventName"], "AttachUserPolicy");
    }

    #[test]
    fn a_report_with_no_such_verdict_or_no_finding_is_sent_back() {
        let (answer, _, took) = review(
            &alerts(),
            &held(),
            20,
            |_| unreachable!(),
            model(vec![
                vec![report("suspicious")],
                vec![("report", json!({"finding": " ", "verdict": "benign"}))],
                vec![report("unresolved")],
            ]),
        );
        assert_eq!(answer["verdict"], "unresolved");
        assert_eq!(took.calls, 3);
    }

    /// A report in a turn with queries was written before their results: the
    /// queries run, the report is sent back, and the next one stands.
    #[test]
    fn a_report_beside_a_query_waits_for_the_result() {
        let mut seen = Vec::new();
        let mut answers = model(vec![
            vec![query("SELECT 1"), report("benign")],
            vec![report("malicious")],
        ]);
        let (answer, ran, _) = review(
            &alerts(),
            &held(),
            20,
            |_| ("| n |\n| 1 |".into(), true),
            |request| {
                seen.push(request.clone());
                answers(request)
            },
        );
        assert_eq!(answer["verdict"], "malicious");
        assert_eq!(ran, ["SELECT 1"]);
        let results = seen[1]["messages"][2]["results"].as_array().unwrap();
        assert_eq!(results[0]["error"], false);
        assert_eq!(results[1]["error"], true);
        assert!(results[1]["text"].as_str().unwrap().contains("on its own"));
    }

    /// A tool the model made up is not a query: nothing runs, and none of
    /// the queries allowed is spent.
    #[test]
    fn a_tool_that_is_not_one_is_not_run() {
        let (answer, ran, _) = review(
            &alerts(),
            &held(),
            1,
            |_| ("| n |".into(), true),
            model(vec![
                vec![("shell", json!({"cmd": "ls"}))],
                vec![query("SELECT 1")],
                vec![report("benign")],
            ]),
        );
        assert_eq!(answer["verdict"], "benign");
        assert_eq!(ran, ["SELECT 1"]);
    }

    #[test]
    fn a_review_before_the_lake_has_the_last_alert_s_records_is_told_so() {
        let mut early = held();
        early["whole"] = json!(false);
        let said = first_message(&alerts(), &early);
        assert!(said.contains("does not yet hold the last alert's records"));
        assert!(!first_message(&alerts(), &held()).contains("does not yet hold"));
    }

    #[test]
    fn queries_past_the_limit_are_not_run() {
        let mut seen = Vec::new();
        let mut answers = model(vec![
            vec![query("SELECT 1")],
            vec![query("SELECT 2")],
            vec![query("SELECT 3")],
            vec![report("unresolved")],
        ]);
        let (answer, ran, _) = review(
            &alerts(),
            &held(),
            2,
            |_| ("| n |".into(), true),
            |request| {
                seen.push(request.clone());
                answers(request)
            },
        );
        assert_eq!(answer["verdict"], "unresolved");
        assert_eq!(ran, ["SELECT 1", "SELECT 2"]);
        let last = |i: usize| {
            let m = seen[i]["messages"].as_array().unwrap();
            m[m.len() - 1]["results"][0]["text"].as_str().unwrap().to_string()
        };
        assert!(last(2).ends_with("That was the last query. Call `report` with what you have."));
        assert_eq!(last(3), "No queries are left. Call `report` with what you have.");
    }

    #[test]
    fn an_answer_in_prose_is_asked_for_as_a_report_and_never_reporting_is_an_error() {
        let mut seen = Vec::new();
        let mut answers = model(vec![vec![], vec![report("benign")]]);
        let (answer, _, _) = review(
            &alerts(),
            &held(),
            20,
            |_| unreachable!(),
            |request| {
                seen.push(request.clone());
                answers(request)
            },
        );
        assert_eq!(answer["verdict"], "benign");
        assert_eq!(seen[1]["messages"][2]["text"], "Answer by calling `report`.");

        let (answer, _, took) = review(&alerts(), &held(), 20, |_| unreachable!(), model(vec![]));
        assert_eq!(answer["error"], "the model gave no report");
        assert_eq!(took.calls, 3); // asked twice more, then left
    }

    #[test]
    fn a_model_that_fails_is_the_error() {
        let (answer, ran, took) = review(
            &alerts(),
            &held(),
            20,
            |_| unreachable!(),
            |_| Err("bedrock: content filtered".to_string()),
        );
        assert_eq!(answer, json!({"error": "bedrock: content filtered"}));
        assert!(ran.is_empty());
        assert_eq!(took.calls, 0);
    }

    #[test]
    fn a_time_is_utc_to_the_second_or_it_is_not_one() {
        assert_eq!(sql_time("2026-03-02T10:05:00Z").as_deref(), Some("2026-03-02T10:05:00+00:00"));
        assert_eq!(sql_time("2026-03-02T10:05:00.250Z").as_deref(), Some("2026-03-02T10:05:00+00:00"));
        for not in [
            "2026-03-02T10:05:00+02:00",
            "2026-03-02T10:05:00",
            "2026-03-02 10:05:00Z",
            "2026-03-02T10:05:00.Z",
            "2026-03-02T10:05:00Z' OR 1=1 --",
            "x",
        ] {
            assert_eq!(sql_time(not), None, "{not}");
        }
    }

    #[test]
    fn the_view_ends_where_the_alerts_do() {
        let until = sql_time("2026-03-02T10:05:00.250Z").unwrap();
        let sql = view("lake", &until, 30, 0);
        assert!(sql.starts_with("SELECT ts AS ts, source AS source, _norm['org'] AS org,"));
        assert!(sql.contains("record AS record FROM lake WHERE ts IS NULL OR (ts <= "));
        assert!(sql.contains("'2026-03-02T10:05:00+00:00'"));
        assert!(sql.contains("INTERVAL '1 seconds'")); // the last alert's second whole
        assert!(sql.ends_with("- INTERVAL '30 days')"));
        assert!(view("lake", &until, 7, 400).contains("INTERVAL '401 seconds'"));
    }

    #[test]
    fn a_long_result_is_cut_and_an_empty_one_says_so() {
        assert_eq!(shown(" \n".into()), "(no rows)");
        assert_eq!(shown("| n |".into()), "| n |");
        let cut = shown("é".repeat(RESULT_LIMIT + 5));
        assert!(cut.starts_with(&"é".repeat(RESULT_LIMIT)));
        assert!(cut.ends_with("[cut: 5 more characters; select fewer columns or rows]"));
    }
}
