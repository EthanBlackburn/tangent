//! What a person asked Claude Code, for a `macos` source: one line a
//! prompt. Endpoint Security shows what an agent ran, never why. The same
//! `aws` calls are a person's request or an injected instruction, and only
//! the prompt tells them apart. Claude Code writes every session to a
//! transcript, `~/.claude/projects/<project>/<session id>.jsonl`, and marks
//! the entries a person typed; it also keeps `~/.claude/sessions/<pid>.json`
//! for each running agent, which says whose session a process is. The
//! transcripts are followed, and each prompt is a line as it is typed:
//!
//! ```json
//! {"time": "...Z", "prompt": {"agent": "claude-code", "session": "<session id>",
//!  "cwd": "/Users/dev/code/x", "text": "look at our AWS spend", "pids": [4100]}}
//! ```
//!
//! `pids` is the agent's process, which is how the plugin places the prompt
//! in a session; a prompt of a session no running agent claims has none.
//!
//! A message typed while the agent is working is marked `during`: Claude
//! Code counts it as part of the turn under way, and so does the pack, which
//! cuts an agent's session at the prompts that start a turn.
//!
//! It starts with the latest three prompts of each session touched in the
//! last two hours, under their own times, since what an agent is doing now
//! was asked for before the capture began; then only what is appended is
//! read. Each prompt carries `after`, the end of what the agent last said
//! before it: "yes, the second one" says nothing alone. Nothing in Claude
//! Code's settings changes, and sessions already open are covered. The
//! transcript's format is Claude Code's own and may change with a release:
//! a line that cannot be read is skipped.

use std::collections::HashMap;
use std::fs::{self, File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use bytes::BytesMut;
use serde_json::{json, Map, Value};

/// How often the transcripts are looked at.
pub(super) const POLL: Duration = Duration::from_secs(1);

/// Enough of a prompt to say what was asked; a pasted file is not the
/// request.
const TEXT: usize = 4000;
/// What the agent last said before a prompt, which the prompt replies to.
/// Its start says what it was about and its end holds the question, so a
/// long one is sent as both.
const SAID_START: usize = 400;
const SAID_END: usize = 800;
/// A session touched this recently has its latest prompts sent at the start,
const RECENT: Duration = Duration::from_secs(2 * 3600);
/// this many of them.
const START: usize = 3;
/// How much of a transcript's end is searched for them.
const TAIL: u64 = 8 << 20;

/// What JSON calls nothing: absent, null, false, zero or empty.
fn set(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// What the person typed in a transcript entry, or `None`.
///
/// A prompt that starts a turn is an entry of type `user`, as are a tool's
/// result, a notice from the system and the agent's own prompt to a
/// subagent. A message typed while the agent is working never becomes one:
/// it is an `attachment` of type `queued_command`, as a finished task's
/// notice is too. `origin.kind` is `human` on what a person wrote, in both.
fn prompt(entry: &Value) -> Option<String> {
    let entry = entry.as_object()?;
    if ["isSidechain", "isMeta", "isCompactSummary"]
        .iter()
        .any(|flag| set(entry.get(*flag)))
    {
        return None;
    }
    let (origin, content) = match entry.get("type")?.as_str()? {
        "attachment" => {
            let held = entry.get("attachment")?.as_object()?;
            if held.get("type")?.as_str()? != "queued_command" {
                return None;
            }
            (held.get("origin"), held.get("prompt"))
        }
        "user" => (
            entry.get("origin"),
            entry.get("message").and_then(|m| m.get("content")),
        ),
        _ => return None,
    };
    if origin?.as_object()?.get("kind")?.as_str()? != "human" {
        return None;
    }
    let content = match content? {
        Value::String(text) => text.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .map(|block| block.get("text").and_then(Value::as_str).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => return None,
    };
    (!content.trim().is_empty()).then_some(content)
}

/// What the agent wrote to the person in a transcript entry, or `None`.
fn said(entry: &Value) -> Option<String> {
    let entry = entry.as_object()?;
    if entry.get("type")?.as_str()? != "assistant" || set(entry.get("isSidechain")) {
        return None;
    }
    entry
        .get("message")?
        .get("content")?
        .as_array()?
        .iter()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|block| block.get("text")?.as_str())
        .rfind(|text| !text.trim().is_empty())
        .map(str::to_string)
}

/// The pack's line for a typed entry, with what the agent last said before
/// it. `during` marks a message typed while the agent was working: it adds
/// to the turn under way and starts none, as Claude Code itself counts
/// turns.
fn line(entry: &Value, text: &str, pid: Option<u64>, after: Option<&str>) -> Value {
    let field = |name| entry.get(name).cloned().unwrap_or(Value::Null);
    let mut made = Map::new();
    made.insert("agent".into(), json!("claude-code"));
    made.insert("session".into(), field("sessionId"));
    made.insert("cwd".into(), field("cwd"));
    made.insert(
        "text".into(),
        json!(text.chars().take(TEXT).collect::<String>()),
    );
    if entry.get("type").and_then(Value::as_str) == Some("attachment") {
        made.insert("during".into(), json!(true));
    }
    if let Some(after) = after.filter(|after| !after.is_empty()) {
        let after: Vec<char> = after.trim().chars().collect();
        let after: String = if after.len() <= SAID_START + SAID_END {
            after.iter().collect()
        } else {
            let start: String = after[..SAID_START].iter().collect();
            let end: String = after[after.len() - SAID_END..].iter().collect();
            format!("{start} … {end}")
        };
        made.insert("after".into(), json!(after));
    }
    if let Some(pid) = pid.filter(|pid| *pid != 0) {
        made.insert("pids".into(), json!([pid]));
    }
    json!({"time": field("timestamp"), "prompt": made})
}

/// A typed entry, and what the agent last said before it.
type Typed = (Value, Option<String>);

/// The typed entries in a run of whole lines, each with what the agent last
/// said before it; `last` is what it last said, before the run and after.
fn read(data: &str, last: &mut Option<String>) -> Vec<Typed> {
    let mut found = Vec::new();
    for entry in entries(data) {
        if let Some(spoke) = said(&entry) {
            *last = Some(spoke);
        } else if prompt(&entry).is_some() {
            found.push((entry, last.clone()));
        }
    }
    found
}

/// The JSON values in a run of whole lines; what does not parse is skipped.
/// A line ends at a newline alone: a prompt may hold the other characters a
/// line is sometimes broken at (U+2028, U+0085), unescaped.
fn entries(data: &str) -> impl Iterator<Item = Value> + '_ {
    data.split('\n')
        .filter_map(|raw| serde_json::from_str(raw).ok())
}

/// The transcripts under a Claude Code home, read as they grow.
pub(super) struct Follower {
    projects: PathBuf,
    sessions: PathBuf,
    /// transcript -> bytes read
    at: HashMap<PathBuf, u64>,
    /// transcript -> the bytes of an unfinished line
    left: HashMap<PathBuf, Vec<u8>>,
    /// transcript -> what the agent last said
    last: HashMap<PathBuf, Option<String>>,
    started: bool,
}

impl Follower {
    /// `home` is Claude Code's, `~/.claude`.
    pub(super) fn new(home: &Path) -> Self {
        Self {
            projects: home.join("projects"),
            sessions: home.join("sessions"),
            at: HashMap::new(),
            left: HashMap::new(),
            last: HashMap::new(),
            started: false,
        }
    }

    /// Session id -> the pid of the running agent that holds it.
    fn pids(&self) -> HashMap<String, u64> {
        let Ok(sessions) = fs::read_dir(&self.sessions) else {
            return HashMap::new();
        };
        sessions
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .filter_map(|path| {
                let session: Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
                let pid = match session.get("pid")? {
                    Value::String(pid) => pid.trim().parse().ok()?,
                    pid => pid.as_u64()?,
                };
                Some((session.get("sessionId")?.as_str()?.to_string(), pid))
            })
            .collect()
    }

    /// Every transcript: `<project>/<session id>.jsonl`.
    fn transcripts(&self) -> Vec<(PathBuf, Metadata)> {
        let within = |dir: &Path| fs::read_dir(dir).into_iter().flatten().flatten();
        within(&self.projects)
            .map(|project| project.path())
            .filter(|project| project.is_dir())
            .flat_map(|project| within(&project).collect::<Vec<_>>())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
            .filter_map(|path| {
                let meta = fs::metadata(&path).ok().filter(Metadata::is_file)?;
                Some((path, meta))
            })
            .collect()
    }

    /// The last [`START`] typed entries in a transcript's end.
    fn latest(&mut self, path: &Path, size: u64) -> Vec<Typed> {
        let start = size.saturating_sub(TAIL);
        let Ok(mut data) = bytes(path, start, size - start) else {
            return Vec::new();
        };
        if start > 0 {
            // the first line is cut
            let whole = data.iter().position(|b| *b == b'\n').map_or(0, |nl| nl + 1);
            data.drain(..whole);
        }
        let mut last = None;
        let mut found = read(&String::from_utf8_lossy(&data), &mut last);
        self.last.insert(path.to_path_buf(), last);
        found.drain(..found.len().saturating_sub(START));
        found
    }

    /// The lines for what was typed since the last poll.
    pub(super) fn poll(&mut self, now: SystemTime) -> Vec<BytesMut> {
        let mut found = Vec::new();
        for (path, meta) in self.transcripts() {
            let size = meta.len();
            if !self.at.contains_key(&path) {
                if self.started {
                    // a session begun since: all of it
                    self.at.insert(path.clone(), 0);
                } else {
                    // one already there: its latest prompts, then what follows
                    self.at.insert(path.clone(), size);
                    let touched = meta
                        .modified()
                        .ok()
                        .and_then(|at| now.duration_since(at).ok());
                    if touched.unwrap_or_default() <= RECENT {
                        found.extend(self.latest(&path, size));
                    }
                    continue;
                }
            }
            if size < self.at[&path] {
                // rewritten
                self.at.insert(path.clone(), 0);
                self.left.remove(&path);
            }
            let at = self.at[&path];
            if size == at {
                continue;
            }
            let Ok(new) = bytes(&path, at, size - at) else {
                continue;
            };
            let mut data = self.left.remove(&path).unwrap_or_default();
            data.extend(new);
            self.at.insert(path.clone(), size);
            let whole = data
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |nl| nl + 1);
            let rest = data.split_off(whole);
            if !rest.is_empty() {
                self.left.insert(path.clone(), rest);
            }
            let last = self.last.entry(path).or_default();
            found.extend(read(&String::from_utf8_lossy(&data), last));
        }
        self.started = true;
        if found.is_empty() {
            return Vec::new();
        }
        let pids = self.pids();
        found.sort_by_cached_key(|(entry, _)| match entry.get("timestamp") {
            Some(Value::String(at)) => at.clone(),
            Some(at) => at.to_string(),
            None => String::new(),
        });
        found
            .iter()
            .filter_map(|(entry, after)| {
                let pid = entry
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .and_then(|s| pids.get(s));
                let made = line(entry, &prompt(entry)?, pid.copied(), after.as_deref());
                let mut made = BytesMut::from(made.to_string().as_bytes());
                made.extend_from_slice(b"\n");
                Some(made)
            })
            .collect()
    }
}

/// `len` bytes of a file from `start`, or as many as it has.
fn bytes(path: &Path, start: u64, len: u64) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(start))?;
    let mut data = Vec::new();
    file.take(len).read_to_end(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SESSION: &str = "00000000-0000-4000-8000-000000000001";

    fn typed(text: Value, at: &str) -> Value {
        json!({"type": "user", "origin": {"kind": "human"}, "sessionId": SESSION,
               "cwd": "/Users/dev/code/x", "timestamp": at,
               "message": {"role": "user", "content": text}})
    }

    fn with(mut entry: Value, key: &str, value: Value) -> Value {
        entry[key] = value;
        entry
    }

    fn spoke(text: &str) -> Value {
        json!({"type": "assistant", "message": {"content": [
            {"type": "text", "text": text},
            {"type": "tool_use", "name": "Bash", "input": {}}]}})
    }

    /// A Claude Code home with one transcript of `lines`, held by pid 4100.
    fn home(tmp: &Path, lines: &[Value]) -> PathBuf {
        let project = tmp.join("projects").join("-Users-dev-code-x");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(tmp.join("sessions")).unwrap();
        let path = project.join(format!("{SESSION}.jsonl"));
        append(
            &path,
            &lines.iter().map(|l| format!("{l}\n")).collect::<String>(),
        );
        let session = json!({"pid": 4100, "sessionId": SESSION});
        fs::write(tmp.join("sessions").join("4100.json"), session.to_string()).unwrap();
        path
    }

    fn append(path: &Path, text: &str) {
        let mut file = File::options()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    fn parsed(lines: &[BytesMut]) -> Vec<Value> {
        lines
            .iter()
            .map(|l| serde_json::from_slice(l).unwrap())
            .collect()
    }

    fn texts(lines: &[Value]) -> Vec<&str> {
        lines
            .iter()
            .map(|l| l["prompt"]["text"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn what_a_person_typed_is_a_prompt() {
        let asked = typed(json!("look at our AWS spend"), "t");
        assert_eq!(prompt(&asked).as_deref(), Some("look at our AWS spend"));
        let blocks = json!([{"type": "text", "text": "and"}, {"type": "text", "text": "this"}]);
        assert_eq!(prompt(&typed(blocks, "t")).as_deref(), Some("and\nthis"));
    }

    #[test]
    fn a_prompt_with_a_line_separator_in_it_is_one_line() {
        let line = typed(json!("first\u{2028}second\u{0085}third"), "t").to_string();
        assert!(line.contains('\u{2028}'), "written as it is, unescaped");
        assert_eq!(entries(&format!("{line}\n{line}\n")).count(), 2);
    }

    #[test]
    fn a_message_typed_while_the_agent_works_is_a_prompt() {
        let queued = json!({"type": "attachment", "sessionId": SESSION, "timestamp": "t",
            "attachment": {"type": "queued_command", "prompt": "and run the linter as well",
                           "origin": {"kind": "human"}, "commandMode": "prompt"}});
        assert_eq!(
            prompt(&queued).as_deref(),
            Some("and run the linter as well")
        );
        let made = line(&queued, "and run the linter as well", Some(1), None);
        assert_eq!(made["prompt"]["during"], json!(true));
        let made = line(&typed(json!("x"), "t"), "x", Some(1), None);
        assert_eq!(made["prompt"].get("during"), None);
        let notice = json!({"type": "attachment", "attachment": {
            "type": "queued_command", "prompt": "<task-notification>",
            "origin": {"kind": "task-notification"}}});
        assert_eq!(prompt(&notice), None);
        let other = json!({"type": "attachment",
            "attachment": {"type": "file", "origin": {"kind": "human"}}});
        assert_eq!(prompt(&other), None);
    }

    #[test]
    fn what_nobody_typed_is_not() {
        let result = json!({"type": "user",
            "message": {"content": [{"type": "tool_result", "content": "ok"}]}});
        let notice = with(
            typed(json!("<task-notification>"), "t"),
            "origin",
            json!({"kind": "task-notification"}),
        );
        let said = json!({"type": "assistant", "origin": {"kind": "human"},
            "message": {"content": "hi"}});
        for entry in [
            result,
            notice,
            with(
                typed(json!("to a subagent"), "t"),
                "isSidechain",
                json!(true),
            ),
            with(
                typed(json!("a summary"), "t"),
                "isCompactSummary",
                json!(true),
            ),
            typed(json!("  "), "t"),
            said,
            json!("a line that is no entry"),
        ] {
            assert_eq!(prompt(&entry), None, "{entry}");
        }
    }

    #[test]
    fn a_long_prompt_is_cut() {
        let made = line(&typed(json!("x"), "t"), &"x".repeat(10000), Some(1), None);
        assert_eq!(made["prompt"]["text"].as_str().unwrap().len(), TEXT);
    }

    #[test]
    fn a_long_reply_to_is_its_start_and_its_end() {
        let said = format!(
            "The build takes nine minutes. {} Which do you want first?",
            "x".repeat(5000)
        );
        let made = line(&typed(json!("x"), "t"), "the second", Some(1), Some(&said));
        let after = made["prompt"]["after"].as_str().unwrap();
        assert!(after.starts_with("The build takes nine minutes."));
        assert!(after.ends_with("Which do you want first?"));
        assert_eq!(after.chars().count(), SAID_START + SAID_END + 3);
    }

    #[test]
    fn a_session_already_open_gives_its_latest_prompts_then_what_follows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = home(
            tmp.path(),
            &[
                typed(json!("zero"), "t0"),
                typed(json!("first"), "t1"),
                spoke("The deny rule blocks it. Can you remove it?"),
                typed(json!("second"), "t2"),
                typed(json!("third"), "t3"),
            ],
        );
        let mut follower = Follower::new(tmp.path());
        let got = parsed(&follower.poll(SystemTime::now()));
        assert_eq!(texts(&got), ["first", "second", "third"]);
        assert_eq!(
            got[1],
            json!({"time": "t2", "prompt": {
                "agent": "claude-code", "session": SESSION, "cwd": "/Users/dev/code/x",
                "text": "second", "after": "The deny rule blocks it. Can you remove it?",
                "pids": [4100]}})
        );
        assert_eq!(got[0]["prompt"].get("after"), None);
        assert!(follower.poll(SystemTime::now()).is_empty());

        let fifth = typed(json!("fifth"), "t5").to_string();
        append(
            &path,
            &format!(
                "{}\n{}\n{}",
                spoke("Done. Anything else?"),
                typed(json!("fourth"), "t4"),
                &fifth[..20] // a line still being written
            ),
        );
        let got = parsed(&follower.poll(SystemTime::now()));
        assert_eq!(texts(&got), ["fourth"]);
        assert_eq!(got[0]["prompt"]["after"], json!("Done. Anything else?"));

        append(&path, &format!("{}\n", &fifth[20..]));
        let got = parsed(&follower.poll(SystemTime::now()));
        assert_eq!(texts(&got), ["fifth"]);
        // the agent has not spoken since: the same words came before it
        assert_eq!(got[0]["prompt"]["after"], json!("Done. Anything else?"));
    }

    #[test]
    fn an_old_session_is_left_alone_and_a_new_one_is_read_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let path = home(tmp.path(), &[typed(json!("long ago"), "t0")]);
        let mut follower = Follower::new(tmp.path());
        let later = SystemTime::now() + RECENT + Duration::from_secs(60);
        assert!(follower.poll(later).is_empty());

        let other = with(typed(json!("a"), "t1"), "sessionId", json!("other"));
        let again = with(typed(json!("b"), "t2"), "sessionId", json!("other"));
        let new = path.with_file_name("00000000-0000-4000-8000-000000000002.jsonl");
        append(&new, &format!("{other}\nnot json\n{again}\n"));
        let got = parsed(&follower.poll(SystemTime::now()));
        assert_eq!(texts(&got), ["a", "b"]);
        // no running agent claims that session
        assert_eq!(got[0]["prompt"].get("pids"), None);
    }

    #[test]
    fn a_home_that_is_not_there_gives_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let mut follower = Follower::new(&tmp.path().join("none"));
        assert!(follower.poll(SystemTime::now()).is_empty());
    }
}
