//! What `tangent watch` says while its pipeline runs: each minute how many
//! records the judge checked, each alert as the judge flags it (numbered `#1`,
//! `#2`, ... while it waits for review; the alerts one review will settle
//! are one number and one line, with their count), and each review as it
//! settles them (`cleared`, `MALICIOUS`, `ALERT`, or `REVIEW FAILED`). A review
//! that upholds its alert is a notification too, at a Mac ([`crate::notify`]).
//! It reads them where the pipeline writes them (alerts.ndjson, reviews.ndjson
//! and verdicts.ndjson, in the pipeline's directory), from where each file
//! ended when the watch began, so the runtime knows nothing of it and a
//! restart says nothing twice.
//!
//! The text of an alert and of a review was written by a model that had
//! read whatever an attacker put in a record. It goes to a terminal, so
//! every control character is taken out of it first: an escape sequence
//! there could rewrite what the lines above it say.

use std::io::{IsTerminal as _, Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::notify::{Note, Notifier};
use crate::status::{self, AlertSummary, Tracker};

/// How often the files are read for what is new.
const EVERY: Duration = Duration::from_secs(1);
/// The least time between two lines that say how many activities were checked.
const TALLY_EVERY: Duration = Duration::from_secs(60);
/// While reviews are pending, how often to print a progress update.
const PROGRESS_EVERY: Duration = Duration::from_secs(15);
/// The most of a model's text a settled review shows.
const SHOWN: usize = 600;
/// The most of the judge's text an unconfirmed Tier 1 line shows.
const BRIEF: usize = 100;

/// A human duration: `42s`, `5m 10s`, `1h 05m`.
fn span(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        let m = secs / 60;
        let s = secs % 60;
        if s == 0 {
            format!("{m}m")
        } else {
            format!("{m}m {s:02}s")
        }
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{h}h {m:02}m")
    }
}

fn activities(count: u64) -> String {
    if count == 1 {
        "1 activity".to_string()
    } else {
        format!("{count} activities")
    }
}

/// Terminal styling: ANSI escapes only on a TTY when `NO_COLOR` is unset, and
/// only around tangent's own labels, never around model or log text.
#[derive(Clone, Copy)]
struct Style {
    color: bool,
}

impl Style {
    fn detect() -> Self {
        Self {
            color: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }

    #[cfg(test)]
    fn plain() -> Self {
        Self { color: false }
    }

    fn wrap(self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn dim(self, text: &str) -> String {
        self.wrap("2", text)
    }

    fn yellow(self, text: &str) -> String {
        self.wrap("33", text)
    }

    fn bold_red(self, text: &str) -> String {
        self.wrap("1;31", text)
    }

    fn bold_yellow(self, text: &str) -> String {
        self.wrap("1;33", text)
    }

    fn bold(self, text: &str) -> String {
        self.wrap("1", text)
    }
}

/// A file read as it grows, a whole line at a time.
struct Tail {
    path: PathBuf,
    at: u64,
}

impl Tail {
    /// `path` from where it ends now: what is in it was said by another
    /// watch, or is nobody's to say.
    fn from_end(path: PathBuf) -> Self {
        let at = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Self { path, at }
    }

    /// The whole lines written since the last call. A line still being
    /// written is left for the next; a file that is not there yet has none;
    /// one that became shorter is read from its start.
    fn lines(&mut self) -> Vec<String> {
        let Ok(mut file) = std::fs::File::open(&self.path) else {
            return Vec::new();
        };
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if len < self.at {
            self.at = 0;
        }
        let mut new = Vec::new();
        if file.seek(SeekFrom::Start(self.at)).is_err() || file.read_to_end(&mut new).is_err() {
            return Vec::new();
        }
        let Some(end) = new.iter().rposition(|b| *b == b'\n') else {
            return Vec::new();
        };
        self.at += end as u64 + 1;
        String::from_utf8_lossy(&new[..end])
            .lines()
            .map(str::to_string)
            .collect()
    }
}

/// `text` as one line a terminal can be shown: control characters out, a
/// run of white space one space, and no more than [`SHOWN`] characters.
fn clean(text: &str) -> String {
    let plain: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let line = plain.split_whitespace().collect::<Vec<_>>().join(" ");
    match line.char_indices().nth(SHOWN) {
        Some((cut, _)) => format!("{}...", &line[..cut]),
        None => line,
    }
}

/// A short one-line preview of already-cleaned text for an unconfirmed Tier 1
/// line: the first sentence when short enough, else cut at [`BRIEF`] chars.
fn brief(text: &str) -> String {
    let first = text.find(". ").map(|i| &text[..=i]).unwrap_or(text);
    if first.chars().count() <= BRIEF {
        return first.to_string();
    }
    match text.char_indices().nth(BRIEF) {
        Some((cut, _)) => format!("{}...", text[..cut].trim_end()),
        None => text.to_string(),
    }
}

/// A field of a record as text, by its path: empty when it is not there.
fn text(record: &Value, path: &[&str]) -> String {
    let field = path.iter().try_fold(record, |at, key| at.get(key));
    match field {
        Some(Value::String(s)) => clean(s),
        Some(Value::Null) | None => String::new(),
        Some(other) => clean(&other.to_string()),
    }
}

/// When a record happened, to the minute: `03:09Z` for an RFC 3339 UTC time.
fn when(record: &Value) -> String {
    let ts = text(record, &["ts"]);
    match ts.get(11..16) {
        Some(minute) if ts.len() >= 16 && ts.as_bytes()[10] == b'T' && ts.ends_with('Z') => {
            format!("{minute}Z")
        }
        _ => ts,
    }
}

/// Who a record is about in full: the actor every cloud source names, or on a
/// Mac the session's entry path.
fn who(record: &Value) -> String {
    match text(record, &["_norm", "actor"]) {
        actor if actor.is_empty() => text(record, &["session", "entry"]),
        actor => actor,
    }
}

/// Short display name for a terminal line: on a Mac the program's basename
/// (`Python`, `tmux`, `agent`) instead of a full Homebrew/app path; in the
/// cloud the actor.
fn subject(record: &Value) -> String {
    let entry = text(record, &["session", "entry"]);
    if !entry.is_empty() {
        return match entry.rsplit('/').next() {
            Some(program) if !program.is_empty() => program.to_string(),
            _ => entry,
        };
    }
    who(record)
}

/// How an alert and the review that settles it are matched.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReviewKey {
    Mac {
        id: String,
        window: String,
        entry: String,
    },
    Cloud {
        org: String,
        actor: String,
    },
}

fn review_key(record: &Value) -> ReviewKey {
    if record.get("session").is_some() {
        ReviewKey::Mac {
            id: text(record, &["session", "id"]),
            window: text(record, &["session", "window"]),
            entry: text(record, &["session", "entry"]),
        }
    } else {
        ReviewKey::Cloud {
            org: text(record, &["_norm", "org"]),
            actor: text(record, &["_norm", "actor"]),
        }
    }
}

/// What waits for one review: the alerts of one key, under one number.
#[derive(Debug)]
struct Waiting {
    key: ReviewKey,
    id: u64,
    /// When the first of them was raised.
    since: Instant,
    alerts: u64,
}

/// Formats matched alert IDs (`#1`, `#1, #2`, `#1-#3`), or empty when none.
fn format_ids(ids: &[u64]) -> String {
    match ids {
        [] => String::new(),
        [only] => format!("#{only}"),
        [first, .., last] if ids.len() >= 3 && ids.windows(2).all(|w| w[1] == w[0] + 1) => {
            format!("#{first}-#{last}")
        }
        many => many
            .iter()
            .map(|id| format!("#{id}"))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// An unconfirmed Tier 1 alert as one compact line while the reviewer works on
/// it. Full details wait for the settled review.
fn alert(record: &Value, id: u64, style: Style) -> Vec<String> {
    let mark = match text(record, &["judge", "warrants_investigation"]).as_str() {
        "look" => "look   ",
        _ => "flagged",
    };
    let why = match text(record, &["judge", "why"]) {
        why if why.is_empty() => text(record, &["judge", "assessment"]),
        why => why,
    };
    let summary = brief(&why);
    let mac = record.get("session").is_some() || text(record, &["source"]) == "macos_session";
    let who = if mac {
        subject(record)
    } else {
        match text(record, &["source"]) {
            source if source.is_empty() => subject(record),
            source => format!("{source}  {}", subject(record)),
        }
    };
    let tag = style.dim(&format!("#{id}"));
    let time = style.dim(&when(record));
    let badge = style.yellow(mark);
    let status = style.dim("(reviewing)");
    let line = if summary.is_empty() {
        format!("{tag}  {time}  {badge}  {who}  {status}")
    } else {
        format!("{tag}  {time}  {badge}  {who}  {summary}  {status}")
    };
    vec![line]
}

/// Whether a record of reviews.ndjson is a review to say. A cloud
/// pipeline's review covers an actor's alerts and is on each of them: it is
/// said from the first, which carries `reviewed`, and the others say
/// nothing more. A Mac's is a record of its own for each alert.
fn says_a_review(record: &Value) -> bool {
    record.get("reviewed").is_some() || text(record, &["source"]) == "macos_review"
}

/// A settled Tier 2 review: one quiet line when cleared (`benign`), or a
/// standout multi-line block with `finding` and `check:` when upheld or failed.
fn review(record: &Value, ids: &[u64], style: Style) -> Vec<String> {
    if !says_a_review(record) {
        return Vec::new();
    }
    let prefix = match format_ids(ids) {
        id if id.is_empty() => String::new(),
        id => format!("{}  ", style.dim(&id)),
    };
    let about = record.get("reviewed");
    let who = subject(record);
    let alerts = match about.and_then(|a| a.get("alerts")).and_then(Value::as_u64) {
        Some(1) => " (1 alert)".to_string(),
        Some(n) => format!(" ({n} alerts)"),
        None => String::new(),
    };
    let error = text(record, &["review", "error"]);
    if !error.is_empty() {
        return vec![
            String::new(),
            format!(
                "{prefix}{}  {who}{alerts} — judge's mark stands",
                style.bold_yellow("REVIEW FAILED")
            ),
            format!("    {error}"),
        ];
    }
    let verdict = text(record, &["review", "verdict"]);
    let finding = text(record, &["review", "finding"]);
    let check = text(record, &["review", "check"]);

    if verdict == "benign" {
        let label = style.dim("cleared");
        let note = style.dim(&brief(&finding));
        return vec![format!("{prefix}{label}  {who}{alerts}  {note}")];
    }

    let label = match verdict.as_str() {
        "malicious" => style.bold_red("MALICIOUS"),
        "unresolved" => style.bold_red("ALERT"),
        other => style.bold(&other.to_uppercase()),
    };
    let mut lines = vec![
        String::new(),
        format!("{prefix}{label}  {}", style.bold(&format!("{who}{alerts}"))),
    ];
    if !finding.is_empty() {
        lines.push(format!("    {finding}"));
    }
    if !check.is_empty() {
        lines.push(format!("    {} {check}", style.bold("check:")));
    }
    lines
}

/// A review, as the notification it is when it upholds its alert:
/// `malicious` with a sound, `unresolved` without. A review that clears
/// its alert has none, nor has one that failed, nor the judge's mark
/// before its review: a notification is for what a person should look at,
/// and those are said in the terminal. Behind its click is the finding
/// whole, what to check, and where the review is kept, in `dir`.
///
/// A Mac's asks whether the session was its reader's doing, and the answer
/// is a line of feedback.ndjson in `dir`: the session, the judge's mark,
/// the verdict and the review's time, which with the session says which
/// review it answers. A cloud review is about someone else's account, and
/// asks nothing.
fn note(record: &Value, dir: &Path) -> Option<Note> {
    if !says_a_review(record) {
        return None;
    }
    let (title, sound) = match text(record, &["review", "verdict"]).as_str() {
        "malicious" => ("Tangent: malicious activity", true),
        "unresolved" => ("Tangent: needs a look", false),
        _ => return None,
    };
    // A Mac's review is about a session; a cloud's, an actor in a log.
    let mac = text(record, &["source"]) == "macos_review";
    let subtitle = match text(record, &["source"]) {
        source if source.is_empty() || mac => who(record),
        source => format!("{} ({source})", who(record)),
    };
    let finding = text(record, &["review", "finding"]);
    let mut detail = vec![finding.clone()];
    let check = text(record, &["review", "check"]);
    if !check.is_empty() {
        detail.push(format!("Check: {check}"));
    }
    detail.push(format!(
        "The review is kept in {}",
        dir.join("reviews.ndjson").display()
    ));
    let answer = || {
        json!({
            "source": "macos_feedback",
            "session": record.get("session"),
            "judge": record.pointer("/judge/warrants_investigation"),
            "review": record.pointer("/review/verdict"),
            "reviewed": record.get("ts"),
        })
    };
    Some(Note {
        title: title.to_string(),
        subtitle,
        body: finding,
        detail: detail.join("\n\n"),
        sound,
        feedback: mac.then(|| (dir.join("feedback.ndjson"), answer())),
    })
}

/// What the pipeline in a directory has written, said as it is written.
pub struct Follow {
    /// The directory the pipeline writes in.
    dir: PathBuf,
    alerts: Tail,
    reviews: Tail,
    verdicts: Tail,
    judged: u64,
    flagged: u64,
    /// Judged records and flags since the last heartbeat line.
    checked: u64,
    marked: u64,
    /// The last number given (`#1`, `#2`, ...), and what still awaits a
    /// settled review.
    next_id: u64,
    pending: Vec<Waiting>,
    /// How long the pipeline holds an alert before the reviewer starts it.
    review_wait: Option<Duration>,
    /// When the last heartbeat / progress line was said.
    told: Instant,
    /// Terminal styling (plain in tests and when stdout is not a TTY).
    style: Style,
    /// The reviews to show as notifications, not yet handed to `notifier`,
    /// which is there when this watch shows any.
    notes: Vec<Note>,
    notifier: Option<Notifier>,
    /// Upheld reviews collected since the last `status.json` flush.
    new_alerts: Vec<AlertSummary>,
    /// The seconds from each alert of this run being flagged to its
    /// review's verdict, its wait for a reviewer included.
    reviewed: Vec<f64>,
    /// When the ledger was last added to.
    began: Instant,
    /// What the models were asked and what it cost, by the hour.
    ledger: status::Ledger,
    /// The run's cost, tokens and sessions checked as last added to it.
    counted: (f64, f64, f64),
    /// The same for the alerts the review being read settles.
    settled: Vec<f64>,
    /// What each model last said of its credentials: the judge's, then the
    /// reviewer's. They are kept apart because they are two models, and one
    /// can be refused while the other is let in: the judge's clean call does
    /// not clear what the reviewer was refused for. `status.json` has the
    /// reviewer's when both are refused.
    judge_auth: Option<String>,
    review_auth: Option<String>,
    /// Whether the judge has answered since the status was last written:
    /// what its request was refused for while it was tried again is over.
    judge_answered: bool,
    status: Option<Tracker>,
}

impl Follow {
    pub fn new(
        dir: &Path,
        notifier: Option<Notifier>,
        review_wait: Option<Duration>,
        status: Option<Tracker>,
    ) -> Self {
        Self::with_style(dir, notifier, review_wait, status, Style::detect())
    }

    fn with_style(
        dir: &Path,
        notifier: Option<Notifier>,
        review_wait: Option<Duration>,
        status: Option<Tracker>,
        style: Style,
    ) -> Self {
        Self {
            dir: dir.to_path_buf(),
            alerts: Tail::from_end(dir.join("alerts.ndjson")),
            reviews: Tail::from_end(dir.join("reviews.ndjson")),
            verdicts: Tail::from_end(dir.join("verdicts.ndjson")),
            judged: 0,
            flagged: 0,
            checked: 0,
            marked: 0,
            next_id: 0,
            pending: Vec::new(),
            review_wait,
            told: Instant::now(),
            style,
            notes: Vec::new(),
            notifier,
            new_alerts: Vec::new(),
            reviewed: Vec::new(),
            began: Instant::now(),
            ledger: status::Ledger::open(dir),
            counted: (0.0, 0.0, 0.0),
            settled: Vec::new(),
            judge_auth: None,
            review_auth: None,
            judge_answered: false,
            status,
        }
    }

    /// The numbers in `pending` that `record` settles, each taken out once
    /// all its alerts are settled: a review that covers some of an actor's
    /// alerts leaves the rest waiting under their number.
    fn resolve(&mut self, record: &Value) -> Vec<u64> {
        let key = review_key(record);
        let mut matched = Vec::new();
        match key {
            ReviewKey::Mac { id, window, entry } => {
                let exact = !id.is_empty() && !window.is_empty();
                let mut rest = Vec::with_capacity(self.pending.len());
                for waiting in self.pending.drain(..) {
                    let hit = match &waiting.key {
                        ReviewKey::Mac {
                            id: pid,
                            window: pw,
                            ..
                        } if exact => pid == &id && pw == &window,
                        ReviewKey::Mac {
                            id: pid, entry: pe, ..
                        } if !id.is_empty() => pid == &id && pe == &entry,
                        ReviewKey::Mac { entry: pe, .. } => pe == &entry && matched.is_empty(),
                        _ => false,
                    };
                    if hit {
                        matched.push(waiting.id);
                        self.settled.push(waiting.since.elapsed().as_secs_f64());
                    } else {
                        rest.push(waiting);
                    }
                }
                self.pending = rest;
            }
            key @ ReviewKey::Cloud { .. } => {
                // how many alerts the review covered; all that wait, if it
                // does not say
                let mut left = record.pointer("/reviewed/alerts").and_then(Value::as_u64);
                for waiting in self.pending.iter_mut().filter(|w| w.key == key) {
                    let settled = left.map_or(waiting.alerts, |left| left.min(waiting.alerts));
                    if settled > 0 {
                        waiting.alerts -= settled;
                        matched.push(waiting.id);
                    }
                    left = left.map(|left| left - settled);
                }
                self.pending.retain(|w| w.alerts > 0);
            }
        }
        matched
    }

    /// Progress for each pending review: countdown while held, elapsed
    /// investigation time once past the hold, and how many alerts it has
    /// when more than one.
    fn progress(&self, now: Instant) -> String {
        let items: Vec<String> = self
            .pending
            .iter()
            .map(|waiting| {
                let elapsed = now.saturating_duration_since(waiting.since);
                let state = match self.review_wait {
                    Some(wait) if elapsed < wait => {
                        let left = wait.saturating_sub(elapsed);
                        if left.as_secs() >= 5 {
                            format!("starts in ~{}", span(left))
                        } else {
                            "starting".to_string()
                        }
                    }
                    Some(wait) => {
                        let active = elapsed.saturating_sub(wait);
                        format!("investigating {}", span(active))
                    }
                    None => format!("reviewing {}", span(elapsed)),
                };
                match waiting.alerts {
                    1 => format!("#{} ({state})", waiting.id),
                    alerts => format!("#{} ({alerts} alerts, {state})", waiting.id),
                }
            })
            .collect();
        format!("reviewing {}", items.join(", "))
    }

    /// The heartbeat line for what was judged since the last one, and live
    /// progress on any alerts still awaiting review.
    fn tally(&mut self, at: Instant) -> String {
        let count = std::mem::take(&mut self.checked);
        let flagged = std::mem::take(&mut self.marked);
        self.told = at;
        let line = if count > 0 {
            let mark = match flagged {
                0 => "all clear".to_string(),
                n => format!("{n} flagged"),
            };
            let mut s = format!("checked {} · {mark}", activities(count));
            if !self.pending.is_empty() {
                s.push_str(&format!(" · {}", self.progress(at)));
            }
            s
        } else {
            self.progress(at)
        };
        self.style.dim(&line)
    }

    /// The lines for what was written since the last call. `now` asks for
    /// what was checked to be said however lately it was.
    fn said(&mut self, now: bool) -> Vec<String> {
        let at = Instant::now();
        let mut lines = Vec::new();
        let parsed = |line: String| serde_json::from_str::<Value>(&line).ok();
        for record in self.verdicts.lines().into_iter().filter_map(parsed) {
            self.judged += 1;
            self.checked += 1;
            let err = text(&record, &["judge", "error"]);
            if !err.is_empty() {
                if status::looks_like_auth_error(&err) {
                    self.judge_auth = Some(err);
                }
            } else if record.get("judge").is_some() {
                self.judge_auth = None;
                self.judge_answered = true;
            }
        }
        let alerts: Vec<Value> = self.alerts.lines().into_iter().filter_map(parsed).collect();
        self.flagged += alerts.len() as u64;
        self.marked += alerts.len() as u64;
        for record in &alerts {
            // One line for what one review will settle: an alert whose
            // actor has alerts waiting is counted with them, so a burst of
            // a hundred is a number that grows and not a hundred lines.
            let key = review_key(record);
            if let Some(waiting) = self.pending.iter_mut().find(|w| w.key == key) {
                waiting.alerts += 1;
                continue;
            }
            self.next_id += 1;
            let id = self.next_id;
            self.pending.push(Waiting {
                key,
                id,
                since: at,
                alerts: 1,
            });
            lines.extend(alert(record, id, self.style));
        }
        for record in self.reviews.lines().into_iter().filter_map(parsed) {
            if !says_a_review(&record) {
                continue;
            }
            let rev_err = text(&record, &["review", "error"]);
            let answered = rev_err.is_empty();
            if !rev_err.is_empty() {
                if status::looks_like_auth_error(&rev_err) {
                    self.review_auth = Some(rev_err);
                }
            } else {
                self.review_auth = None;
            }
            self.settled.clear();
            let ids = self.resolve(&record);
            // an alert of this run whose review gave a verdict: one from
            // before it was not seen flagged, and has no time to count
            if answered {
                self.reviewed.extend(self.settled.drain(..));
            }
            lines.extend(review(&record, &ids, self.style));
            self.notes.extend(note(&record, &self.dir));
            self.new_alerts
                .extend(AlertSummary::from_review(&record, &self.dir));
        }
        let elapsed = at.saturating_duration_since(self.told);
        let due = if self.pending.is_empty() {
            self.checked > 0 && (now || elapsed >= TALLY_EVERY)
        } else {
            (self.checked > 0 && now) || elapsed >= PROGRESS_EVERY
        };
        if due {
            lines.push(self.tally(at));
        }
        lines
    }

    /// Says the lines for what was written since the last call, and hands
    /// its notifications on.
    fn say(&mut self, now: bool) {
        for line in self.said(now) {
            println!("{line}");
        }
        if let Some(status) = &self.status {
            // the judge's from the runtime's own count of its requests
            let nodes = [
                ("judge", tangent_runtime::inference_totals("judge")),
                ("reviewer", tangent_runtime::inference_totals("reviewer")),
            ];
            // what was spent and checked since the last time, to the hour
            let now = (
                nodes.iter().map(|(_, t)| t.cost).sum::<f64>(),
                nodes.iter().map(|(_, t)| t.tokens.all()).sum::<u64>() as f64,
                self.judged as f64,
            );
            let hour = status::hour_now();
            self.ledger.add(
                hour,
                now.0 - self.counted.0,
                now.1 - self.counted.1,
                now.2 - self.counted.2,
                self.began.elapsed().as_secs_f64(),
            );
            self.counted = now;
            self.began = Instant::now();
            status.set_usage(status::usage(&nodes, &self.ledger.day(hour)));
            status.set_timing(
                status::percentiles(&tangent_runtime::inference_recent("judge")),
                status::percentiles(&self.reviewed),
            );
            status.set_underway(status::underway(
                &tangent_runtime::underway::underway(),
                "macos_sessions",
                "judge",
            ));
            let alerts = std::mem::take(&mut self.new_alerts);
            status.update(self.judged, self.flagged, self.pending.len() as u64, alerts);
            // It writes nothing when this is what the file already has.
            status.set_auth_error(self.review_auth.clone().or_else(|| self.judge_auth.clone()));
            if std::mem::take(&mut self.judge_answered) {
                status.set_refused(None);
            }
        } else {
            self.new_alerts.clear();
        }
        for note in self.notes.drain(..) {
            if let Some(notifier) = &self.notifier {
                notifier.show(note);
            }
        }
    }

    /// Says what is written, as it is written, until `stop`; then what the
    /// pipeline wrote as it stopped, and the count.
    pub async fn run(mut self, mut stop: oneshot::Receiver<()>) {
        let mut tick = tokio::time::interval(EVERY);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = &mut stop => break,
            }
            self.say(false);
        }
        self.say(true);
        if let Some(notifier) = self.notifier.take() {
            notifier.end().await;
        }
        // A pipeline with no judge has nothing to count.
        if self.judged > 0 {
            let mut summary = format!(
                "judged {} since this watch began, {} flagged",
                self.judged, self.flagged
            );
            if !self.pending.is_empty() {
                summary.push_str(&format!(" ({} still in review)", self.pending.len()));
            }
            println!("{}", self.style.dim(&summary));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write as _;

    fn append(path: &Path, text: &str) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    /// A file is read from where it ended, a whole line at a time: what
    /// was there is not said again, and half a line waits for its end.
    #[test]
    fn a_file_is_read_as_it_grows_by_whole_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerts.ndjson");
        let mut absent = Tail::from_end(path.clone());
        assert!(absent.lines().is_empty(), "no file yet");
        append(&path, "old\n");
        assert_eq!(absent.lines(), ["old"], "it was not there at the start");

        let mut tail = Tail::from_end(path.clone());
        assert!(tail.lines().is_empty(), "what was there is not new");
        append(&path, "one\ntwo\nthr");
        assert_eq!(tail.lines(), ["one", "two"]);
        assert!(tail.lines().is_empty());
        append(&path, "ee\n");
        assert_eq!(tail.lines(), ["three"]);

        std::fs::write(&path, "again\n").unwrap();
        assert_eq!(tail.lines(), ["again"], "a shorter file is read anew");
    }

    /// Nothing a record holds reaches the terminal as a control character:
    /// an escape sequence, a carriage return and a new line are spaces.
    #[test]
    fn a_models_text_cannot_write_to_the_terminal() {
        let said = clean("ok\x1b[2J\x1b[1;1H all clear\r\nflagged   nothing\x07\u{9b}31m");
        assert!(!said.chars().any(char::is_control), "{said:?}");
        assert_eq!(said, "ok [2J [1;1H all clear flagged nothing 31m");
        let long = clean(&"é".repeat(SHOWN + 50));
        assert_eq!(long.chars().count(), SHOWN + 3);

        let record = json!({
            "ts": "2026-11-24T03:09:43Z", "source": "okta\x1b[0m",
            "_norm": {"actor": "eve\nreviewed  eve: benign"},
            "judge": {"flag": true, "why": "a sign-in\x1b]0;title\x07 from Tor"},
        });
        let lines = alert(&record, 1, Style::plain());
        assert_eq!(lines.len(), 1, "an actor's name cannot start a line");
        assert!(
            lines.iter().all(|l| !l.chars().any(char::is_control)),
            "{lines:?}"
        );
    }

    #[test]
    fn an_alert_is_one_compact_line_with_id_and_reviewing_status() {
        let record = json!({
            "ts": "2026-11-24T03:09:43Z", "source": "okta",
            "_norm": {"actor": "ana@acme.example"},
            "judge": {"flag": true, "why": "a sign-in from a Tor exit. Check everything else too."},
        });
        assert_eq!(
            alert(&record, 1, Style::plain()),
            ["#1  03:09Z  flagged  okta  ana@acme.example  a sign-in from a Tor exit.  (reviewing)"]
        );
    }

    /// A review is said once, from the alert that carries `reviewed`: benign
    /// is one quiet `cleared` line, upheld verdicts expand with finding and
    /// check, and a failed one says the judge's mark stands.
    #[test]
    fn a_review_is_said_once_for_its_alerts() {
        let first = json!({
            "_norm": {"actor": "ana@acme.example"},
            "review": {"verdict": "malicious", "finding": "She made a key.", "check": "Revoke it."},
            "reviewed": {"alerts": 3},
        });
        assert_eq!(
            review(&first, &[1, 2, 3], Style::plain()),
            [
                "",
                "#1-#3  MALICIOUS  ana@acme.example (3 alerts)",
                "    She made a key.",
                "    check: Revoke it."
            ]
        );
        let mut next = first.clone();
        next.as_object_mut().unwrap().remove("reviewed");
        assert!(review(&next, &[], Style::plain()).is_empty());

        let benign = json!({
            "_norm": {"actor": "ci"},
            "review": {"verdict": "benign", "finding": "A deploy."},
            "reviewed": {"alerts": 1},
        });
        assert_eq!(
            review(&benign, &[4], Style::plain()),
            ["#4  cleared  ci (1 alert)  A deploy."]
        );
        let failed = json!({
            "_norm": {"actor": "ci"},
            "review": {"error": "no reply"},
            "reviewed": {"alerts": 2},
        });
        assert_eq!(
            review(&failed, &[5, 6], Style::plain()),
            [
                "",
                "#5, #6  REVIEW FAILED  ci (2 alerts) — judge's mark stands",
                "    no reply"
            ]
        );
    }

    /// A Mac's alert uses the program's basename (not a 100-char Homebrew
    /// path), drops `macos_session`, and correlates with its review by
    /// session id and window.
    #[test]
    fn a_macs_alert_and_review_correlate_with_short_names() {
        let dir = tempfile::tempdir().unwrap();
        let mut follow = Follow::with_style(dir.path(), None, None, None, Style::plain());
        let look = json!({
            "ts": "2026-11-24T03:09:43Z", "source": "macos_session",
            "_norm": {"actor": "/opt/homebrew/Cellar/python@3.15/Python#501"},
            "session": {"id": "501", "window": "2026-11-24T03:05", "entry": "/opt/homebrew/Cellar/python@3.15/Python"},
            "judge": {"warrants_investigation": "look", "assessment": "An agent read a key.", "so_far": "..."},
        });
        append(&dir.path().join("verdicts.ndjson"), &format!("{look}\n"));
        append(&dir.path().join("alerts.ndjson"), &format!("{look}\n"));
        assert_eq!(
            follow.said(false),
            ["#1  03:09Z  look     Python  An agent read a key.  (reviewing)"]
        );
        assert_eq!(
            follow.said(true),
            ["checked 1 activity · 1 flagged · reviewing #1 (reviewing 0s)"],
            "heartbeat shows activities and pending review progress"
        );

        let reviewed = json!({
            "ts": "2026-11-24T03:17:00Z", "source": "macos_review",
            "session": {"id": "501", "window": "2026-11-24T03:05", "entry": "/opt/homebrew/Cellar/python@3.15/Python"},
            "judge": {"warrants_investigation": "look"},
            "review": {"verdict": "unresolved", "finding": "It read a key and connected out.", "check": "Rotate the key."},
        });
        append(&dir.path().join("reviews.ndjson"), &format!("{reviewed}\n"));
        assert_eq!(
            follow.said(false),
            [
                "",
                "#1  ALERT  Python",
                "    It read a key and connected out.",
                "    check: Rotate the key."
            ]
        );
        assert!(follow.pending.is_empty(), "review cleared the pending slot");
    }

    /// A review that upholds its alert is a notification: `malicious` with
    /// a sound and `unresolved` without, about the session or the actor,
    /// with the finding, what to check and where the review is kept behind
    /// the click. A Mac's asks whose doing it was, and says where the
    /// answer goes and as what. One that clears the alert, one that failed,
    /// and a cloud alert that only repeats its actor's review are none.
    #[test]
    fn a_review_that_upholds_its_alert_is_a_notification() {
        let kept = Path::new("/w");
        let mac = json!({
            "ts": "2026-11-24T03:17:00Z",
            "source": "macos_review", "session": {"id": "501", "entry": "~/bin/agent"},
            "judge": {"warrants_investigation": "flag"},
            "review": {"verdict": "unresolved", "finding": "It read a key and connected out.", "check": "Rotate the key."},
        });
        assert_eq!(
            note(&mac, kept),
            Some(Note {
                title: "Tangent: needs a look".to_string(),
                subtitle: "~/bin/agent".to_string(),
                body: "It read a key and connected out.".to_string(),
                detail: "It read a key and connected out.\n\nCheck: Rotate the key.\n\nThe review is kept in /w/reviews.ndjson".to_string(),
                sound: false,
                feedback: Some((
                    PathBuf::from("/w/feedback.ndjson"),
                    json!({
                        "source": "macos_feedback",
                        "session": {"id": "501", "entry": "~/bin/agent"},
                        "judge": "flag", "review": "unresolved",
                        "reviewed": "2026-11-24T03:17:00Z",
                    })
                )),
            })
        );
        let cloud = json!({
            "source": "okta", "_norm": {"actor": "ana@acme.example"},
            "review": {"verdict": "malicious", "finding": "She made a key."},
            "reviewed": {"alerts": 3},
        });
        let shown = note(&cloud, kept).unwrap();
        assert_eq!(shown.title, "Tangent: malicious activity");
        assert_eq!(shown.subtitle, "ana@acme.example (okta)");
        assert_eq!(
            shown.detail,
            "She made a key.\n\nThe review is kept in /w/reviews.ndjson"
        );
        assert!(shown.sound);
        assert_eq!(shown.feedback, None, "it is about someone else's account");

        let mut repeated = cloud.clone();
        repeated.as_object_mut().unwrap().remove("reviewed");
        assert_eq!(note(&repeated, kept), None);
        for review in [
            json!({"verdict": "benign", "finding": "A deploy."}),
            json!({"error": "no reply"}),
            json!({"verdict": "malicious\u{1b}[0m", "finding": "x"}),
        ] {
            let mut none = mac.clone();
            none["review"] = review;
            assert_eq!(note(&none, kept), None, "{none}");
        }

        // The text is a model's: no control character reaches the banner.
        let mut odd = mac.clone();
        odd["review"]["finding"] = json!("ok\u{1b}[2J\nall clear\u{7}");
        let shown = note(&odd, kept).unwrap();
        assert_eq!(shown.body, "ok [2J all clear");
    }

    /// What a pipeline writes is said as it is written, and its reviews
    /// that are notifications are held to hand on.
    #[test]
    fn a_pipelines_notifications_are_handed_on() {
        let dir = tempfile::tempdir().unwrap();
        let mut follow = Follow::with_style(dir.path(), None, None, None, Style::plain());
        let review = |verdict: &str| {
            json!({"source": "macos_review", "session": {"entry": "~/bin/agent"},
                "review": {"verdict": verdict, "finding": "It ran."}})
        };
        append(
            &dir.path().join("reviews.ndjson"),
            &format!("{}\n{}\n", review("benign"), review("malicious")),
        );
        assert_eq!(
            follow.said(false),
            [
                "cleared  agent  It ran.",
                "",
                "MALICIOUS  agent",
                "    It ran."
            ],
            "cleared is one quiet line; malicious is a multi-line block"
        );
        assert_eq!(follow.notes.len(), 1);
        assert_eq!(follow.notes[0].title, "Tangent: malicious activity");
    }

    /// Heartbeat stays quiet until its turn (`now` or 60s), and does not
    /// spam daemon names or fire on every individual alert.
    #[test]
    fn what_the_pipeline_writes_is_said() {
        let dir = tempfile::tempdir().unwrap();
        append(&dir.path().join("verdicts.ndjson"), "{}\n");
        let mut follow = Follow::with_style(dir.path(), None, None, None, Style::plain());
        assert!(follow.said(true).is_empty(), "nothing new, nothing said");

        let session = |entry: &str| json!({"session": {"entry": entry}}).to_string();
        append(
            &dir.path().join("verdicts.ndjson"),
            &format!(
                "{}\n{}\n{}\n",
                session("/bin/zsh"),
                session("/usr/libexec/xpcproxy"),
                session("/usr/libexec/xpcproxy")
            ),
        );
        assert!(follow.said(false).is_empty(), "the count waits its turn");
        assert_eq!(follow.said(true), ["checked 3 activities · all clear"]);
        assert!(
            follow.said(true).is_empty(),
            "what was checked is said once"
        );

        let flagged = json!({"ts": "2026-11-24T03:09:43Z", "source": "okta",
            "_norm": {"actor": "ana"}, "judge": {"why": "odd"}});
        append(&dir.path().join("verdicts.ndjson"), &format!("{flagged}\n"));
        append(
            &dir.path().join("alerts.ndjson"),
            &format!("{flagged}\nnot json\n"),
        );
        assert_eq!(
            follow.said(false),
            ["#1  03:09Z  flagged  okta  ana  odd  (reviewing)"],
            "an alert prints immediately without dumping a noisy checked line"
        );
        assert_eq!(
            follow.said(true),
            ["checked 1 activity · 1 flagged · reviewing #1 (reviewing 0s)"]
        );
    }

    #[test]
    fn review_progress_shows_hold_countdown_then_investigating_elapsed() {
        let dir = tempfile::tempdir().unwrap();
        let wait = Duration::from_secs(60);
        let mut follow = Follow::with_style(dir.path(), None, Some(wait), None, Style::plain());
        let now = Instant::now();
        let key = ReviewKey::Mac {
            id: "1".into(),
            window: "w".into(),
            entry: "tmux".into(),
        };
        let waiting = |id, ago, alerts| Waiting {
            key: key.clone(),
            id,
            since: now - Duration::from_secs(ago),
            alerts,
        };
        follow.pending.push(waiting(1, 75, 1));
        follow.pending.push(waiting(2, 20, 12));
        assert_eq!(
            follow.progress(now),
            "reviewing #1 (investigating 15s), #2 (12 alerts, starts in ~40s)"
        );
    }

    #[test]
    fn brief_stops_at_first_sentence_or_caps_length() {
        assert_eq!(
            brief("First sentence. Second sentence with more detail."),
            "First sentence."
        );
        let long = "a".repeat(BRIEF + 20);
        let cut = brief(&long);
        assert_eq!(cut.chars().count(), BRIEF + 3);
        assert!(cut.ends_with("..."));
    }

    /// An actor's alerts that wait for one review are one line and one
    /// number, however many they are; another actor's are their own.
    #[test]
    fn cloud_reviews_correlate_multiple_alerts_for_same_actor() {
        let dir = tempfile::tempdir().unwrap();
        let mut follow = Follow::with_style(dir.path(), None, None, None, Style::plain());
        let mk = |why: &str| {
            json!({
                "ts": "2026-11-24T03:09:43Z", "source": "okta",
                "_norm": {"org": "acme", "actor": "ana@acme.example"},
                "judge": {"flag": true, "why": why},
            })
        };
        let mut other = mk("c");
        other["_norm"]["actor"] = json!("ci");
        append(
            &dir.path().join("alerts.ndjson"),
            &format!("{}\n{}\n{other}\n", mk("a"), mk("b")),
        );
        let first = follow.said(false);
        assert_eq!(first.len(), 2, "{first:?}");
        assert!(first[0].starts_with("#1  ") && first[0].contains("ana@acme.example"));
        assert!(first[1].starts_with("#2  ") && first[1].contains("ci"));
        // a third of hers, a second later, is counted and not said
        append(&dir.path().join("alerts.ndjson"), &format!("{}\n", mk("d")));
        assert!(follow.said(false).is_empty());
        assert_eq!(
            follow.progress(Instant::now()),
            "reviewing #1 (3 alerts, reviewing 0s), #2 (reviewing 0s)"
        );
        assert_eq!(follow.flagged, 4);

        let rev = json!({
            "source": "okta",
            "_norm": {"org": "acme", "actor": "ana@acme.example"},
            "review": {"verdict": "malicious", "finding": "Stolen session.", "check": "Revoke."},
            "reviewed": {"alerts": 2},
        });
        append(&dir.path().join("reviews.ndjson"), &format!("{rev}\n"));
        assert_eq!(
            follow.said(false),
            [
                "",
                "#1  MALICIOUS  ana@acme.example (2 alerts)",
                "    Stolen session.",
                "    check: Revoke."
            ]
        );
        // the review covered two of her three: the third waits, as #1 still
        assert_eq!(
            follow.progress(Instant::now()),
            "reviewing #1 (reviewing 0s), #2 (reviewing 0s)"
        );
        let mut rest = rev.clone();
        rest["reviewed"]["alerts"] = json!(1);
        rest["review"] = json!({"verdict": "benign", "finding": "Hers."});
        append(&dir.path().join("reviews.ndjson"), &format!("{rest}\n"));
        assert_eq!(
            follow.said(false),
            ["#1  cleared  ana@acme.example (1 alert)  Hers."]
        );
        assert_eq!(follow.pending.len(), 1, "ci's alert waits");
    }

    #[test]
    fn judge_auth_errors_surface_in_status_and_clear_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let tracker = Tracker::start(dir.path(), "hosted", "Claude Haiku 5.5 + Sonnet 5.5");
        tracker.set_watching();
        let mut follow = Follow::with_style(dir.path(), None, None, Some(tracker), Style::plain());

        let rejected = json!({
            "session": {"entry": "/bin/zsh"},
            "judge": {"error": "HTTP 401 Unauthorized: invalid x-api-key"}
        });
        append(
            &dir.path().join("verdicts.ndjson"),
            &format!("{rejected}\n"),
        );
        follow.say(false);
        assert_eq!(
            status::read(dir.path()).unwrap().auth_error.as_deref(),
            Some("HTTP 401 Unauthorized: invalid x-api-key")
        );

        let ok = json!({
            "session": {"entry": "/bin/zsh"},
            "judge": {"warrants_investigation": "pass"}
        });
        append(&dir.path().join("verdicts.ndjson"), &format!("{ok}\n"));
        follow.say(false);
        assert_eq!(status::read(dir.path()).unwrap().auth_error, None);
    }

    #[test]
    fn a_judge_that_is_let_in_does_not_clear_what_the_reviewer_was_refused_for() {
        let dir = tempfile::tempdir().unwrap();
        let tracker = Tracker::start(dir.path(), "hosted", "Claude Haiku 5.5 + Sonnet 5.5");
        tracker.set_watching();
        let mut follow = Follow::with_style(dir.path(), None, None, Some(tracker), Style::plain());
        let judged = json!({
            "session": {"entry": "/bin/zsh"},
            "judge": {"warrants_investigation": "pass"}
        });
        let refused = json!({
            "session": {"entry": "/bin/zsh"},
            "source": "macos_review",
            "judge": {"warrants_investigation": "look"},
            "review": {"error": "status 403 Forbidden: INVALID_PAYMENT_INSTRUMENT"}
        });
        append(&dir.path().join("reviews.ndjson"), &format!("{refused}\n"));
        append(&dir.path().join("verdicts.ndjson"), &format!("{judged}\n"));
        follow.say(false);
        let said = || status::read(dir.path()).unwrap().auth_error;
        assert_eq!(
            said().as_deref(),
            Some("status 403 Forbidden: INVALID_PAYMENT_INSTRUMENT")
        );

        // and it stays through the judge's later clean calls
        append(&dir.path().join("verdicts.ndjson"), &format!("{judged}\n"));
        follow.say(false);
        assert!(said().is_some(), "the reviewer is still refused");

        let reviewed = json!({
            "session": {"entry": "/bin/zsh"},
            "source": "macos_review",
            "judge": {"warrants_investigation": "look"},
            "review": {"verdict": "dismissed", "finding": "nothing"}
        });
        append(&dir.path().join("reviews.ndjson"), &format!("{reviewed}\n"));
        follow.say(false);
        assert_eq!(said(), None);
    }
}
