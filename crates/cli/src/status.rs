//! Live watch status written atomically to `status.json` inside the pipeline
//! directory (`~/.local/share/tangent/mac/status.json` for `watch mac`).
//!
//! Read by the macOS menu bar app (`Tangent.app`) via kqueue and by
//! `tangent status` so both show the same live counts, model info, recent
//! alerts, and permission errors without polling logs or talking to the
//! runtime over IPC.

use std::fs::{self, File};
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// Status file name inside a watch directory.
pub const FILE: &str = "status.json";

/// Maximum number of recent upheld alerts kept in `status.json`.
const MAX_RECENT: usize = 5;

/// One upheld alert (`malicious` or `unresolved`) surfaced to the menu bar and
/// `tangent status`.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertSummary {
    pub ts: String,
    pub verdict: String,
    pub subject: String,
    pub who: String,
    pub summary: String,
    pub finding: String,
    pub check: String,
    pub feedback_file: Option<String>,
    pub feedback_line: Option<Value>,
}

impl AlertSummary {
    pub fn to_json(&self) -> Value {
        json!({
            "ts": self.ts,
            "verdict": self.verdict,
            "subject": self.subject,
            "who": self.who,
            "summary": self.summary,
            "finding": self.finding,
            "check": self.check,
            "feedback_file": self.feedback_file,
            "feedback_line": self.feedback_line,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        Some(Self {
            ts: s("ts"),
            verdict: s("verdict"),
            subject: s("subject"),
            who: s("who"),
            summary: s("summary"),
            finding: s("finding"),
            check: s("check"),
            feedback_file: v
                .get("feedback_file")
                .and_then(Value::as_str)
                .map(str::to_string),
            feedback_line: v
                .get("feedback_line")
                .filter(|x| !x.is_null())
                .cloned(),
        })
    }

    /// Parses an upheld review record from `reviews.ndjson`.
    pub fn from_review(record: &Value, dir: &Path) -> Option<Self> {
        let is_review = record.get("reviewed").is_some()
            || record.get("source").and_then(Value::as_str) == Some("macos_review");
        if !is_review {
            return None;
        }
        let verdict = record
            .pointer("/review/verdict")
            .and_then(Value::as_str)
            .unwrap_or("");
        if verdict != "malicious" && verdict != "unresolved" {
            return None;
        }
        let finding = clean_text(
            record
                .pointer("/review/finding")
                .and_then(Value::as_str)
                .unwrap_or(""),
        );
        let check = clean_text(
            record
                .pointer("/review/check")
                .and_then(Value::as_str)
                .unwrap_or(""),
        );
        let who = record
            .pointer("/_norm/actor")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| record.pointer("/session/entry").and_then(Value::as_str))
            .unwrap_or("");
        let subject = record
            .pointer("/session/entry")
            .and_then(Value::as_str)
            .and_then(|entry| entry.rsplit('/').next())
            .filter(|s| !s.is_empty())
            .unwrap_or(who);
        let ts = record
            .get("ts")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mac = record.get("source").and_then(Value::as_str) == Some("macos_review");
        let (feedback_file, feedback_line) = if mac {
            (
                Some(dir.join("feedback.ndjson").display().to_string()),
                Some(json!({
                    "source": "macos_feedback",
                    "session": record.get("session"),
                    "judge": record.pointer("/judge/warrants_investigation"),
                    "review": record.pointer("/review/verdict"),
                    "reviewed": record.get("ts"),
                })),
            )
        } else {
            (None, None)
        };
        Some(Self {
            ts,
            verdict: verdict.to_string(),
            subject: clean_text(subject),
            who: clean_text(who),
            summary: first_sentence(&finding, 100),
            finding,
            check,
            feedback_file,
            feedback_line,
        })
    }
}

/// Snapshot of a running or stopped `tangent watch` pipeline.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub state: String,
    pub pid: Option<u32>,
    pub started_at: Option<String>,
    pub updated_at: String,
    pub mode: String,
    pub models: String,
    pub checked: u64,
    pub flagged: u64,
    pub pending: u64,
    pub alerts: u64,
    pub recent_alerts: Vec<AlertSummary>,
    pub error: Option<String>,
    pub needs_fda: bool,
    pub auth_error: Option<String>,
    /// How long the models take in this run, in seconds, each the median
    /// and the 95th percentile, None until there is one: the judge a
    /// request, and an alert from flagged to its review's verdict, its wait
    /// for a reviewer included.
    pub judge_seconds: Option<(f64, f64)>,
    pub review_seconds: Option<(f64, f64)>,
    /// This run's tokens, what they cost and how fast sessions are checked
    /// ([`usage`]), None until a model has answered.
    pub usage: Option<Value>,
}

impl Snapshot {
    pub fn to_json(&self) -> Value {
        let recent: Vec<Value> = self.recent_alerts.iter().map(AlertSummary::to_json).collect();
        json!({
            "state": self.state,
            "pid": self.pid,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "mode": self.mode,
            "models": self.models,
            "checked": self.checked,
            "flagged": self.flagged,
            "pending": self.pending,
            "alerts": self.alerts,
            "recent_alerts": recent,
            "error": self.error,
            "needs_fda": self.needs_fda,
            "auth_error": self.auth_error,
            "judge_seconds": self.judge_seconds.map(|(p50, p95)| json!({"p50": p50, "p95": p95})),
            "review_seconds": self.review_seconds.map(|(p50, p95)| json!({"p50": p50, "p95": p95})),
            "usage": self.usage,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let u = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        let recent_alerts = v
            .get("recent_alerts")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(AlertSummary::from_json).collect())
            .unwrap_or_default();
        Some(Self {
            state: s("state"),
            pid: v.get("pid").and_then(Value::as_u64).map(|n| n as u32),
            started_at: v
                .get("started_at")
                .and_then(Value::as_str)
                .map(str::to_string),
            updated_at: s("updated_at"),
            mode: s("mode"),
            models: s("models"),
            checked: u("checked"),
            flagged: u("flagged"),
            pending: u("pending"),
            alerts: u("alerts"),
            recent_alerts,
            error: v.get("error").and_then(Value::as_str).map(str::to_string),
            needs_fda: v.get("needs_fda").and_then(Value::as_bool).unwrap_or(false),
            auth_error: v
                .get("auth_error")
                .and_then(Value::as_str)
                .map(str::to_string),
            judge_seconds: spread(v.get("judge_seconds")),
            review_seconds: spread(v.get("review_seconds")),
            usage: v.get("usage").filter(|u| u.is_object()).cloned(),
        })
    }
}

/// A `{"p50", "p95"}` as its pair.
fn spread(v: Option<&Value>) -> Option<(f64, f64)> {
    let v = v?;
    Some((v.get("p50")?.as_f64()?, v.get("p95")?.as_f64()?))
}

/// The median and the 95th percentile of `seconds`, each the nearest one
/// there is, to a tenth of a second; None of none.
pub fn percentiles(seconds: &[f64]) -> Option<(f64, f64)> {
    let mut sorted = seconds.to_vec();
    sorted.sort_by(f64::total_cmp);
    let at = |p: f64| {
        let rank = (p * sorted.len() as f64).ceil() as usize;
        (sorted[rank.clamp(1, sorted.len()) - 1] * 10.0).round() / 10.0
    };
    (!sorted.is_empty()).then(|| (at(0.5), at(0.95)))
}

/// Shared handle used by `watch.rs` (`Ready` layer + lifecycle) and `follow.rs`
/// to keep `status.json` atomically up to date.
#[derive(Clone)]
pub struct Tracker {
    inner: Arc<Mutex<TrackerInner>>,
}

struct TrackerInner {
    dir: PathBuf,
    snapshot: Snapshot,
    /// What the judge's and the reviewer's answers last said of their
    /// credentials, from `Follow`.
    answered: Option<String>,
    /// What a request that is being tried again was refused for. A judge
    /// that is refused tries for minutes before it answers at all, and until
    /// then there is no answer to read it from.
    refused: Option<String>,
    /// When `usage` was last written for its own sake: it changes with
    /// every request, and is written at most every [`USAGE_EVERY`].
    usage_written: Option<std::time::Instant>,
}

const USAGE_EVERY: std::time::Duration = std::time::Duration::from_secs(10);

/// This run's tokens, cost and rate, as `status.json` has them. `nodes` is
/// each inference node's name and totals, `checked` the sessions judged and
/// `seconds` how long the run has been going.
///
/// - `tokens`: every token of every request.
/// - `output_tokens_per_second`: by node, its output tokens over the time
///   its requests took.
/// - `tokens_per_activity`, `cost_per_activity`: over the sessions checked,
///   the judge's requests and the reviews together.
/// - `cost`, `cost_per_day`: USD at the providers' listed prices, and the
///   same at this run's rate for a day. `priced` is false when a model has
///   no listed price, and then the costs are left out.
/// - `activities_per_second`, `activities_per_day`: sessions checked, at
///   this run's rate.
pub fn usage(
    nodes: &[(&str, tangent_runtime::InferenceTotals)],
    checked: u64,
    seconds: f64,
) -> Option<Value> {
    let requests: u64 = nodes.iter().map(|(_, t)| t.requests).sum();
    if requests == 0 || seconds <= 0.0 {
        return None;
    }
    let tokens: u64 = nodes.iter().map(|(_, t)| t.tokens.all()).sum();
    let cost: f64 = nodes.iter().map(|(_, t)| t.cost).sum();
    let priced = nodes.iter().all(|(_, t)| t.unpriced == 0);
    let per = |n: f64| (checked > 0).then(|| n / checked as f64);
    let speed: serde_json::Map<String, Value> = nodes
        .iter()
        .filter(|(_, t)| t.seconds > 0.0)
        .map(|(name, t)| (name.to_string(), json!(t.tokens.output as f64 / t.seconds)))
        .collect();
    Some(json!({
        "tokens": tokens,
        "output_tokens_per_second": speed,
        "tokens_per_activity": per(tokens as f64),
        "priced": priced,
        "cost": priced.then_some(cost),
        "cost_per_day": priced.then(|| cost / seconds * 86400.0),
        "cost_per_activity": per(cost).filter(|_| priced),
        "activities_per_second": checked as f64 / seconds,
        "activities_per_day": checked as f64 / seconds * 86400.0,
    }))
}

impl Tracker {
    /// Creates a new status tracker in `dir` with `state = "starting"`,
    /// seeding recent alerts from any existing `reviews.ndjson`.
    pub fn start(dir: &Path, mode: &str, models: &str) -> Self {
        let now = now_rfc3339();
        let seeded = seed_recent(dir);
        // A watch that ended on an error is started again by launchd every
        // few seconds until what it lacks is given. What it lacked is said
        // until this one is watching, so the menu bar does not go from
        // "Needs Full Disk Access" to "Starting" and back each time.
        let (error, needs_fda) = match read(dir) {
            Some(last) if last.state == "error" => (last.error, last.needs_fda),
            _ => (None, false),
        };
        let snapshot = Snapshot {
            state: "starting".to_string(),
            pid: Some(std::process::id()),
            started_at: Some(now.clone()),
            updated_at: now,
            mode: mode.to_string(),
            models: models.to_string(),
            checked: 0,
            flagged: 0,
            pending: 0,
            alerts: 0,
            recent_alerts: seeded,
            error,
            needs_fda,
            auth_error: None,
            judge_seconds: None,
            review_seconds: None,
            usage: None,
        };
        let tracker = Self {
            inner: Arc::new(Mutex::new(TrackerInner {
                dir: dir.to_path_buf(),
                snapshot,
                answered: None,
                refused: None,
                usage_written: None,
            })),
        };
        tracker.flush();
        tracker
    }

    /// Marks the pipeline live once the sensor/pipeline starts.
    pub fn set_watching(&self) {
        let mut g = self.inner.lock().unwrap();
        g.snapshot.state = "watching".to_string();
        g.snapshot.error = None;
        g.snapshot.needs_fda = false;
        g.snapshot.auth_error = None;
        g.answered = None;
        g.refused = None;
        g.snapshot.updated_at = now_rfc3339();
        write_atomic(&g.dir, &g.snapshot);
    }

    /// Updates or clears the current provider authentication/billing error
    /// (401/403, invalid API key, expired AWS SSO token) observed on live
    /// judge or review calls.
    pub fn set_auth_error(&self, err: Option<String>) {
        let mut g = self.inner.lock().unwrap();
        g.answered = err;
        Self::say_auth(&mut g);
    }

    /// What the judge's request, which is being tried again, was refused
    /// for, or `None` once the judge has answered.
    pub fn set_refused(&self, err: Option<String>) {
        let mut g = self.inner.lock().unwrap();
        g.refused = err;
        Self::say_auth(&mut g);
    }

    /// `auth_error` is what an answer said, or else what a request still
    /// being tried was refused for. It is written when it changes.
    fn say_auth(g: &mut TrackerInner) {
        let err = g.answered.clone().or_else(|| g.refused.clone());
        if g.snapshot.auth_error == err {
            return;
        }
        g.snapshot.auth_error = err;
        g.snapshot.updated_at = now_rfc3339();
        write_atomic(&g.dir, &g.snapshot);
    }

    /// How long the models take ([`percentiles`]): written when either
    /// has changed.
    pub fn set_timing(&self, judge: Option<(f64, f64)>, review: Option<(f64, f64)>) {
        let mut g = self.inner.lock().unwrap();
        if (g.snapshot.judge_seconds, g.snapshot.review_seconds) == (judge, review) {
            return;
        }
        g.snapshot.judge_seconds = judge;
        g.snapshot.review_seconds = review;
        g.snapshot.updated_at = now_rfc3339();
        write_atomic(&g.dir, &g.snapshot);
    }

    /// This run's tokens, cost and rate ([`usage`]): written with whatever
    /// is written next, and for its own sake every [`USAGE_EVERY`].
    pub fn set_usage(&self, usage: Option<Value>) {
        let mut g = self.inner.lock().unwrap();
        if g.snapshot.usage == usage {
            return;
        }
        g.snapshot.usage = usage;
        if g.usage_written.is_some_and(|at| at.elapsed() < USAGE_EVERY) {
            return;
        }
        g.usage_written = Some(std::time::Instant::now());
        g.snapshot.updated_at = now_rfc3339();
        write_atomic(&g.dir, &g.snapshot);
    }

    /// Updates counts and appends any new upheld alerts from `Follow`.
    pub fn update(&self, checked: u64, flagged: u64, pending: u64, new_alerts: Vec<AlertSummary>) {
        let mut g = self.inner.lock().unwrap();
        let changed = g.snapshot.checked != checked
            || g.snapshot.flagged != flagged
            || g.snapshot.pending != pending
            || !new_alerts.is_empty();
        if !changed {
            return;
        }
        g.snapshot.checked = checked;
        g.snapshot.flagged = flagged;
        g.snapshot.pending = pending;
        for alert in new_alerts {
            g.snapshot.alerts += 1;
            g.snapshot.recent_alerts.insert(0, alert);
            g.snapshot.recent_alerts.truncate(MAX_RECENT);
        }
        g.snapshot.updated_at = now_rfc3339();
        write_atomic(&g.dir, &g.snapshot);
    }

    /// Records clean shutdown (`state = "stopped"`).
    pub fn set_stopped(&self) {
        let mut g = self.inner.lock().unwrap();
        g.snapshot.state = "stopped".to_string();
        g.snapshot.pid = None;
        g.snapshot.pending = 0;
        // A watch that was stopped has no error: one left here from before
        // is what `tangent up` and the menu bar would take for today's.
        g.snapshot.error = None;
        g.snapshot.needs_fda = false;
        g.snapshot.auth_error = None;
        g.answered = None;
        g.refused = None;
        g.snapshot.updated_at = now_rfc3339();
        write_atomic(&g.dir, &g.snapshot);
    }

    /// Records a fatal startup/runtime error (`state = "error"`), flagging
    /// whether it looks like missing macOS Full Disk Access.
    pub fn set_error(&self, err: &str) {
        let mut g = self.inner.lock().unwrap();
        g.snapshot.state = "error".to_string();
        g.snapshot.pid = None;
        g.snapshot.pending = 0;
        g.snapshot.error = Some(err.to_string());
        g.snapshot.needs_fda = looks_like_fda(err);
        g.snapshot.updated_at = now_rfc3339();
        write_atomic(&g.dir, &g.snapshot);
    }

    /// The error this watch ended on, when it did.
    pub fn failed(&self) -> Option<String> {
        let g = self.inner.lock().unwrap();
        match g.snapshot.state.as_str() {
            "error" => g.snapshot.error.clone(),
            _ => None,
        }
    }

    fn flush(&self) {
        let g = self.inner.lock().unwrap();
        write_atomic(&g.dir, &g.snapshot);
    }
}

/// Reads `status.json` from `dir`, if present and valid.
pub fn read(dir: &Path) -> Option<Snapshot> {
    let text = fs::read_to_string(dir.join(FILE)).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    Snapshot::from_json(&value)
}

/// Whether `err` indicates macOS Full Disk Access has not been granted yet.
/// The sensor names it when that is what it lacks, as the daemon or under
/// sudo. "Operation not permitted" alone is any refusal by macOS, of a file
/// or a socket as much as of this.
pub fn looks_like_fda(err: &str) -> bool {
    err.to_ascii_lowercase().contains("full disk access")
}

/// Whether a judge or review error indicates rejected, expired, or missing
/// provider credentials (e.g. HTTP 401/403, revoked API key, expired AWS SSO).
pub fn looks_like_auth_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    [
        "401",
        "403",
        "unauthorized",
        "authentication_error",
        "authentication error",
        "invalid x-api-key",
        "invalid_api_key",
        "incorrect api key",
        "api key not valid",
        "expiredtoken",
        "sso token has expired",
        "token has expired",
        "no credentials",
        "unrecognizedclient",
        "invalidclienttokenid",
        "accessdenied",
        "credit balance is too low",
        "insufficient_quota",
        "invalid_payment_instrument",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Seeds up to [`MAX_RECENT`] upheld alerts from the tail of `reviews.ndjson`.
fn seed_recent(dir: &Path) -> Vec<AlertSummary> {
    let Ok(file) = File::open(dir.join("reviews.ndjson")) else {
        return Vec::new();
    };
    let mut alerts = Vec::new();
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let Ok(record) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if let Some(alert) = AlertSummary::from_review(&record, dir) {
            alerts.push(alert);
        }
    }
    alerts.reverse();
    alerts.truncate(MAX_RECENT);
    alerts
}

fn write_atomic(dir: &Path, snapshot: &Snapshot) {
    let tmp = dir.join(".status.json.tmp");
    let dst = dir.join(FILE);
    let Ok(bytes) = serde_json::to_vec_pretty(&snapshot.to_json()) else {
        return;
    };
    if let Ok(mut file) = File::create(&tmp) {
        if file.write_all(&bytes).is_ok() && file.sync_all().is_ok() {
            let _ = fs::rename(&tmp, &dst);
        }
    }
}

fn clean_text(text: &str) -> String {
    let plain: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    plain.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn first_sentence(text: &str, limit: usize) -> String {
    let first = text.find(". ").map(|i| &text[..=i]).unwrap_or(text);
    if first.chars().count() <= limit {
        return first.to_string();
    }
    match text.char_indices().nth(limit) {
        Some((cut, _)) => format!("{}...", text[..cut].trim_end()),
        None => text.to_string(),
    }
}

/// Current UTC time formatted as RFC 3339 (`2026-11-26T18:05:12Z`) without
/// pulling in `chrono` into `tangent-cli`.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_rfc3339(secs)
}

fn format_rfc3339(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_is_per_activity_and_per_day_at_the_run_s_rate() {
        use tangent_runtime::inference::price::Tokens;
        use tangent_runtime::InferenceTotals;
        let judge = InferenceTotals {
            requests: 10,
            seconds: 20.0,
            tokens: Tokens { input: 9000, output: 1000, ..Tokens::default() },
            cost: 0.01,
            unpriced: 0,
        };
        let reviewer = InferenceTotals {
            requests: 2,
            seconds: 50.0,
            tokens: Tokens { cache_read: 85_000, output: 5000, ..Tokens::default() },
            cost: 0.09,
            unpriced: 0,
        };
        assert_eq!(usage(&[("judge", InferenceTotals::default())], 0, 60.0), None);
        // an hour's run: 20 sessions checked
        let u = usage(&[("judge", judge), ("reviewer", reviewer)], 20, 3600.0).unwrap();
        let near = |k: &str, want: f64| {
            let got = u.pointer(k).and_then(Value::as_f64).unwrap();
            assert!((got - want).abs() < 1e-9, "{k}: {got} != {want}");
        };
        assert_eq!(u["tokens"], 100_000);
        near("/output_tokens_per_second/judge", 50.0);
        near("/output_tokens_per_second/reviewer", 100.0);
        near("/tokens_per_activity", 5000.0);
        near("/cost", 0.10);
        near("/cost_per_day", 2.40);
        near("/cost_per_activity", 0.005);
        near("/activities_per_second", 20.0 / 3600.0);
        near("/activities_per_day", 480.0);
        // a model with no listed price: no cost is said
        let unknown = InferenceTotals { unpriced: 1, ..reviewer };
        let u = usage(&[("judge", judge), ("reviewer", unknown)], 20, 3600.0).unwrap();
        assert_eq!((&u["priced"], &u["cost"], &u["cost_per_day"]), (&json!(false), &Value::Null, &Value::Null));
        assert_eq!(u["cost_per_activity"], Value::Null);
    }

    #[test]
    fn the_median_and_the_95th_are_seconds_there_were() {
        assert_eq!(percentiles(&[]), None);
        assert_eq!(percentiles(&[3.04]), Some((3.0, 3.0)));
        let twenty: Vec<f64> = (1..=20).rev().map(f64::from).collect();
        assert_eq!(percentiles(&twenty), Some((10.0, 19.0)));
    }

    #[test]
    fn rfc3339_formats_known_epochs() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_764_180_312), "2025-11-26T18:05:12Z");
    }

    #[test]
    fn tracker_writes_and_updates_status_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let existing = json!({
            "ts": "2026-11-26T10:00:00Z",
            "source": "macos_review",
            "session": {"id": "1", "entry": "/usr/bin/curl"},
            "judge": {"warrants_investigation": "flag"},
            "review": {
                "verdict": "malicious",
                "finding": "Uploaded SSH keys.",
                "check": "Inspect ~/.ssh."
            }
        });
        fs::write(dir.path().join("reviews.ndjson"), format!("{existing}\n")).unwrap();

        let tracker = Tracker::start(dir.path(), "hosted", "Claude Haiku 5.5 + Sonnet 5.5");
        let snap = read(dir.path()).unwrap();
        assert_eq!(snap.state, "starting");
        assert_eq!(snap.pid, Some(std::process::id()));
        assert_eq!(snap.recent_alerts.len(), 1);
        assert_eq!(snap.recent_alerts[0].subject, "curl");
        assert_eq!(snap.recent_alerts[0].verdict, "malicious");

        tracker.set_watching();
        assert_eq!(read(dir.path()).unwrap().state, "watching");

        let newer = AlertSummary::from_review(
            &json!({
                "ts": "2026-11-26T10:05:00Z",
                "source": "macos_review",
                "session": {"id": "2", "entry": "/Applications/VS Code.app/Code Helper"},
                "judge": {"warrants_investigation": "flag"},
                "review": {
                    "verdict": "unresolved",
                    "finding": "Hidden script contacted external host.",
                    "check": "Check extensions."
                }
            }),
            dir.path(),
        )
        .unwrap();
        tracker.update(42, 2, 1, vec![newer]);
        let snap = read(dir.path()).unwrap();
        assert_eq!(snap.checked, 42);
        assert_eq!(snap.flagged, 2);
        assert_eq!(snap.pending, 1);
        assert_eq!(snap.alerts, 1);
        assert_eq!(snap.recent_alerts.len(), 2);
        assert_eq!(snap.recent_alerts[0].subject, "Code Helper");

        tracker.set_error("source mac: not permitted: grant Tangent Full Disk Access");
        let snap = read(dir.path()).unwrap();
        assert_eq!(snap.state, "error");
        assert!(snap.needs_fda);
        assert_eq!(snap.pid, None);

        assert_eq!(
            tracker.failed().as_deref(),
            Some("source mac: not permitted: grant Tangent Full Disk Access")
        );
        // the next start, which launchd makes, still says what is lacking
        let next = Tracker::start(dir.path(), "hosted", "Claude Haiku 5.5 + Sonnet 5.5");
        let snap = read(dir.path()).unwrap();
        assert_eq!(snap.state, "starting");
        assert!(snap.needs_fda);
        assert_eq!(next.failed(), None, "it has not failed itself");
        next.set_watching();
        assert!(!read(dir.path()).unwrap().needs_fda, "and no longer once it watches");

        tracker.set_stopped();
        let snap = read(dir.path()).unwrap();
        assert_eq!(snap.state, "stopped");
        assert_eq!(snap.pid, None);
        assert!(!snap.needs_fda, "a stop leaves no error behind");
        assert_eq!(snap.error, None);
    }

    #[test]
    fn only_an_error_that_names_full_disk_access_asks_for_it() {
        assert!(looks_like_fda("source mac: not permitted: grant Tangent Full Disk Access"));
        assert!(!looks_like_fda("opening lake/x.parquet: Operation not permitted (os error 1)"));
    }

    #[test]
    fn a_request_still_being_tried_says_what_it_was_refused_for() {
        let dir = tempfile::tempdir().unwrap();
        let tracker = Tracker::start(dir.path(), "hosted", "Claude Haiku 5.5 + Sonnet 5.5");
        tracker.set_watching();
        let said = || read(dir.path()).unwrap().auth_error;
        tracker.set_refused(Some("AWS sign-in has expired".to_string()));
        // `Follow` has read no answer, and says so each second
        tracker.set_auth_error(None);
        assert_eq!(said().as_deref(), Some("AWS sign-in has expired"));
        // an answer's own word is the one shown
        tracker.set_auth_error(Some("403 Forbidden".to_string()));
        assert_eq!(said().as_deref(), Some("403 Forbidden"));
        tracker.set_auth_error(None);
        tracker.set_refused(None);
        assert_eq!(said(), None);
    }

    #[test]
    fn auth_error_detects_provider_rejections_and_tracks_clear() {
        assert!(looks_like_auth_error("HTTP 401 Unauthorized: invalid x-api-key"));
        assert!(looks_like_auth_error("ExpiredTokenException: The SSO token has expired"));
        assert!(looks_like_auth_error("403 Forbidden: INVALID_PAYMENT_INSTRUMENT"));
        assert!(!looks_like_auth_error("request timed out after 90s"));

        let dir = tempfile::tempdir().unwrap();
        let tracker = Tracker::start(dir.path(), "hosted", "Claude Haiku 5.5 + Sonnet 5.5");
        tracker.set_watching();
        tracker.set_auth_error(Some("401 Unauthorized: invalid x-api-key".to_string()));
        assert_eq!(
            read(dir.path()).unwrap().auth_error.as_deref(),
            Some("401 Unauthorized: invalid x-api-key")
        );
        tracker.set_auth_error(None);
        assert_eq!(read(dir.path()).unwrap().auth_error, None);
    }
}
