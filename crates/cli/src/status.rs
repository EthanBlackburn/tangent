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
        })
    }
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
}

impl Tracker {
    /// Creates a new status tracker in `dir` with `state = "starting"`,
    /// seeding recent alerts from any existing `reviews.ndjson`.
    pub fn start(dir: &Path, mode: &str, models: &str) -> Self {
        let now = now_rfc3339();
        let seeded = seed_recent(dir);
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
            error: None,
            needs_fda: false,
        };
        let tracker = Self {
            inner: Arc::new(Mutex::new(TrackerInner {
                dir: dir.to_path_buf(),
                snapshot,
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

    fn flush(&self) {
        let g = self.inner.lock().unwrap();
        write_atomic(&g.dir, &g.snapshot);
    }
}

/// Reads `status.json` from `dir`, if present and valid.
#[allow(dead_code)]
pub fn read(dir: &Path) -> Option<Snapshot> {
    let text = fs::read_to_string(dir.join(FILE)).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    Snapshot::from_json(&value)
}

/// Whether `err` indicates macOS Full Disk Access has not been granted yet.
pub fn looks_like_fda(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("full disk access") || lower.contains("not permitted")
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

        tracker.set_stopped();
        let snap = read(dir.path()).unwrap();
        assert_eq!(snap.state, "stopped");
        assert_eq!(snap.pid, None);
    }
}
