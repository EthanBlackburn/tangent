//! What `tangent watch` says while its pipeline runs: each alert as the
//! judge flags it, each review as it is written, and now and then how many
//! records were judged. It reads them where the pipeline writes them
//! (alerts.ndjson, reviews.ndjson and verdicts.ndjson, in the pipeline's
//! directory), from where each file ended when the watch began, so the
//! runtime knows nothing of it and a restart says nothing twice.
//!
//! The text of an alert and of a review was written by a model that had
//! read whatever an attacker put in a record. It goes to a terminal, so
//! every control character is taken out of it first: an escape sequence
//! there could rewrite what the lines above it say.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::oneshot;

/// How often the files are read for what is new.
const EVERY: Duration = Duration::from_secs(1);
/// The least time between two lines that say how many records were judged.
const TALLY_EVERY: Duration = Duration::from_secs(300);
/// The most of a model's text a line shows.
const SHOWN: usize = 600;

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

/// A field of a record as text, by its path: empty when it is not there.
fn text(record: &Value, path: &[&str]) -> String {
    let field = path.iter().try_fold(record, |at, key| at.get(key));
    match field {
        Some(Value::String(s)) => clean(s),
        Some(Value::Null) | None => String::new(),
        Some(other) => clean(&other.to_string()),
    }
}

/// When a record happened, to the minute, as it says: `2026-11-24 03:09Z`.
fn when(record: &Value) -> String {
    let ts = text(record, &["ts"]);
    match (ts.get(..10), ts.get(11..16)) {
        (Some(day), Some(minute)) if ts.ends_with('Z') => format!("{day} {minute}Z"),
        _ => ts,
    }
}

/// An alert, as the lines that say it: when, from which log, who, and why
/// the judge flagged it.
fn alert(record: &Value) -> Vec<String> {
    vec![
        format!(
            "flagged   {}  {}  {}",
            when(record),
            text(record, &["source"]),
            text(record, &["_norm", "actor"])
        ),
        format!("          {}", text(record, &["judge", "why"])),
    ]
}

/// A review, as the lines that say it, from the first of its alerts, which
/// carries `reviewed`; the others say nothing more.
fn review(record: &Value) -> Vec<String> {
    let Some(about) = record.get("reviewed") else {
        return Vec::new();
    };
    let actor = text(record, &["_norm", "actor"]);
    let alerts = match about.get("alerts").and_then(Value::as_u64) {
        Some(1) => "1 alert".to_string(),
        Some(n) => format!("{n} alerts"),
        None => "its alerts".to_string(),
    };
    let error = text(record, &["review", "error"]);
    if !error.is_empty() {
        return vec![
            format!("review failed  {actor}, {alerts}: they stand"),
            format!("          {error}"),
        ];
    }
    let mut lines = vec![
        format!(
            "reviewed  {actor}, {alerts}: {}",
            text(record, &["review", "verdict"])
        ),
        format!("          {}", text(record, &["review", "finding"])),
    ];
    let check = text(record, &["review", "check"]);
    if !check.is_empty() {
        lines.push(format!("          check: {check}"));
    }
    lines
}

/// What the pipeline in a directory has written, said as it is written.
pub struct Follow {
    alerts: Tail,
    reviews: Tail,
    verdicts: Tail,
    judged: u64,
    flagged: u64,
    /// The count the last tally gave, and when.
    told: (u64, Instant),
}

impl Follow {
    pub fn new(dir: &Path) -> Self {
        Self {
            alerts: Tail::from_end(dir.join("alerts.ndjson")),
            reviews: Tail::from_end(dir.join("reviews.ndjson")),
            verdicts: Tail::from_end(dir.join("verdicts.ndjson")),
            judged: 0,
            flagged: 0,
            told: (0, Instant::now()),
        }
    }

    /// The lines for what was written since the last call. `tally` asks for
    /// the count now, if it has changed, however lately it was given.
    fn said(&mut self, tally: bool) -> Vec<String> {
        let mut lines = Vec::new();
        let parsed = |line: String| serde_json::from_str::<Value>(&line).ok();
        self.judged += self.verdicts.lines().len() as u64;
        for record in self.alerts.lines().into_iter().filter_map(parsed) {
            self.flagged += 1;
            lines.extend(alert(&record));
        }
        for record in self.reviews.lines().into_iter().filter_map(parsed) {
            lines.extend(review(&record));
        }
        let (told, at) = self.told;
        if self.judged != told && (tally || at.elapsed() >= TALLY_EVERY) {
            self.told = (self.judged, Instant::now());
            lines.push(format!(
                "judged    {} records since this watch began, {} flagged",
                self.judged, self.flagged
            ));
        }
        lines
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
            for line in self.said(false) {
                println!("{line}");
            }
        }
        for line in self.said(true) {
            println!("{line}");
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
        let lines = alert(&record);
        assert_eq!(lines.len(), 2, "an actor's name cannot start a line");
        assert!(
            lines.iter().all(|l| !l.chars().any(char::is_control)),
            "{lines:?}"
        );
    }

    #[test]
    fn an_alert_says_when_where_who_and_why() {
        let record = json!({
            "ts": "2026-11-24T03:09:43Z", "source": "okta",
            "_norm": {"actor": "ana@acme.example"},
            "judge": {"flag": true, "why": "a sign-in from a Tor exit"},
        });
        assert_eq!(
            alert(&record),
            [
                "flagged   2026-11-24 03:09Z  okta  ana@acme.example",
                "          a sign-in from a Tor exit"
            ]
        );
    }

    /// A review is said once, from the alert that carries `reviewed`: its
    /// verdict, its finding and what to check; a failed one says the alerts
    /// stand.
    #[test]
    fn a_review_is_said_once_for_its_alerts() {
        let first = json!({
            "_norm": {"actor": "ana@acme.example"},
            "review": {"verdict": "malicious", "finding": "She made a key.", "check": "Revoke it."},
            "reviewed": {"alerts": 3},
        });
        assert_eq!(
            review(&first),
            [
                "reviewed  ana@acme.example, 3 alerts: malicious",
                "          She made a key.",
                "          check: Revoke it."
            ]
        );
        let mut next = first.clone();
        next.as_object_mut().unwrap().remove("reviewed");
        assert!(review(&next).is_empty());

        let benign = json!({
            "_norm": {"actor": "ci"},
            "review": {"verdict": "benign", "finding": "A deploy."},
            "reviewed": {"alerts": 1},
        });
        assert_eq!(
            review(&benign),
            ["reviewed  ci, 1 alert: benign", "          A deploy."]
        );
        let failed = json!({
            "_norm": {"actor": "ci"},
            "review": {"error": "no reply"},
            "reviewed": {"alerts": 2},
        });
        assert_eq!(
            review(&failed),
            [
                "review failed  ci, 2 alerts: they stand",
                "          no reply"
            ]
        );
    }

    /// What a pipeline writes is said as it is written: the alerts, the
    /// reviews, and the count when asked, once for a count.
    #[test]
    fn what_the_pipeline_writes_is_said() {
        let dir = tempfile::tempdir().unwrap();
        append(&dir.path().join("verdicts.ndjson"), "{}\n");
        let mut follow = Follow::new(dir.path());
        assert!(follow.said(true).is_empty(), "nothing new, nothing said");

        append(&dir.path().join("verdicts.ndjson"), "{}\n{}\n{}\n");
        let flagged = json!({"ts": "2026-11-24T03:09:43Z", "source": "okta",
            "_norm": {"actor": "ana"}, "judge": {"why": "odd"}});
        append(
            &dir.path().join("alerts.ndjson"),
            &format!("{flagged}\nnot json\n"),
        );
        assert_eq!(
            follow.said(false),
            ["flagged   2026-11-24 03:09Z  okta  ana", "          odd"],
            "the count waits its turn"
        );
        assert_eq!(
            follow.said(true),
            ["judged    3 records since this watch began, 1 flagged"]
        );
        assert!(follow.said(true).is_empty(), "a count is given once");
    }
}
