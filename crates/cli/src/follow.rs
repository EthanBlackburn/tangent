//! What `tangent watch` says while its pipeline runs: each minute what the
//! judge checked, each alert as the judge flags it, and each review as it
//! is written. A review that upholds its alert is a notification too, at a
//! Mac ([`crate::notify`]). It reads them where the pipeline writes them
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

use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::notify::{Note, Notifier};

/// How often the files are read for what is new.
const EVERY: Duration = Duration::from_secs(1);
/// The least time between two lines that say what the judge checked.
const TALLY_EVERY: Duration = Duration::from_secs(60);
/// The most names a line that says what was checked gives.
const NAMED: usize = 5;
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

/// Who a record is about: the actor every cloud source names, or on a Mac
/// the session, by what started it.
fn who(record: &Value) -> String {
    match text(record, &["_norm", "actor"]) {
        actor if actor.is_empty() => text(record, &["session", "entry"]),
        actor => actor,
    }
}

/// An alert, as the lines that say it: when, from which log, who, and why
/// the judge marked it. A Mac's judge marks a session `look` or `flag`, and
/// says why or, of a `look`, what the session did.
fn alert(record: &Value) -> Vec<String> {
    let mark = match text(record, &["judge", "warrants_investigation"]).as_str() {
        "look" => "look",
        _ => "flagged",
    };
    let why = match text(record, &["judge", "why"]) {
        why if why.is_empty() => text(record, &["judge", "assessment"]),
        why => why,
    };
    vec![
        format!(
            "{mark:<8}  {}  {}  {}",
            when(record),
            text(record, &["source"]),
            who(record)
        ),
        format!("          {why}"),
        "          sent to review".to_string(),
    ]
}

/// What a judged record is called where the checked are counted: a Mac's
/// session by the program that started it, without its path, and a cloud
/// record by its actor.
fn name(record: &Value) -> String {
    let entry = text(record, &["session", "entry"]);
    match entry.rsplit('/').next() {
        Some(program) if !program.is_empty() => program.to_string(),
        _ => who(record),
    }
}

/// Whether a record of reviews.ndjson is a review to say. A cloud
/// pipeline's review covers an actor's alerts and is on each of them: it is
/// said from the first, which carries `reviewed`, and the others say
/// nothing more. A Mac's is a record of its own for each alert.
fn says_a_review(record: &Value) -> bool {
    record.get("reviewed").is_some() || text(record, &["source"]) == "macos_review"
}

/// A review, as the lines that say it.
fn review(record: &Value) -> Vec<String> {
    if !says_a_review(record) {
        return Vec::new();
    }
    let about = record.get("reviewed");
    let who = who(record);
    let alerts = match about.and_then(|a| a.get("alerts")).and_then(Value::as_u64) {
        Some(1) => ", 1 alert".to_string(),
        Some(n) => format!(", {n} alerts"),
        None => String::new(),
    };
    let error = text(record, &["review", "error"]);
    if !error.is_empty() {
        return vec![
            format!("review failed  {who}{alerts}: the judge's mark stands"),
            format!("          {error}"),
        ];
    }
    let mut lines = vec![
        format!(
            "reviewed  {who}{alerts}: {}",
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
    /// What was judged since the last line that said so: each name, how
    /// many times, and how many of them were flagged.
    checked: Vec<(String, u64)>,
    marked: u64,
    /// When the last such line was said.
    told: Instant,
    /// The reviews to show as notifications, not yet handed to `notifier`,
    /// which is there when this watch shows any.
    notes: Vec<Note>,
    notifier: Option<Notifier>,
}

impl Follow {
    pub fn new(dir: &Path, notifier: Option<Notifier>) -> Self {
        Self {
            dir: dir.to_path_buf(),
            alerts: Tail::from_end(dir.join("alerts.ndjson")),
            reviews: Tail::from_end(dir.join("reviews.ndjson")),
            verdicts: Tail::from_end(dir.join("verdicts.ndjson")),
            judged: 0,
            flagged: 0,
            checked: Vec::new(),
            marked: 0,
            told: Instant::now(),
            notes: Vec::new(),
            notifier,
        }
    }

    /// The line for what was judged since the last one: how many, the names
    /// judged most, and how many were flagged.
    fn tally(&mut self) -> String {
        let mut checked = std::mem::take(&mut self.checked);
        checked.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        let count: u64 = checked.iter().map(|(_, n)| n).sum();
        let mut names: Vec<String> = checked
            .iter()
            .take(NAMED)
            .map(|(name, n)| match n {
                1 => name.clone(),
                n => format!("{name} x{n}"),
            })
            .collect();
        if checked.len() > NAMED {
            names.push(format!("{} more", checked.len() - NAMED));
        }
        let flagged = match std::mem::take(&mut self.marked) {
            0 => "nothing flagged".to_string(),
            n => format!("{n} flagged"),
        };
        self.told = Instant::now();
        format!("checked   {count} ({}): {flagged}", names.join(", "))
    }

    /// The lines for what was written since the last call. `now` asks for
    /// what was checked to be said however lately it was.
    fn said(&mut self, now: bool) -> Vec<String> {
        let mut lines = Vec::new();
        let parsed = |line: String| serde_json::from_str::<Value>(&line).ok();
        for record in self.verdicts.lines().into_iter().filter_map(parsed) {
            self.judged += 1;
            let name = name(&record);
            match self.checked.iter_mut().find(|(known, _)| *known == name) {
                Some((_, n)) => *n += 1,
                None => self.checked.push((name, 1)),
            }
        }
        let alerts: Vec<Value> = self.alerts.lines().into_iter().filter_map(parsed).collect();
        self.flagged += alerts.len() as u64;
        self.marked += alerts.len() as u64;
        // What was checked is said before an alert from among it.
        if !self.checked.is_empty()
            && (now || !alerts.is_empty() || self.told.elapsed() >= TALLY_EVERY)
        {
            lines.push(self.tally());
        }
        for record in &alerts {
            lines.extend(alert(record));
        }
        for record in self.reviews.lines().into_iter().filter_map(parsed) {
            lines.extend(review(&record));
            self.notes.extend(note(&record, &self.dir));
        }
        lines
    }

    /// Says the lines for what was written since the last call, and hands
    /// its notifications on.
    fn say(&mut self, now: bool) {
        for line in self.said(now) {
            println!("{line}");
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
            println!(
                "judged    {} since this watch began, {} flagged",
                self.judged, self.flagged
            );
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
        assert_eq!(lines.len(), 3, "an actor's name cannot start a line");
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
                "          a sign-in from a Tor exit",
                "          sent to review"
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
                "review failed  ci, 2 alerts: the judge's mark stands",
                "          no reply"
            ]
        );
    }

    /// A Mac's alert is a session the judge marked `look` or `flag`, and
    /// its review a record of its own: each is said, by what started the
    /// session.
    #[test]
    fn a_macs_alert_and_review_are_said() {
        let look = json!({
            "ts": "2026-11-24T03:09:43Z", "source": "macos_session",
            "_norm": {"actor": "~/bin/agent#501"},
            "session": {"id": "501", "entry": "~/bin/agent"},
            "judge": {"warrants_investigation": "look", "assessment": "An agent read a key.", "so_far": "..."},
        });
        assert_eq!(
            alert(&look),
            [
                "look      2026-11-24 03:09Z  macos_session  ~/bin/agent#501",
                "          An agent read a key.",
                "          sent to review"
            ]
        );
        let mut flag = look.clone();
        flag["judge"] = json!({"warrants_investigation": "flag", "assessment": "It read a key.", "why": "It then sent it."});
        assert_eq!(
            alert(&flag)[0],
            "flagged   2026-11-24 03:09Z  macos_session  ~/bin/agent#501"
        );
        assert_eq!(alert(&flag)[1], "          It then sent it.");

        let reviewed = json!({
            "ts": "2026-11-24T03:17:00Z", "source": "macos_review",
            "session": {"id": "501", "entry": "~/bin/agent"},
            "judge": {"warrants_investigation": "flag"},
            "review": {"verdict": "unresolved", "finding": "It read a key and connected out.", "check": "Rotate the key."},
        });
        assert_eq!(
            review(&reviewed),
            [
                "reviewed  ~/bin/agent: unresolved",
                "          It read a key and connected out.",
                "          check: Rotate the key."
            ]
        );
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
        let mut follow = Follow::new(dir.path(), None);
        let review = |verdict: &str| {
            json!({"source": "macos_review", "session": {"entry": "~/bin/agent"},
                "review": {"verdict": verdict, "finding": "It ran."}})
        };
        append(
            &dir.path().join("reviews.ndjson"),
            &format!("{}\n{}\n", review("benign"), review("malicious")),
        );
        assert_eq!(follow.said(false).len(), 4, "both are said in the terminal");
        assert_eq!(follow.notes.len(), 1);
        assert_eq!(follow.notes[0].title, "Tangent: malicious activity");
    }

    /// What a pipeline writes is said as it is written: what was checked,
    /// by name and once, then the alert from among it and its review.
    #[test]
    fn what_the_pipeline_writes_is_said() {
        let dir = tempfile::tempdir().unwrap();
        append(&dir.path().join("verdicts.ndjson"), "{}\n");
        let mut follow = Follow::new(dir.path(), None);
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
        assert_eq!(
            follow.said(true),
            ["checked   3 (xpcproxy x2, zsh): nothing flagged"]
        );
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
            [
                "checked   1 (ana): 1 flagged",
                "flagged   2026-11-24 03:09Z  okta  ana",
                "          odd",
                "          sent to review"
            ],
            "an alert does not wait, and what was checked comes before it"
        );
    }
}
