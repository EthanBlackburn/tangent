//! The notifications `tangent watch` shows at a Mac: each review that
//! upholds an alert, as a banner of macOS's own, so whoever is not looking
//! at the terminal still hears of it.
//!
//! macOS shows a notification under an app's name and icon, and asks the
//! Mac's owner once whether that app may show any. The app is the sensor's
//! (packs/macos/sensor), run as you with `notify`: the one a `macos` source
//! names, else this release's, fetched and checked as the sensor is. Watch
//! starts it once and writes it a line for each notification
//! ([`Notifier`]). macOS takes its question back when the process that
//! asked ends, and counts that as a no, so the one process is kept for as
//! long as the watch runs.
//!
//! A notification may ask whether what it reports was its reader's doing,
//! with three buttons ([`Note::feedback`]). The app keeps the answer
//! itself, in the file the note names: a banner can be answered after the
//! watch that showed it has ended, when macOS starts the app for the click.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use serde_json::{json, Value};
use tangent_shared::sources::common::SourceConfig;
use tangent_shared::Config;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// How long the app is given to show the last of them as the watch ends.
const LAST: Duration = Duration::from_secs(2);

/// One notification: the three lines of its banner, the text shown when it
/// is clicked, and whether it makes a sound.
#[derive(Debug, Clone, PartialEq)]
pub struct Note {
    pub title: String,
    pub subtitle: String,
    pub body: String,
    pub detail: String,
    pub sound: bool,
    /// With it the notification asks, "Not me", "Not sure" or "That was
    /// me": the file the answer is added to, and the line it is added as,
    /// to which the app adds `answer`, `note` and `ts`.
    pub feedback: Option<(PathBuf, Value)>,
}

/// The app that shows a watch's notifications, when it shows any: none
/// with `off` (--no-notify), on anything but a Mac, and over ssh, where
/// nobody is at the Mac's screen. When there should be one and is not, it
/// says why, and the watch goes on without.
pub async fn app(config: &Path, off: bool) -> Option<PathBuf> {
    if off || !cfg!(target_os = "macos") || std::env::var_os("SSH_CONNECTION").is_some() {
        return None;
    }
    match find(config).await {
        Ok(app) => Some(app),
        Err(e) => {
            println!("Notifications are off: {e:#}");
            None
        }
    }
}

/// The sensor a `macos` source of `config` names, which is a build of your
/// own; else this release's, fetched if it is not kept yet, and checked.
async fn find(config: &Path) -> Result<PathBuf> {
    let cfg = Config::load(config)?.config;
    let named = cfg.sources.values().find_map(|source| match source {
        SourceConfig::Macos(mac) => mac.sensor.clone(),
        _ => None,
    });
    if let Some(named) = named {
        return Ok(named);
    }
    let dir = tangent_shared::sensor::dir()?;
    if !tangent_shared::sensor::binary(&dir).is_file() {
        crate::fetch::sensor(&dir).await?;
    }
    tangent_shared::sensor::check(&dir)?;
    Ok(tangent_shared::sensor::binary(&dir))
}

/// The app, started, and what it is to show.
pub struct Notifier {
    notes: mpsc::UnboundedSender<Note>,
    shown: JoinHandle<()>,
}

impl Notifier {
    /// Starts `app` to show what [`Notifier::show`] is given. Nothing here
    /// waits for it: an app that does not start, or that the Mac's owner
    /// has not allowed, says so once and the notes go nowhere.
    pub fn start(app: PathBuf) -> Self {
        let (notes, shown) = mpsc::unbounded_channel();
        Self {
            notes,
            shown: tokio::spawn(run(app, shown)),
        }
    }

    pub fn show(&self, note: Note) {
        let _ = self.notes.send(note);
    }

    /// Lets the app show what it was last given, for a moment.
    pub async fn end(self) {
        drop(self.notes);
        let _ = self.shown.await;
    }
}

async fn run(app: PathBuf, mut notes: mpsc::UnboundedReceiver<Note>) {
    let mut command = Command::new(&app);
    command
        .arg("notify")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // A group of its own: Ctrl-C at the terminal stops the watch, and the
    // app ends when the watch has written it the last review.
    #[cfg(unix)]
    command.process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            println!("Notifications are off: starting {}: {e}", app.display());
            return;
        }
    };
    let mut to = child.stdin.take().expect("the app's stdin is piped");
    loop {
        tokio::select! {
            note = notes.recv() => match note {
                Some(note) => write(&mut to, note).await,
                None => break,
            },
            _ = child.wait() => return off(child).await,
        }
    }
    // Its stdin ends, and it with it: unless macOS's question, or a report
    // someone opened, is still up, which the app goes on waiting with, for
    // the answer to be kept.
    drop(to);
    let _ = tokio::time::timeout(LAST, child.wait()).await;
}

/// A note as the line the app reads. A write that fails is the app gone,
/// which the next turn of [`run`] finds.
async fn write(to: &mut ChildStdin, note: Note) {
    let mut line = json!({
        "title": note.title, "subtitle": note.subtitle, "body": note.body,
        "detail": note.detail, "sound": note.sound,
    });
    if let Some((file, answer)) = note.feedback {
        line["feedback"] = json!({"file": file, "line": answer});
    }
    let _ = to.write_all(format!("{line}\n").as_bytes()).await;
}

/// The app ended while the watch runs: it says why on stderr, and its last
/// line is said here.
async fn off(mut child: Child) {
    let mut said = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut said).await;
    }
    let why = said.lines().last().unwrap_or("the app stopped");
    let why = why.strip_prefix("tangent-sensor: ").unwrap_or(why);
    println!("Notifications are off: {why}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(who: &str, feedback: Option<(PathBuf, Value)>) -> Note {
        Note {
            title: "Tangent: needs a look".to_string(),
            subtitle: who.to_string(),
            body: format!("{who} did it."),
            detail: format!("{who} did it.\n\nCheck: {who}."),
            sound: false,
            feedback,
        }
    }

    /// An app that reads its stdin to `out`, as the sensor's does.
    #[cfg(unix)]
    fn stub(dir: &Path, script: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let app = dir.join("app");
        std::fs::write(&app, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&app, std::fs::Permissions::from_mode(0o755)).unwrap();
        app
    }

    /// The app is started with `notify` and written a line for each
    /// notification, each its own, before its stdin closes: one that asks
    /// carries the file its answer goes to and the line it goes as.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_app_is_written_a_line_for_each_notification() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let app = stub(
            dir.path(),
            &format!("echo \"$1\" > {0}; cat >> {0}", out.display()),
        );
        let notifier = Notifier::start(app);
        notifier.show(note("ana", None));
        let answer = json!({"source": "macos_feedback", "session": {"id": "501"}});
        notifier.show(note(
            "eve",
            Some((PathBuf::from("/w/feedback.ndjson"), answer.clone())),
        ));
        notifier.end().await;

        let written = std::fs::read_to_string(&out).unwrap();
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines[0], "notify");
        assert_eq!(lines.len(), 3, "{written}");
        let first: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first["subtitle"], "ana");
        assert_eq!(first["detail"], "ana did it.\n\nCheck: ana.");
        assert_eq!(first["sound"], false);
        assert!(first.get("feedback").is_none(), "{first}");
        let last: Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(last["title"], "Tangent: needs a look");
        assert_eq!(last["subtitle"], "eve");
        assert_eq!(
            last["feedback"],
            json!({"file": "/w/feedback.ndjson", "line": answer})
        );
    }

    /// An app that ends, as the sensor's does when the Mac's owner has not
    /// allowed it, takes nothing with it: what is shown after goes nowhere.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_app_that_ends_stops_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let app = stub(dir.path(), "echo 'not allowed' >&2; exit 1");
        let notifier = Notifier::start(app);
        tokio::time::sleep(Duration::from_millis(300)).await;
        notifier.show(note("ana", None));
        notifier.end().await;

        let none = Notifier::start(dir.path().join("no-such-app"));
        none.show(note("ana", None));
        none.end().await;
    }
}
