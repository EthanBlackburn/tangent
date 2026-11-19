//! A `macos` source: this Mac, as packs/macos reads it. Tangent starts the
//! Endpoint Security sensor (packs/macos/sensor) and sends on each line it
//! writes, with what the sensor cannot say for itself:
//!
//! - **Who was already running.** The sensor shows a process when it forks
//!   or execs, so the terminal, the apps and an agent left open never come
//!   into view, and what they start has no one above it. A snapshot of
//!   `ps` goes ahead of the sensor's first line, and again a second after
//!   it starts, for what began in between. The plugin takes a snapshot's
//!   line only for a process it does not know.
//! - **That tangent is the capture.** A line names tangent's own pid, and
//!   the plugin leaves out what it and the programs under it do: the sensor
//!   reading every file event is what spyware looks like.
//!
//! The sensor needs root and tangent does not, so it is started through
//! `sudo`, which asks for the password once, on the terminal, before
//! anything is read. Root's process is not tangent's to signal: it ends
//! when the pipe it writes to closes, which is when this source stops.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::json;
use tangent_shared::dag::NodeRef;
use tangent_shared::sources::macos::MacosConfig;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use crate::router::Router;
use crate::sources::socket::drain_ndjson_lines;

/// How long after the sensor starts the second snapshot is taken.
const SECOND_SNAPSHOT: Duration = Duration::from_secs(1);
/// How long after the sensor ends a stop of tangent's may still explain it.
const STOP_KNOWN: Duration = Duration::from_millis(500);

pub async fn run_consumer(
    name: Arc<str>,
    cfg: MacosConfig,
    router: Arc<Router>,
    shutdown: CancellationToken,
) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("source {name}: a macos source reads the Mac it runs on, and this is not one");
    }
    if !cfg.sensor.is_file() {
        bail!(
            "source {name}: no sensor at {}: `sensor` names tangent-sensor inside TangentSensor.app, \
             from a release's tangent-sensor-macos.zip or a build of packs/macos/sensor",
            cfg.sensor.display()
        );
    }
    allow_root(&name).await?;

    let from = NodeRef::Source { name: name.clone() };
    let mut first = snapshot(Utc::now()).await?;
    first.push(monitor(std::process::id(), Utc::now()));
    router.forward(&from, first, Vec::new()).await?;

    let mut sensor = Command::new("sudo")
        .arg("-n")
        .arg("--")
        .arg(&cfg.sensor)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("source {name}: starting {}", cfg.sensor.display()))?;
    let mut out = sensor.stdout.take().expect("the sensor's stdout is piped");
    let err = sensor.stderr.take().expect("the sensor's stderr is piped");
    // What the sensor says of itself: the events the kernel dropped, and why
    // it stopped.
    let said = tokio::spawn(said(name.clone(), err));
    tracing::info!(source = %name, sensor = %cfg.sensor.display(), "the sensor is started");

    let again = tokio::time::sleep(SECOND_SNAPSHOT);
    tokio::pin!(again);
    let mut snapshots_left = true;
    let mut buf = BytesMut::with_capacity(512 * 1024);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = &mut again, if snapshots_left => {
                snapshots_left = false;
                router.forward(&from, snapshot(Utc::now()).await?, Vec::new()).await?;
            }
            read = out.read_buf(&mut buf) => {
                if read.with_context(|| format!("source {name}: reading the sensor"))? == 0 {
                    // Ctrl-C at a terminal reaches the sensor as it reaches
                    // tangent, and the sensor may be first to end.
                    if tokio::time::timeout(STOP_KNOWN, shutdown.cancelled()).await.is_ok() {
                        break;
                    }
                    let status = sensor.wait().await?;
                    let last = said.await.unwrap_or_default();
                    bail!("source {name}: the sensor stopped ({status}){}", why(&last));
                }
                let frames = drain_ndjson_lines(&mut buf);
                if !frames.is_empty() {
                    router.forward(&from, frames, Vec::new()).await?;
                }
            }
        }
    }
    // The pipe closes here, and the sensor ends at its next line.
    drop(out);
    Ok(())
}

/// Root's leave to start the sensor, asked for on the terminal before
/// anything is read: `sudo -v` asks for the password when it has to and
/// remembers the answer, so starting the sensor asks nothing.
async fn allow_root(name: &str) -> Result<()> {
    let status = Command::new("sudo")
        .arg("-v")
        .arg("-p")
        .arg("tangent starts the Mac's sensor as root. Password: ")
        .status()
        .await
        .with_context(|| format!("source {name}: running sudo"))?;
    if !status.success() {
        bail!("source {name}: the sensor needs root, and sudo did not give it ({status})");
    }
    Ok(())
}

/// The sensor's stderr, each line logged, and the last few kept for when it
/// stops.
async fn said(name: Arc<str>, err: tokio::process::ChildStderr) -> Vec<String> {
    let mut last = Vec::new();
    let mut lines = BufReader::new(err).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::warn!(source = %name, "sensor: {line}");
        if last.len() == 5 {
            last.remove(0);
        }
        last.push(line);
    }
    last
}

/// What the sensor last said, for the error that it stopped; and what a
/// sensor that says nothing most often lacks.
fn why(last: &[String]) -> String {
    if last.is_empty() {
        return ": it said nothing. The terminal tangent runs in needs Full Disk Access \
                (System Settings, Privacy & Security), and a restart after the grant"
            .to_string();
    }
    format!(": {}", last.join("; "))
}

/// The line that names `pid` as the capture: the plugin leaves out what it
/// and the programs under it do from here on.
fn monitor(pid: u32, now: DateTime<Utc>) -> BytesMut {
    line(&json!({"time": stamp(now), "monitor": {"pid": pid}}))
}

/// Every process running now, one line each, as the plugin reads them.
async fn snapshot(now: DateTime<Utc>) -> Result<Vec<BytesMut>> {
    // The start times in English and in UTC, whatever the Mac's language
    // and time zone.
    let ps = Command::new("ps")
        .args(["-axo", "pid=,ppid=,lstart=,comm="])
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .output()
        .await
        .context("running ps")?;
    if !ps.status.success() {
        bail!("ps: {}", String::from_utf8_lossy(&ps.stderr).trim());
    }
    Ok(processes(&String::from_utf8_lossy(&ps.stdout), now))
}

/// `ps -axo pid=,ppid=,lstart=,comm=` as the plugin's lines: a row is a
/// pid, its parent's, when it started (five words) and its path, which may
/// hold spaces. A row that is not one is left out.
fn processes(ps: &str, now: DateTime<Utc>) -> Vec<BytesMut> {
    let now = stamp(now);
    ps.lines()
        .filter_map(|row| {
            let mut rest = row;
            let mut words = Vec::with_capacity(7);
            for _ in 0..7 {
                rest = rest.trim_start();
                let end = rest.find(char::is_whitespace)?;
                words.push(&rest[..end]);
                rest = &rest[end..];
            }
            let (pid, ppid) = (words[0].parse::<u32>().ok()?, words[1].parse::<u32>().ok()?);
            // a login shell's argv[0] is its path after a dash
            let path = rest.trim();
            let path = path.strip_prefix('-').unwrap_or(path);
            if path.is_empty() {
                return None;
            }
            let mut ps = json!({"pid": pid, "ppid": ppid, "path": path});
            if let Some(start) = started(&words[2..]) {
                ps["start"] = json!(start);
            }
            Some(line(&json!({"time": now, "ps": ps})))
        })
        .collect()
}

/// `ps`'s `lstart` (`Mon Mar  2 09:00:00 2026`, in UTC as it was asked for)
/// as the plugin reads a time; `None` when it is not one.
fn started(words: &[&str]) -> Option<String> {
    let at = NaiveDateTime::parse_from_str(&words.join(" "), "%a %b %d %H:%M:%S %Y").ok()?;
    Some(at.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn stamp(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

fn line(value: &serde_json::Value) -> BytesMut {
    let mut line = BytesMut::from(value.to_string().as_bytes());
    line.extend_from_slice(b"\n");
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::Value;

    fn at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 2, 9, 30, 0).unwrap()
    }

    fn parsed(lines: &[BytesMut]) -> Vec<Value> {
        lines
            .iter()
            .map(|l| {
                assert!(l.ends_with(b"\n"), "a line ends");
                serde_json::from_slice(l).unwrap()
            })
            .collect()
    }

    /// A row is a pid, its parent's, when it started and its path: the
    /// plugin's `ps` line, as packs/macos/ps/ps.py wrote it. A path keeps
    /// its spaces, a login shell loses its dash, and a one-digit day, which
    /// ps pads with a space, is read.
    #[test]
    fn a_snapshot_row_is_the_plugins_ps_line() {
        let ps = "\
    1     0 Tue Nov 17 19:20:35 2026     /sbin/launchd
  412     1 Mon Mar  2 09:00:00 2026     /Applications/Visual Studio Code.app/Contents/MacOS/Electron
 5120   412 Mon Mar  2 09:01:07 2026     -zsh
";
        assert_eq!(
            parsed(&processes(ps, at())),
            [
                json!({"time": "2026-03-02T09:30:00.000000Z", "ps": {"pid": 1, "ppid": 0, "path": "/sbin/launchd", "start": "2026-11-17T19:20:35Z"}}),
                json!({"time": "2026-03-02T09:30:00.000000Z", "ps": {"pid": 412, "ppid": 1, "path": "/Applications/Visual Studio Code.app/Contents/MacOS/Electron", "start": "2026-03-02T09:00:00Z"}}),
                json!({"time": "2026-03-02T09:30:00.000000Z", "ps": {"pid": 5120, "ppid": 412, "path": "zsh", "start": "2026-03-02T09:01:07Z"}}),
            ]
        );
    }

    /// A row that is not a process is left out, and one whose start is not
    /// a time keeps the rest.
    #[test]
    fn a_row_that_is_not_one_is_left_out() {
        let ps = "\
PID PPID STARTED COMMAND
  77     1 Mon Mar  2 09:00:00 2026
  78     x Mon Mar  2 09:00:00 2026     /bin/ls

  79     1 Mon Foo  2 09:00:00 2026     /bin/cat
";
        assert_eq!(
            parsed(&processes(ps, at())),
            [
                json!({"time": "2026-03-02T09:30:00.000000Z", "ps": {"pid": 79, "ppid": 1, "path": "/bin/cat"}})
            ]
        );
    }

    #[test]
    fn the_capture_is_named_by_its_pid() {
        assert_eq!(
            parsed(&[monitor(4242, at())]),
            [json!({"time": "2026-03-02T09:30:00.000000Z", "monitor": {"pid": 4242}})]
        );
    }

    /// This machine's own ps is read: tangent is in it, with a start time,
    /// so the line that names it the capture names a process the plugin
    /// knows.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn this_process_is_in_the_snapshot() {
        let lines = parsed(&snapshot(Utc::now()).await.unwrap());
        let me = lines
            .iter()
            .find(|l| l["ps"]["pid"] == json!(std::process::id()))
            .expect("this process is running");
        assert!(me["ps"]["start"].is_string(), "{me}");
        assert!(lines.len() > 20, "{} processes", lines.len());
    }

    #[test]
    fn a_silent_sensor_is_most_often_without_full_disk_access() {
        assert!(why(&[]).contains("Full Disk Access"));
        assert_eq!(why(&["a".into(), "b".into()]), ": a; b");
    }
}
