//! An `exec` sink: each record to a command, a JSON line on its stdin.
//!
//! The command is one long-lived process, started with tangent. It ends when
//! its stdin closes, and tangent never signals it:
//!
//! - It runs in a process group of its own, so the terminal's Ctrl-C, which
//!   reaches tangent, does not reach it: the records tangent writes as it
//!   stops still find it running.
//! - At tangent's stop ([`Sink::flush`]) its stdin is closed and tangent
//!   waits for it to end, as long as any sink is waited for. A command still
//!   at work then (one that waits on a person) is left to finish alone.
//! - When tangent ends any other way, the pipe closes all the same.
//!
//! Its stdout and stderr are tangent's own, so what it prints is where
//! tangent's log is, and it can print after tangent has gone.

use std::process::Stdio;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use tangent_shared::sinks::exec::ExecConfig;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Mutex;

use crate::sinks::encoding;
use crate::sinks::manager::{Sink, SinkWrite};
use crate::{SINK_BYTES_TOTAL, SINK_OBJECTS_TOTAL};

pub struct ExecSink {
    name: Arc<str>,
    command: Vec<String>,
    /// The command while it runs; none once its stdin has been closed, until
    /// the next record.
    running: Mutex<Option<Running>>,
}

struct Running {
    child: Child,
    stdin: ChildStdin,
}

impl ExecSink {
    /// Starts the command: one that cannot start fails tangent's start, not
    /// its first record.
    pub fn new(name: &Arc<str>, cfg: &ExecConfig) -> Result<Arc<Self>> {
        if cfg.command.first().is_none_or(String::is_empty) {
            bail!("sink {name}: `command` names no program");
        }
        let running = start(name, &cfg.command)?;
        Ok(Arc::new(Self {
            name: Arc::clone(name),
            command: cfg.command.clone(),
            running: Mutex::new(Some(running)),
        }))
    }
}

fn start(name: &str, command: &[String]) -> Result<Running> {
    let mut program = Command::new(&command[0]);
    program.args(&command[1..]).stdin(Stdio::piped());
    #[cfg(unix)]
    program.process_group(0);
    let mut child = program
        .spawn()
        .with_context(|| format!("sink {name}: starting `{}`", command[0]))?;
    let stdin = child.stdin.take().expect("the command's stdin is piped");
    Ok(Running { child, stdin })
}

#[async_trait]
impl Sink for ExecSink {
    async fn write(&self, req: SinkWrite) -> Result<()> {
        let lines = encoding::ndjson_ensure_newline(req.payload);
        let mut running = self.running.lock().await;
        if let Some(command) = running.as_mut() {
            if let Some(status) = command.child.try_wait()? {
                tracing::warn!(sink = %self.name, "the command ended ({status}); it is started again");
                *running = None;
            }
        }
        let command = match running.as_mut() {
            Some(command) => command,
            None => running.insert(start(&self.name, &self.command)?),
        };
        let written = async {
            command.stdin.write_all(&lines).await?;
            command.stdin.flush().await
        };
        if let Err(e) = written.await {
            // It has ended or closed its stdin since: the write is tried
            // again, whole, with the command started anew.
            *running = None;
            return Err(e).with_context(|| format!("sink {}: writing to the command", self.name));
        }
        SINK_OBJECTS_TOTAL.inc();
        SINK_BYTES_TOTAL.inc_by(lines.len() as u64);
        Ok(())
    }

    /// The command has every record once its stdin closes and it ends, so
    /// that is what this waits for. A record after it starts the command
    /// again.
    async fn flush(&self) -> Result<()> {
        let Some(Running { mut child, stdin }) = self.running.lock().await.take() else {
            return Ok(());
        };
        drop(stdin);
        let status = child.wait().await?;
        if !status.success() {
            tracing::warn!(sink = %self.name, "the command ended ({status})");
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use std::path::Path;
    use std::time::Duration;

    /// A sink whose command is `sh -c <script> <file>`: `$0` is the file.
    fn sink(script: &str, file: &Path) -> Arc<ExecSink> {
        let command = ["sh", "-c", script, &file.to_string_lossy()]
            .map(String::from)
            .to_vec();
        ExecSink::new(&Arc::from("ask"), &ExecConfig { command }).unwrap()
    }

    fn records(lines: &str) -> SinkWrite {
        SinkWrite {
            sink_name: Arc::from("ask"),
            payload: BytesMut::from(lines),
            s3: None,
        }
    }

    async fn until(what: &str, mut is: impl FnMut() -> bool) {
        for _ in 0..500 {
            if is() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("waited five seconds for {what}");
    }

    #[tokio::test]
    async fn each_record_is_a_line_on_the_commands_stdin() {
        let tmp = tempfile::tempdir().unwrap();
        let got = tmp.path().join("got");
        let sink = sink(r#"cat > "$0""#, &got);
        sink.write(records("{\"a\":1}\n{\"a\":2}\n")).await.unwrap();
        sink.write(records("{\"a\":3}")).await.unwrap();
        sink.flush().await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&got).unwrap(),
            "{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n"
        );
    }

    /// The stop waits for the command to act on what it was given.
    #[tokio::test]
    async fn the_stop_waits_for_the_command_to_end() {
        let tmp = tempfile::tempdir().unwrap();
        let got = tmp.path().join("got");
        let sink = sink(r#"cat > /dev/null; sleep 0.3; echo done > "$0""#, &got);
        sink.write(records("{}\n")).await.unwrap();
        sink.flush().await.unwrap();
        assert_eq!(std::fs::read_to_string(&got).unwrap(), "done\n");
    }

    #[tokio::test]
    async fn a_command_that_ended_is_started_again_for_the_next_record() {
        let tmp = tempfile::tempdir().unwrap();
        let got = tmp.path().join("got");
        // one line, and it ends
        let sink = sink(r#"head -n 1 >> "$0""#, &got);
        sink.write(records("{\"a\":1}\n")).await.unwrap();
        let mut ended = false;
        for _ in 0..500 {
            let mut running = sink.running.lock().await;
            ended = running
                .as_mut()
                .unwrap()
                .child
                .try_wait()
                .unwrap()
                .is_some();
            drop(running);
            if ended {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ended, "head ends at its first line");
        sink.write(records("{\"a\":2}\n")).await.unwrap();
        sink.flush().await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&got).unwrap(),
            "{\"a\":1}\n{\"a\":2}\n"
        );
    }

    /// Ctrl-C at the terminal goes to tangent's process group. The command
    /// is in one of its own, and is there for the records of the stop.
    #[tokio::test]
    async fn the_command_is_in_a_process_group_of_its_own() {
        let tmp = tempfile::tempdir().unwrap();
        let got = tmp.path().join("got");
        let sink = sink(r#"ps -o pgid= -p $$ > "$0"; cat > /dev/null"#, &got);
        until("the command's group", || {
            got.metadata().is_ok_and(|m| m.len() > 0)
        })
        .await;
        let group = |pid: u32| {
            let ps = std::process::Command::new("ps")
                .args(["-o", "pgid=", "-p", &pid.to_string()])
                .output()
                .unwrap();
            String::from_utf8_lossy(&ps.stdout).trim().to_string()
        };
        let its = std::fs::read_to_string(&got).unwrap().trim().to_string();
        assert!(!its.is_empty());
        assert_ne!(its, group(std::process::id()));
        sink.flush().await.unwrap();
    }

    #[tokio::test]
    async fn a_command_that_cannot_start_fails_the_start() {
        let none = |command: &[&str]| {
            let command = command.iter().map(|s| s.to_string()).collect();
            let e = ExecSink::new(&Arc::from("ask"), &ExecConfig { command });
            format!("{:#}", e.err().expect("no such command"))
        };
        assert!(none(&["/no/such/program"]).starts_with("sink ask: starting `/no/such/program`"));
        assert_eq!(none(&[]), "sink ask: `command` names no program");
        assert_eq!(none(&[""]), "sink ask: `command` names no program");
    }
}
