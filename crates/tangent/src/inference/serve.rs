//! A model's server, when tangent runs it: `serve` on a `models` entry.
//!
//! - A server that already answers at the model's `url` is used as it is:
//!   nothing is started, and nothing is stopped when tangent stops.
//! - Otherwise the command is started, and the pipeline is not built until
//!   it answers: a GET of `<url>/models` that gets any reply but a server
//!   error. A command that ends first, or has not answered in [`READY`], is
//!   tangent's error, and so is a signal while it starts.
//! - It runs in a process group of its own, so the terminal's Ctrl-C, which
//!   reaches tangent, does not reach it: the model calls tangent finishes as
//!   it stops still find it answering.
//! - Tangent ends it, once the pipeline has shut down: SIGTERM to its group,
//!   and the kill if it is still there [`STOP`] later. An exit that shuts
//!   nothing down ([`end_now`]) and a pipeline dropped half-built send the
//!   SIGTERM alone. If tangent is killed outright the server is left
//!   running, and the next run finds it answering and uses it.
//!
//! What it prints is tangent's debug log; its last lines are in the error
//! when it ends unasked.

use std::collections::{BTreeMap, VecDeque};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tangent_shared::models::{ModelConfig, ServeConfig};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// How long a server has to answer after it is started: a model of tens of
/// gigabytes is read from disk first.
const READY: Duration = Duration::from_secs(600);
/// How often it is asked while it starts, and how long one ask waits.
const POLL: Duration = Duration::from_millis(250);
const ASK: Duration = Duration::from_secs(2);
/// How long it has to end after SIGTERM before it is killed.
const STOP: Duration = Duration::from_secs(10);
/// How long the readers of what it printed get to reach the end, once it has
/// ended.
const READ: Duration = Duration::from_millis(500);
/// How many of its last lines an error repeats.
const TAIL: usize = 5;

/// The process groups of the servers running now, for [`end_now`].
static RUNNING: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// SIGTERM to every server tangent started, for an exit that drops nothing
/// and waits for nothing: the signal that exits at once.
pub fn end_now() {
    for group in RUNNING.lock().unwrap().drain(..) {
        signal(group, Signal::End);
    }
}

enum Signal {
    End,
    Kill,
}

/// A signal to a server's whole process group: the server and whatever it
/// started.
fn signal(group: u32, signal: Signal) {
    #[cfg(unix)]
    {
        let signal = match signal {
            Signal::End => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
        };
        // SAFETY: `killpg` takes a group and a signal number and touches no
        // memory.
        unsafe { libc::killpg(group as libc::pid_t, signal) };
    }
    #[cfg(not(unix))]
    let _ = (group, signal);
}

/// A server tangent started, until [`Served::stop`] or the drop.
pub struct Served {
    stop: CancellationToken,
    ended: JoinHandle<()>,
}

impl Served {
    /// Ends the server and waits until it has.
    pub async fn stop(mut self) {
        self.stop.cancel();
        let _ = (&mut self.ended).await;
    }
}

impl Drop for Served {
    /// A pipeline that failed to start, or to stop, still ends its servers.
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// Starts the server of every model with `serve` that is not answering
/// already, one at a time, and returns once each answers.
pub async fn start(models: &BTreeMap<Arc<str>, ModelConfig>) -> Result<Vec<Served>> {
    let http = reqwest::Client::builder().timeout(ASK).build()?;
    let mut served = Vec::new();
    for (name, model) in models {
        let (Some(serve), Some(url)) = (&model.serve, &model.url) else {
            continue;
        };
        if answers(&http, url).await {
            tracing::info!(model = %name, "already answering at {url}; `serve.command` is not started");
            continue;
        }
        served.push(serve_one(name, serve, url, &http).await?);
    }
    Ok(served)
}

/// Whether a server is there: any reply to `<url>/models` but a server
/// error, which is what one still loading its model gives.
async fn answers(http: &reqwest::Client, url: &str) -> bool {
    let models = format!("{}/models", url.trim_end_matches('/'));
    matches!(http.get(models).send().await, Ok(reply) if !reply.status().is_server_error())
}

async fn serve_one(
    name: &Arc<str>,
    serve: &ServeConfig,
    url: &str,
    http: &reqwest::Client,
) -> Result<Served> {
    let program = &serve.command[0];
    let mut server = Server::start(name, serve)?;

    tracing::info!(model = %name, "starting `{program}` and waiting for it at {url}");
    let began = Instant::now();
    // Ctrl-C does not reach the server, and nothing else of tangent's waits
    // for a signal this early: without this the terminal would have no way
    // to end a model that takes minutes to load.
    let signalled = crate::wait_for_shutdown_signal();
    tokio::pin!(signalled);
    loop {
        tokio::select! {
            status = server.child.wait() => bail!(
                "model {name}: `{program}` ended ({}) before it answered at {url}{}",
                status?,
                server.printed.last().await
            ),
            _ = &mut signalled => {
                server.end().await;
                bail!("model {name}: stopped by a signal while `{program}` was starting");
            }
            () = tokio::time::sleep(POLL) => {}
        }
        if answers(http, url).await {
            break;
        }
        if began.elapsed() > READY {
            server.end().await;
            bail!(
                "model {name}: `{program}` had not answered at {url} after {} minutes{}",
                READY.as_secs() / 60,
                server.printed.last().await
            );
        }
    }
    tracing::info!(model = %name, "answering at {url}, {:.0?} after it was started", began.elapsed());

    let stop = CancellationToken::new();
    let ended = tokio::spawn(watch(server, stop.clone()));
    Ok(Served { stop, ended })
}

/// The server from when it answers: ended at `stop`, and an error in the log
/// if it ends before, since every request to its model fails from then on.
async fn watch(mut server: Server, stop: CancellationToken) {
    tokio::select! {
        () = stop.cancelled() => server.end().await,
        status = server.child.wait() => {
            let status = status.map_or_else(|e| e.to_string(), |s| s.to_string());
            tracing::error!(
                model = %server.name,
                "its server ended ({status}); requests to it fail from here on{}",
                server.printed.last().await
            );
        }
    }
}

/// A server's process, the first of a process group of its own.
struct Server {
    name: Arc<str>,
    child: Child,
    printed: Printed,
    /// Its process group, which has its pid.
    group: u32,
}

impl Server {
    fn start(name: &Arc<str>, serve: &ServeConfig) -> Result<Self> {
        let program = &serve.command[0];
        let mut command = Command::new(program);
        command
            .args(&serve.command[1..])
            .envs(&serve.env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command
            .spawn()
            .with_context(|| format!("model {name}: starting `{program}`"))?;
        let group = child.id().expect("a child not yet waited for has a pid");
        RUNNING.lock().unwrap().push(group);
        let printed = Printed::of(name, &mut child);
        Ok(Self {
            name: name.clone(),
            child,
            printed,
            group,
        })
    }

    /// Whether it has not been seen to end. Once it has, its pid may be
    /// another process's, and nothing more is signalled.
    fn running(&self) -> bool {
        self.child.id().is_some()
    }

    /// SIGTERM to its group, then the kill if it is still there [`STOP`]
    /// later.
    async fn end(&mut self) {
        if !self.running() {
            return;
        }
        signal(self.group, Signal::End);
        #[cfg(not(unix))]
        let _ = self.child.start_kill();
        if tokio::time::timeout(STOP, self.child.wait()).await.is_err() {
            tracing::warn!(model = %self.name, "its server was still there {STOP:?} after it was asked to end; it is killed");
            signal(self.group, Signal::Kill);
            let _ = self.child.kill().await;
        }
    }
}

impl Drop for Server {
    /// Dropped while it runs (a pipeline dropped half-built, a runtime that
    /// ends before the stop): it is asked to end, and not waited for.
    fn drop(&mut self) {
        if self.running() {
            signal(self.group, Signal::End);
        }
        RUNNING.lock().unwrap().retain(|group| *group != self.group);
    }
}

/// What a server prints, read for as long as it prints so it never waits on
/// a full pipe: each line to the debug log, the last [`TAIL`] kept.
struct Printed {
    tail: Arc<Mutex<VecDeque<String>>>,
    readers: Vec<JoinHandle<()>>,
}

impl Printed {
    fn of(name: &Arc<str>, child: &mut Child) -> Self {
        let tail = Arc::default();
        let out = child.stdout.take().expect("its stdout is piped");
        let err = child.stderr.take().expect("its stderr is piped");
        let readers = vec![read(name, out, &tail), read(name, err, &tail)];
        Self { tail, readers }
    }

    /// Its last lines, for an error about a server that has ended. The
    /// readers are given a moment to reach the end of what it printed; a
    /// program it started may hold the pipe open past that.
    async fn last(&mut self) -> String {
        for reader in &mut self.readers {
            let _ = tokio::time::timeout(READ, reader).await;
        }
        let tail = self.tail.lock().unwrap();
        if tail.is_empty() {
            return ": it printed nothing".to_string();
        }
        let lines: Vec<&str> = tail.iter().map(String::as_str).collect();
        format!(": {}", lines.join("; "))
    }
}

fn read(
    name: &Arc<str>,
    out: impl AsyncRead + Unpin + Send + 'static,
    tail: &Arc<Mutex<VecDeque<String>>>,
) -> JoinHandle<()> {
    let (name, tail) = (name.clone(), tail.clone());
    tokio::spawn(async move {
        let mut out = BufReader::new(out);
        let mut line = Vec::new();
        while matches!(out.read_until(b'\n', &mut line).await, Ok(n) if n > 0) {
            let printed = String::from_utf8_lossy(&line).trim_end().to_string();
            line.clear();
            tracing::debug!(model = %name, "{printed}");
            let mut tail = tail.lock().unwrap();
            if tail.len() == TAIL {
                tail.pop_front();
            }
            tail.push_back(printed);
        }
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::Path;
    use tangent_shared::models::ModelKind;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Held by each test that starts a command: `end_now` ends every
    /// server this process started, another test's included.
    static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// One model, `m`, at `url`, whose server is `sh -c <script> <file>`:
    /// `$0` is the file.
    fn models(url: &str, script: &str, file: &Path) -> BTreeMap<Arc<str>, ModelConfig> {
        let command = ["sh", "-c", script, &file.to_string_lossy()]
            .map(String::from)
            .to_vec();
        let model = ModelConfig {
            kind: ModelKind::Openai,
            url: Some(url.to_string()),
            api_key: None,
            model: "m".into(),
            aws: Default::default(),
            concurrency: 1,
            timeout_ms: 1_000,
            retries: 0,
            fallback: None,
            serve: Some(ServeConfig {
                command,
                env: BTreeMap::from([("WHO".to_string(), "tangent".to_string())]),
            }),
        };
        BTreeMap::from([(Arc::from("m"), model)])
    }

    /// Answers every request on `listener` with an empty object.
    fn answer(listener: TcpListener) {
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut request = [0u8; 4096];
                let _ = sock.read(&mut request).await;
                let reply = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
                let _ = sock.write_all(reply.as_bytes()).await;
            }
        });
    }

    /// A port nothing listens on, and the URL of a model there.
    async fn free() -> (std::net::SocketAddr, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        (at, format!("http://{at}/v1"))
    }

    fn running(pid: i32) -> bool {
        // SAFETY: signal 0 sends nothing; it asks whether the pid is there.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    /// The pid and the rest of what the script wrote to `file`, once it has.
    async fn written(file: &Path) -> (i32, String) {
        for _ in 0..200 {
            if let Ok(text) = std::fs::read_to_string(file) {
                if let Some((pid, rest)) = text.trim_end().split_once(' ') {
                    return (pid.parse().unwrap(), rest.to_string());
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the command wrote nothing to {}", file.display());
    }

    /// The command as the model's server: it writes its pid and `$WHO`, and
    /// something answers at `url` once it has.
    async fn started(dir: &Path) -> (Vec<Served>, i32, String) {
        let (at, url) = free().await;
        let file = dir.join("pid");
        let models = models(&url, r#"echo "$$ $WHO" > "$0"; exec sleep 100"#, &file);
        let up = {
            let file = file.clone();
            tokio::spawn(async move {
                let said = written(&file).await;
                answer(TcpListener::bind(at).await.unwrap());
                said
            })
        };
        let served = start(&models).await.unwrap();
        let (pid, who) = up.await.unwrap();
        (served, pid, who)
    }

    #[tokio::test]
    async fn a_server_already_answering_is_used_and_nothing_is_started() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        answer(listener);
        let file = dir.path().join("started");
        let models = models(&url, r#"touch "$0""#, &file);

        let served = start(&models).await.unwrap();
        assert!(served.is_empty());
        assert!(!file.exists());
    }

    #[tokio::test]
    async fn it_is_started_with_its_env_waited_for_and_stopped() {
        let _one = ONE.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let (mut served, pid, who) = started(dir.path()).await;
        assert_eq!(who, "tangent");
        assert_eq!(served.len(), 1);
        assert!(running(pid));

        served.pop().unwrap().stop().await;
        assert!(!running(pid));
    }

    /// The terminal's Ctrl-C goes to tangent's process group, and the
    /// server is in one of its own.
    #[tokio::test]
    async fn the_server_is_in_a_process_group_of_its_own() {
        let _one = ONE.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let (mut served, pid, _) = started(dir.path()).await;
        // SAFETY: both ask for a process group's number and touch nothing.
        let (its, ours) = unsafe { (libc::getpgid(pid), libc::getpgrp()) };
        assert_eq!(its, pid);
        assert_ne!(its, ours);
        served.pop().unwrap().stop().await;
    }

    /// A server that starts another program (a wrapper script, a worker)
    /// takes it along when it is ended.
    #[tokio::test]
    async fn what_the_server_started_ends_with_it() {
        let _one = ONE.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let (at, url) = free().await;
        let file = dir.path().join("pid");
        // The script starts a sleep of its own and writes that one's pid.
        let models = models(&url, r#"sleep 100 & echo "$! $WHO" > "$0"; wait"#, &file);
        let up = {
            let file = file.clone();
            tokio::spawn(async move {
                let wrote = written(&file).await;
                answer(TcpListener::bind(at).await.unwrap());
                wrote
            })
        };
        let mut served = start(&models).await.unwrap();
        let (started_by_it, _) = up.await.unwrap();
        assert!(running(started_by_it));

        served.pop().unwrap().stop().await;
        for _ in 0..200 {
            if !running(started_by_it) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("what the server started was still running five seconds after the stop");
    }

    /// The exit that shuts nothing down ends the servers on its way.
    #[tokio::test]
    async fn an_exit_at_once_ends_the_servers() {
        let _one = ONE.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let (served, pid, _) = started(dir.path()).await;
        assert!(running(pid));

        end_now();
        for _ in 0..200 {
            if !running(pid) {
                drop(served);
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the server was still running five seconds after end_now");
    }

    /// A pipeline that fails after its servers are up drops them.
    #[tokio::test]
    async fn a_server_dropped_is_ended() {
        let _one = ONE.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let (served, pid, _) = started(dir.path()).await;
        assert!(running(pid));

        drop(served);
        for _ in 0..200 {
            if !running(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the server was still running five seconds after the drop");
    }

    #[tokio::test]
    async fn a_command_that_ends_before_it_answers_is_the_error() {
        let _one = ONE.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let (_, url) = free().await;
        let models = models(&url, "echo no such model >&2; exit 3", dir.path());

        let Err(e) = start(&models).await else {
            panic!("a server that ended was taken as started");
        };
        assert_eq!(
            e.to_string(),
            format!(
                "model m: `sh` ended (exit status: 3) before it answered at {url}: no such model"
            )
        );
    }

    #[tokio::test]
    async fn a_command_that_cannot_start_is_the_error() {
        let (_, url) = free().await;
        let mut models = models(&url, "", Path::new(""));
        models.get_mut("m").unwrap().serve.as_mut().unwrap().command =
            vec!["/no/such/program".to_string()];

        let Err(e) = start(&models).await else {
            panic!("a program that is not there was taken as started");
        };
        assert_eq!(e.to_string(), "model m: starting `/no/such/program`");
    }
}
