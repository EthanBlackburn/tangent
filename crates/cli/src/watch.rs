//! `tangent watch`: runs a pipeline and says what it finds.
//!
//! `watch cloud` and `watch mac` are `tangent init` and the run in one
//! command, for whoever has no wish to keep a config. What init would
//! write for the same flags goes into a directory of tangent's own, written
//! again at each start, and tangent runs in that directory, so what the
//! pipeline keeps (its lake, each actor's history, the alerts and their
//! reviews) is there too and the next start goes on from it. They start
//! only what can run: a variable the config reads and the environment
//! lacks stops them with the list, and a model that is to run here is
//! downloaded first.
//!
//! `watch --config` runs a config of the owner's where they are, as it is:
//! a source whose variable is unset is left idle.
//!
//! While any of them runs it says what the judge checks and flags and what
//! each review finds ([`crate::follow`]); unless `RUST_LOG` is set, the
//! runtime's own logs go to `watch.log` in the pipeline's directory and only
//! errors reach stderr.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use fs2::FileExt as _;
use tangent_runtime::RuntimeOptions;
use tangent_shared::sources::common::SourceConfig;
use tangent_shared::Config;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

use crate::follow::Follow;
use crate::init::{self, Choices, Provider, Server, Source};
use crate::mac::{self, Mac};
use crate::notify::{self, Notifier};
use crate::status::Tracker;
use crate::{fetch, local};

/// The queue a CloudTrail source reads its trail from as it is written.
const QUEUE: &str = "CLOUDTRAIL_QUEUE_URL";

/// Where `tangent watch <what>` keeps its pipeline:
/// `$XDG_DATA_HOME/tangent/<what>`, else `$HOME/.local/share/tangent/<what>`.
/// A variable that is unset, empty or relative is not one.
pub fn data_dir(what: &str) -> Result<PathBuf> {
    home(what, |name| std::env::var_os(name))
}

fn home(what: &str, var: impl Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
    let var = |name| var(name).map(PathBuf::from).filter(|p| p.is_absolute());
    let Some(data) = var("XDG_DATA_HOME").or_else(|| Some(var("HOME")?.join(".local/share")))
    else {
        bail!("tangent watch keeps its pipeline in $XDG_DATA_HOME or $HOME/.local/share, and neither variable is set to an absolute path");
    };
    Ok(data.join("tangent").join(what))
}

/// The variables `config` reads with no value to fall back on, of `needs`,
/// that `var` has nothing for: `${NAME}` in the file, and not
/// `${NAME:-default}`.
pub fn unset(
    config: &str,
    needs: &[(&'static str, &'static str)],
    var: impl Fn(&str) -> Option<OsString>,
) -> Vec<(&'static str, &'static str)> {
    needs
        .iter()
        .filter(|(name, _)| config.contains(&format!("${{{name}}}")))
        .filter(|(name, _)| var(name).is_none_or(|v| v.to_string_lossy().trim().is_empty()))
        .copied()
        .collect()
}

/// `dir`, held as this process's for as long as the file returned lives: a
/// second watch of the same pipeline would write the same lake and history.
fn hold(dir: &Path) -> Result<std::fs::File> {
    let path = dir.join("watch.lock");
    let file =
        std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    if file.try_lock_exclusive().is_err() {
        bail!(
            "another tangent watch is running on {}: stop it first",
            dir.display()
        );
    }
    Ok(file)
}

/// Stops with the list when `config` reads a variable, of `needs`, that
/// the environment lacks.
fn needed(config: &str, needs: &[(&'static str, &'static str)]) -> Result<()> {
    let missing = unset(config, needs, |name| std::env::var_os(name));
    if missing.is_empty() {
        return Ok(());
    }
    let width = missing.iter().map(|(var, _)| var.len()).max().unwrap_or(0);
    let lines: Vec<String> = missing
        .iter()
        .map(|(var, what)| format!("  {var:width$}  {what}"))
        .collect();
    bail!(
        "it reads these from the environment, and they are not set:\n{}",
        lines.join("\n")
    );
}

/// A pipeline to watch: what `tangent init` writes for it, and what watch
/// says of it before it starts.
struct Pipeline {
    /// Its directory's name under tangent's own: what is watched.
    what: &'static str,
    /// Short mode name written into `status.json` (`local` or `hosted`).
    mode: &'static str,
    /// Concise model label shown in `tangent status` and the menu bar.
    models: String,
    /// tangent.yaml and the files beside it.
    files: Vec<(&'static str, String)>,
    server: Server,
    /// What is watched, who judges, and where the records go, as lines.
    said: Vec<String>,
    /// When an alert and a review come.
    pace: &'static str,
    /// How to see it catch something now, where there is a way.
    shown: Option<&'static str>,
    /// Whether it shows no notifications (--no-notify).
    no_notify: bool,
}

/// Whether there is something to watch: `tangent watch cloud` asks it
/// first, before who judges.
pub fn sourced(sources: &[Source]) -> Result<()> {
    if sources.is_empty() {
        bail!(
            "--sources says what to watch: one or more of {}",
            init::names::<Source>(", ")
        );
    }
    Ok(())
}

/// `tangent watch cloud`: the pipeline `tangent init cloud` writes for
/// these flags, kept in tangent's own directory, and run.
pub async fn cloud(
    sources: Vec<Source>,
    server: Server,
    models: Option<(String, String)>,
    no_notify: bool,
) -> Result<()> {
    sourced(&sources)?;
    init::runs_here(server)?;
    let choices = Choices::new(sources, server, models).watched();
    needed(&choices.config(), &choices.needs())?;
    // CloudTrail is read as it is written from a queue, and only from one.
    let queued = std::env::var_os(QUEUE).is_some_and(|v| !v.to_string_lossy().trim().is_empty());
    let trail = choices.watch().contains(&Source::Cloudtrail) && !queued;
    if trail && choices.watch().len() == 1 {
        bail!(
            "CloudTrail is read as it is written from the SQS queue its trail's bucket notifies, and {QUEUE} is not set. Its last day needs no queue: `tangent init cloud` with these flags, then `tangent replay --config tangent.yaml --from 1d`"
        );
    }

    let watched: Vec<String> = choices.watch().iter().map(Source::to_string).collect();
    let mut said = vec![format!("Watching {}.", watched.join("; "))];
    if trail {
        said.push(format!(
            "CloudTrail is left out: it is read from the queue {QUEUE} names, which is not set."
        ));
    }
    said.push(format!("{}.", choices.models()));
    said.push(format!("Your records {}.", choices.records()));
    let mode = match server {
        Server::Ollama | Server::Yours => "local",
        Server::Hosted(_) => "hosted",
    };
    start(Pipeline {
        what: "cloud",
        mode,
        models: choices.models(),
        files: choices.files(),
        server,
        said,
        pace: "an actor's\n\
               records are judged together, thirty at a time or an hour after the first, and an alert\n\
               is reviewed a little over an hour after it.",
        shown: None,
        no_notify,
    })
    .await
}

/// `tangent watch mac`: the pipeline `tangent init mac` writes, kept in
/// tangent's own directory, and run.
pub async fn mac(
    provider: Option<Provider>,
    named: Option<(String, String)>,
    no_notify: bool,
) -> Result<()> {
    let (who, pair) = mac::brief_of(provider, named.as_ref());
    let mac = Mac::new(provider).naming(named)?.watched();
    mac::runs_here(&mac)?;
    needed(&mac.config(), &mac.needs())?;
    let mode = if provider.is_some() { "hosted" } else { "local" };
    let models = format!("{pair} · {who}");
    start(Pipeline {
        what: "mac",
        mode,
        models,
        files: mac.files(),
        server: mac.server(),
        said: vec![
            "Watching this Mac: what each program runs, opens and connects to, and what you ask Claude Code."
                .to_string(),
            format!("{}.", mac.models()),
            format!("Your records {}.", mac.records()),
            mac::BY_HAND.to_string(),
        ],
        pace: "a session\n\
               is judged five minutes at a time, or an agent's turn at its end, and an alert is\n\
               reviewed as soon as it is raised.",
        shown: Some("To see it catch an attack, run `tangent simulate` in another terminal."),
        no_notify,
    })
    .await
}

/// Prints one confirmation line once the pipeline (or Mac sensor, after
/// `sudo`) is live, so the terminal is not left blank after startup, and
/// marks `status.json` as watching.
struct Ready {
    target: &'static str,
    message: &'static str,
    printed: AtomicBool,
    status: Option<Tracker>,
}

impl Ready {
    fn for_config(config: &Path, status: Option<Tracker>) -> Self {
        let has_mac = Config::load(config).is_ok_and(|loaded| {
            loaded
                .config
                .sources
                .values()
                .any(|s| matches!(s, SourceConfig::Macos(_)))
        });
        if has_mac {
            Self {
                target: "tangent_runtime::sources::macos",
                message: "the sensor is started",
                printed: AtomicBool::new(false),
                status,
            }
        } else {
            Self {
                target: "tangent_runtime",
                message: "pipeline started",
                printed: AtomicBool::new(false),
                status,
            }
        }
    }
}

struct MessageMatches {
    want: &'static str,
    matched: bool,
}

impl tracing::field::Visit for MessageMatches {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" && value == self.want {
            self.matched = true;
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" && format!("{value:?}") == self.want {
            self.matched = true;
        }
    }
}

/// An event's message, as text.
struct Message(String);

impl tracing::field::Visit for Message {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

/// What the runtime logs when the Mac's source ends on an error, before the
/// error itself. The runtime goes on without a source that failed, which is
/// right for one audit log of several and not for the one thing a Mac's
/// watch reads.
const NO_SENSOR: &str = "macos source error: ";

/// Asks this process to stop as a signal would, so what waits for a model
/// is saved, and again a moment later, which ends the requests under way.
fn stop_this_process() {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("/bin/sh")
            .args(["-c", "kill -TERM \"$0\"; sleep 2; kill -TERM \"$0\" 2>/dev/null", &std::process::id().to_string()])
            .stdin(std::process::Stdio::null())
            .spawn();
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Ready {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // A watch tangent keeps the status of ends when its sensor does:
        // status.json says why, which is how the menu bar and `tangent up`
        // come to ask for Full Disk Access, and launchd starts it again.
        if let Some(status) = &self.status {
            let meta = event.metadata();
            if meta.target() == "tangent_runtime::dag" && *meta.level() == tracing::Level::ERROR {
                let mut said = Message(String::new());
                event.record(&mut said);
                if let Some(why) = said.0.strip_prefix(NO_SENSOR) {
                    status.set_error(why);
                    stop_this_process();
                }
                return;
            }
        }
        if self.printed.load(Ordering::Relaxed) || event.metadata().target() != self.target {
            return;
        }
        let mut check = MessageMatches {
            want: self.message,
            matched: false,
        };
        event.record(&mut check);
        if check.matched && !self.printed.swap(true, Ordering::SeqCst) {
            if let Some(status) = &self.status {
                status.set_watching();
            }
            println!("Started. Activity will show up here.");
        }
    }
}

/// Routes runtime logs to `watch.log` in `dir` (info+) and only errors to
/// stderr, when `RUST_LOG` was not set (otherwise `main` already initialized
/// stderr tracing and `try_init` is a no-op).
fn init_logging(dir: &Path, ready: Option<Ready>) -> Option<PathBuf> {
    if std::env::var_os("RUST_LOG").is_some() {
        return None;
    }
    let path = dir.join("watch.log");
    let stderr = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(EnvFilter::new("error"));
    let file_layer = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()
        .map(|file| {
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(Mutex::new(file))
                .with_filter(EnvFilter::new("info"))
        });
    let logged = file_layer.is_some();
    let _ = tracing_subscriber::registry()
        .with(stderr)
        .with(file_layer)
        .with(ready)
        .try_init();
    logged.then_some(path)
}

/// Writes the pipeline to its directory, fetches what it needs, says what
/// it is, and runs it there until a signal, saying what it finds.
async fn start(pipeline: Pipeline) -> Result<()> {
    let dir = data_dir(pipeline.what)?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let _held = hold(&dir)?;
    let status = Tracker::start(&dir, pipeline.mode, &pipeline.models);
    init::place(&dir, &pipeline.files)?;
    // A sink's path is read against the directory tangent runs in, and the
    // file's are its own: the lake, the alerts and their reviews.
    std::env::set_current_dir(&dir).with_context(|| format!("entering {}", dir.display()))?;
    let config = dir.join("tangent.yaml");
    let log = init_logging(&dir, Some(Ready::for_config(&config, Some(status.clone()))));
    if let Err(e) = fetch::missing(&config).await {
        status.set_error(&format!("{e:#}"));
        return Err(e);
    }
    if pipeline.server == Server::Ollama {
        let root = local::root()?;
        let missing = local::missing(&root);
        if !missing.nothing() {
            if !init::ask_to_fetch(&missing, &root) {
                let msg = "the model is not on this Mac, so there is nothing to judge with: `tangent model fetch` downloads it";
                status.set_error(msg);
                bail!("{msg}");
            }
            if let Err(e) = local::fetch(&root).await {
                status.set_error(&format!("{e:#}"));
                return Err(e);
            }
        }
    }

    println!("\n{}", pipeline.said.join("\n"));
    println!(
        "\nEach alert is said here as the judge marks it, and each review as it is written: {}",
        pipeline.pace
    );
    println!(
        "They are kept, with the pipeline and its lake, in {}",
        dir.display()
    );
    if let Some(log) = log {
        println!(
            "Runtime log: {} (set RUST_LOG=info for verbose terminal logs).",
            log.display()
        );
    }
    let notifier = match notify::app(&config, pipeline.no_notify).await {
        Some(app) => Notifier::start(app).await,
        None => None,
    };
    if notifier.is_some() {
        println!(
            "A review that upholds an alert is a notification on this Mac too, once you allow Tangent's (--no-notify shows none)."
        );
    }
    if let Some(shown) = pipeline.shown {
        println!("{shown}");
    }
    println!("Ctrl-C stops it.\n");

    following(
        &dir,
        &config,
        RuntimeOptions::default(),
        notifier,
        Some(status),
    )
    .await
}

/// `tangent watch --config`: the owner's config, run where they are.
pub async fn config(config: PathBuf, once: bool, no_notify: bool) -> Result<()> {
    let config = config.canonicalize().unwrap_or(config);
    // A sink's path is read against the directory tangent runs in.
    let dir = std::env::current_dir().context("reading the directory this runs in")?;
    let ready = (!once).then(|| Ready::for_config(&config, None));
    let log = init_logging(&dir, ready);
    fetch::missing(&config).await?;
    let notifier = match notify::app(&config, no_notify).await {
        Some(app) => Notifier::start(app).await,
        None => None,
    };
    if !once {
        if let Some(log) = log {
            println!(
                "Watching {}. Runtime log: {} (Ctrl-C stops it).\n",
                config.display(),
                log.display()
            );
        }
    }
    let opts = RuntimeOptions {
        once,
        ..Default::default()
    };
    following(&dir, &config, opts, notifier, None).await
}

/// How long the pipeline's review plugin holds an alert before starting the
/// reviewer (`expire_after_ms` on `macos_review` or `review`), so `Follow`
/// can tell the user when a queued review will begin.
fn review_wait(config: &Path) -> Option<Duration> {
    let cfg = Config::load(config).ok()?.config;
    let plugin = cfg
        .plugins
        .get("macos_review")
        .or_else(|| cfg.plugins.get("review"))?;
    Some(Duration::from_millis(plugin.expire_after_ms))
}

/// Runs `config` until it ends or a signal, saying what it writes in
/// `dir`, the directory it runs in, and showing through `notifier`, when
/// there is one, the reviews that are notifications.
async fn following(
    dir: &Path,
    config: &PathBuf,
    opts: RuntimeOptions,
    notifier: Option<Notifier>,
    status: Option<Tracker>,
) -> Result<()> {
    let wait = review_wait(config);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let said = tokio::spawn(Follow::new(dir, notifier, wait, status.clone()).run(stopped));
    tokio::spawn(async {
        if signalled().await {
            println!(
                "Stopping: the requests a model already has are waited for, and what was waiting is saved for the next start. Ctrl-C again ends them."
            );
        }
    });
    let ran = tangent_runtime::run(config, opts).await;
    let _ = stop.send(());
    let _ = said.await;
    if let Some(status) = status {
        match (&ran, status.failed()) {
            // The sensor ended it: the status says why already, and the
            // exit is a failure, so launchd starts it again.
            (_, Some(why)) => bail!("{why}"),
            (Ok(()), None) => status.set_stopped(),
            (Err(e), None) => status.set_error(&format!("{e:#}")),
        }
    }
    ran
}

/// Waits for the signal that stops the pipeline, which the runtime hears
/// too. False when this process cannot listen for one.
async fn signalled() -> bool {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let Ok(mut term) = signal(SignalKind::terminate()) else {
            return false;
        };
        tokio::select! {
            got = tokio::signal::ctrl_c() => got.is_ok(),
            _ = term.recv() => true,
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::Provider;

    fn vars(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        move |name| {
            let (_, value) = vars.iter().find(|(n, _)| *n == name)?;
            Some(OsString::from(value))
        }
    }

    /// The pipeline is kept under the data directory, XDG's or the home's,
    /// by what is watched.
    #[test]
    fn the_pipeline_is_kept_in_the_data_directory() {
        let both = vars(&[("XDG_DATA_HOME", "/x/data"), ("HOME", "/home/me")]);
        assert_eq!(
            home("cloud", both).unwrap(),
            PathBuf::from("/x/data/tangent/cloud")
        );
        for xdg in ["", "relative/data"] {
            let home_only = move |name: &str| match name {
                "XDG_DATA_HOME" => Some(OsString::from(xdg)),
                "HOME" => Some(OsString::from("/home/me")),
                _ => None,
            };
            assert_eq!(
                home("cloud", home_only).unwrap(),
                PathBuf::from("/home/me/.local/share/tangent/cloud"),
                "XDG_DATA_HOME={xdg:?}"
            );
        }
        let e = home("cloud", vars(&[])).unwrap_err().to_string();
        assert!(e.contains("XDG_DATA_HOME") && e.contains("HOME"), "{e}");
    }

    /// A variable the file reads with nothing to fall back on is needed,
    /// and one with a default is not: on Bedrock with CloudTrail,
    /// AWS_PROFILE falls back to `default`, and nothing is missing.
    #[test]
    fn a_variable_with_no_default_is_needed() {
        let okta = Choices::new(
            vec![Source::Okta],
            Server::Hosted(Provider::Anthropic),
            None,
        );
        let names = |missing: Vec<(&'static str, &'static str)>| -> Vec<&'static str> {
            missing.into_iter().map(|(var, _)| var).collect()
        };
        assert_eq!(
            names(unset(&okta.config(), &okta.needs(), vars(&[]))),
            ["ANTHROPIC_API_KEY", "OKTA_ORG_URL", "OKTA_API_TOKEN"]
        );
        let some = vars(&[("ANTHROPIC_API_KEY", "k"), ("OKTA_ORG_URL", "  ")]);
        assert_eq!(
            names(unset(&okta.config(), &okta.needs(), some)),
            ["OKTA_ORG_URL", "OKTA_API_TOKEN"],
            "a blank value is none"
        );
        let aws = Choices::new(
            vec![Source::Cloudtrail],
            Server::Hosted(Provider::Bedrock),
            None,
        );
        assert!(!aws.needs().is_empty());
        assert!(unset(&aws.config(), &aws.needs(), vars(&[])).is_empty());
    }

    /// A directory is one watch's at a time.
    #[test]
    fn a_directory_is_held_by_one_watch() {
        let dir = tempfile::tempdir().unwrap();
        let held = hold(dir.path()).unwrap();
        let e = hold(dir.path()).unwrap_err().to_string();
        assert!(e.contains("another tangent watch"), "{e}");
        drop(held);
        hold(dir.path()).unwrap();
    }
}
