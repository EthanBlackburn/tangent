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
//! each review finds ([`crate::follow`]), among the runtime's own lines.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use fs2::FileExt as _;
use tangent_runtime::RuntimeOptions;

use crate::follow::Follow;
use crate::init::{self, Choices, Server, Source};
use crate::mac::{self, Mac};
use crate::{fetch, local};

/// The queue a CloudTrail source reads its trail from as it is written.
const QUEUE: &str = "CLOUDTRAIL_QUEUE_URL";

/// Where `tangent watch <what>` keeps its pipeline:
/// `$XDG_DATA_HOME/tangent/<what>`, else `$HOME/.local/share/tangent/<what>`.
/// A variable that is unset, empty or relative is not one.
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
fn unset(
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
    /// tangent.yaml and the files beside it.
    files: Vec<(&'static str, String)>,
    server: Server,
    /// What is watched, who judges, and where the records go, as lines.
    said: Vec<String>,
    /// When an alert and a review come.
    pace: &'static str,
    /// How to see it catch something now, where there is a way.
    shown: Option<&'static str>,
}

/// `tangent watch cloud`: the pipeline `tangent init cloud` writes for
/// these flags, kept in tangent's own directory, and run.
pub async fn cloud(
    sources: Vec<Source>,
    server: Server,
    models: Option<(String, String)>,
) -> Result<()> {
    if sources.is_empty() {
        bail!(
            "--sources says what to watch: one or more of {}",
            init::names::<Source>(", ")
        );
    }
    init::runs_here(server)?;
    let choices = Choices::new(sources, server, models).watched();
    needed(&choices.config(), &choices.needs())?;
    // CloudTrail is read as it is written from a queue, and only from one.
    let queued = std::env::var_os(QUEUE).is_some_and(|v| !v.to_string_lossy().trim().is_empty());
    let trail = choices.watch().contains(&Source::Cloudtrail) && !queued;
    if trail && choices.watch().len() == 1 {
        bail!(
            "CloudTrail is read as it is written from the SQS queue its trail's bucket notifies, and {QUEUE} is not set. Its last day needs no queue: `tangent init cloud --sources cloudtrail`, then `tangent replay --config tangent.yaml --from 1d`"
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
    start(Pipeline {
        what: "cloud",
        files: choices.files(),
        server,
        said,
        pace: "an actor's\n\
               records are judged together, thirty at a time or an hour after the first, and an alert\n\
               is reviewed a little over an hour after it.",
        shown: None,
    })
    .await
}

/// `tangent watch mac`: the pipeline `tangent init mac` writes, kept in
/// tangent's own directory, and run.
pub async fn mac(hosted: bool) -> Result<()> {
    let mac = Mac::new(hosted).watched();
    mac::runs_here(&mac)?;
    needed(&mac.config(), &mac.needs())?;
    start(Pipeline {
        what: "mac",
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
               reviewed about seven minutes after it.",
        shown: Some("To see it catch an attack, run `tangent simulate` in another terminal."),
    })
    .await
}

/// Writes the pipeline to its directory, fetches what it needs, says what
/// it is, and runs it there until a signal, saying what it finds.
async fn start(pipeline: Pipeline) -> Result<()> {
    let dir = home(pipeline.what, |name| std::env::var_os(name))?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let _held = hold(&dir)?;
    init::place(&dir, &pipeline.files)?;
    // A sink's path is read against the directory tangent runs in, and the
    // file's are its own: the lake, the alerts and their reviews.
    std::env::set_current_dir(&dir).with_context(|| format!("entering {}", dir.display()))?;
    let config = dir.join("tangent.yaml");
    fetch::missing(&config).await?;
    if pipeline.server == Server::Mtplx {
        let root = local::root()?;
        let missing = local::missing(&root);
        if !missing.nothing() {
            if !init::ask_to_fetch(&missing, &root) {
                bail!("the model is not on this Mac, so there is nothing to judge with: `tangent model fetch` downloads it");
            }
            local::fetch(&root).await?;
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
    if let Some(shown) = pipeline.shown {
        println!("{shown}");
    }
    println!("Ctrl-C stops it.\n");

    following(&dir, &config, RuntimeOptions::default()).await
}

/// `tangent watch --config`: the owner's config, run where they are.
pub async fn config(config: PathBuf, once: bool) -> Result<()> {
    let config = config.canonicalize().unwrap_or(config);
    fetch::missing(&config).await?;
    // A sink's path is read against the directory tangent runs in.
    let dir = std::env::current_dir().context("reading the directory this runs in")?;
    let opts = RuntimeOptions {
        once,
        ..Default::default()
    };
    following(&dir, &config, opts).await
}

/// Runs `config` until it ends or a signal, saying what it writes in
/// `dir`, the directory it runs in.
async fn following(dir: &Path, config: &PathBuf, opts: RuntimeOptions) -> Result<()> {
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let said = tokio::spawn(Follow::new(dir).run(stopped));
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
