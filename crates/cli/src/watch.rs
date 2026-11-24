//! `tangent watch`: `tangent init` and `tangent run` in one command, for
//! whoever has no wish to keep a config. What init would write for the same
//! flags goes into a directory of tangent's own, written again at each
//! start, and tangent runs in that directory, so what the pipeline keeps
//! (its lake, each actor's history, the alerts and their reviews) is there
//! too and the next start goes on from it.
//!
//! While it runs it says what the judge flags and what each review finds
//! ([`crate::follow`]), and the runtime's own lines are kept to its
//! warnings (main.rs sets that, before the first of them).
//!
//! It starts only what can run: a variable the config reads and the
//! environment lacks stops it with the list, where `tangent run` would
//! leave a source idle, and a model that is to run here is downloaded
//! first.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use fs2::FileExt as _;
use tangent_runtime::RuntimeOptions;

use crate::follow::Follow;
use crate::init::{self, Choices, Server, Source};
use crate::{fetch, local};

/// The queue a CloudTrail source reads its trail from as it is written.
const QUEUE: &str = "CLOUDTRAIL_QUEUE_URL";

/// The files a pipeline reads when they are beside it, none of them
/// shipped: one of each kind, and what it is.
const OPTIONAL: &[(&str, &str)] = &[
    ("profile.yaml", "your company's profile (profile.yaml)"),
    ("data/networks.csv", "the address tables (data/)"),
];

/// Where the profile and the address tables are described.
const PROFILE: &str =
    "https://github.com/EthanBlackburn/tangent/blob/main/packs/README.md#the-profile";

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
    let env = |name: &str| std::env::var_os(name);

    let missing = unset(&choices.config(), &choices.needs(), env);
    if !missing.is_empty() {
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
    // CloudTrail is read as it is written from a queue, and only from one.
    let queued = env(QUEUE).is_some_and(|v| !v.to_string_lossy().trim().is_empty());
    let trail = choices.watch().contains(&Source::Cloudtrail) && !queued;
    if trail && choices.watch().len() == 1 {
        bail!(
            "CloudTrail is read as it is written from the SQS queue its trail's bucket notifies, and {QUEUE} is not set. Its last day needs no queue: `tangent init cloud --sources cloudtrail`, then `tangent replay --config tangent.yaml --from 1d`"
        );
    }

    let dir = home("cloud", env)?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let _held = hold(&dir)?;
    choices.place(&dir)?;
    // A sink's path is read against the directory tangent runs in, and the
    // file's are its own: the lake, the alerts and their reviews.
    std::env::set_current_dir(&dir).with_context(|| format!("entering {}", dir.display()))?;
    let config = dir.join("tangent.yaml");
    fetch::missing(&config).await?;
    if choices.server() == Server::Mtplx {
        let root = local::root()?;
        let missing = local::missing(&root);
        if !missing.nothing() {
            if !init::ask_to_fetch(&missing, &root) {
                bail!("the model is not on this Mac, so there is nothing to judge with: `tangent model fetch` downloads it");
            }
            local::fetch(&root).await?;
        }
    }

    let watched: Vec<String> = choices.watch().iter().map(Source::to_string).collect();
    println!("\nWatching {}.", watched.join("; "));
    if trail {
        println!(
            "CloudTrail is left out: it is read from the queue {QUEUE} names, which is not set."
        );
    }
    println!("{}.", choices.models());
    println!("Your records {}.", choices.records());
    let absent: Vec<&str> = OPTIONAL
        .iter()
        .filter(|(file, _)| !dir.join(file).exists())
        .map(|(_, what)| *what)
        .collect();
    if !absent.is_empty() {
        println!(
            "It judges without {}: {PROFILE} says what each adds, and they go in the directory below.",
            absent.join(" and ")
        );
    }
    println!(
        "\nEach alert is said here as the judge flags it, and each review as it is written: an actor's\n\
         records are judged together, thirty at a time or an hour after the first, and an alert\n\
         is reviewed a little over an hour after it."
    );
    println!(
        "They are kept, with the pipeline and its lake, in {}",
        dir.display()
    );
    println!("Ctrl-C stops it.\n");

    let (stop, stopped) = tokio::sync::oneshot::channel();
    let said = tokio::spawn(Follow::new(&dir).run(stopped));
    tokio::spawn(async {
        if signalled().await {
            println!(
                "Stopping: the requests a model already has are waited for, and what was waiting is saved for the next start. Ctrl-C again ends them."
            );
        }
    });
    let ran = tangent_runtime::run(&config, RuntimeOptions::default()).await;
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
