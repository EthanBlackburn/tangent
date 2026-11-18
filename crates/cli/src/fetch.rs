//! `tangent plugin fetch`: each plugin's compiled component from the release
//! its `prebuilt` names, checked against GitHub's attestation of the build,
//! and precompiled into tangent's cache, per tangent version and engine
//! (`~/.cache/tangent/<version>/plugins/<engine>`), where `tangent run` reads
//! it when `runtime.plugins_path` has no build of its own. Only a pack's
//! author needs the WASM toolchain: a component built once runs on every
//! machine.
//!
//! The check is tangent's own ([`crate::attest`]), with no other program:
//! the component's attestation (a Sigstore bundle, the asset beside it on
//! the release) must be signed by `repo`'s workflow, for the release's tag,
//! and name the component by its digest as the asset asked for. Nothing but
//! the two downloads touches the network. There is no way to skip the
//! check: a plugin reads every record and this one came off the network.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use tangent_shared::plugins::{self, PluginConfig, Prebuilt};
use tangent_shared::Config;

use crate::attest::{self, Attested};

/// This tangent's version: the release a `prebuilt` without `release` is on.
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub struct FetchOptions {
    pub config_path: PathBuf,
    /// One plugin, or every plugin with `prebuilt`.
    pub plugin: Option<String>,
}

pub async fn run(opts: FetchOptions) -> Result<()> {
    let cfg = Config::from_file(&opts.config_path)?;
    let config_dir = opts.config_path.parent().unwrap_or_else(|| Path::new("."));
    let plugins_dir = config_dir.join(&cfg.runtime.plugins_path);
    let cache = tangent_shared::cache::plugins()?;

    if let Some(only) = &opts.plugin {
        if !cfg.plugins.contains_key(only.as_str()) {
            bail!("plugin {only} not found in {}", opts.config_path.display());
        }
    }
    let client = client()?;
    let mut fetched = 0;
    for (name, plugin) in &cfg.plugins {
        if opts
            .plugin
            .as_deref()
            .is_some_and(|only| only != name.as_ref())
        {
            continue;
        }
        let Some(prebuilt) = &plugin.prebuilt else {
            if opts.plugin.is_some() {
                bail!("plugin {name} has no `prebuilt`: `tangent plugin compile` builds it from its source");
            }
            println!(
                "· {name}: no `prebuilt`; `tangent plugin compile` builds it from {}",
                plugin.path.display()
            );
            continue;
        };
        let out = plugins::fetched(&cache, prebuilt);
        fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
        fetch_one(&client, name, plugin, prebuilt, &out).await?;
        fetched += 1;
        if let Some(local) = remove_local_build(name, plugin, &plugins_dir)? {
            println!(
                "   removed {}, a `tangent plugin compile` build, which would run in its place",
                local.display()
            );
        }
    }

    if fetched > 0 {
        println!(
            "\nEach component and its attestation bundle are kept under {}",
            cache.display()
        );
    }
    Ok(())
}

/// Plugin `name`'s local build ([`plugins::built`]), removed after a fetch,
/// since it would run in place of the copy just fetched: whichever of
/// `tangent plugin compile` and `fetch` ran last is what runs, as when both
/// wrote `runtime.plugins_path`. Its path, when there was one.
fn remove_local_build(
    name: &str,
    plugin: &PluginConfig,
    plugins_dir: &Path,
) -> Result<Option<PathBuf>> {
    let Some(built) = plugins::built(name, plugin, plugins_dir) else {
        return Ok(None);
    };
    match fs::remove_file(&built) {
        Ok(()) => Ok(Some(built)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("removing {}", built.display())),
    }
}

/// Before `tangent run` starts: each prebuilt plugin it has neither a local
/// build of nor a copy fetched for its `prebuilt`, fetched and checked as
/// `tangent plugin fetch` does, once per tangent version. With none missing
/// it returns at once, so a machine whose cache has them never needs the
/// network.
pub async fn missing(config_path: &Path) -> Result<()> {
    let cfg = Config::load(config_path)?.config;
    cfg.validate()?;
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let cache = tangent_shared::cache::plugins();
    let plugins_dir = config_dir.join(&cfg.runtime.plugins_path);
    let wanted = wanted(&cfg, &plugins_dir, cache.as_deref().ok());
    if wanted.is_empty() {
        return Ok(());
    }
    let cache = cache?;
    let names: Vec<&str> = wanted.iter().map(|(name, ..)| *name).collect();
    println!(
        "tangent {VERSION}, first run: fetching {} (once per version)",
        names.join(", ")
    );
    let client = client()?;
    for (name, plugin, prebuilt) in wanted {
        let out = plugins::fetched(&cache, prebuilt);
        fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
        fetch_one(&client, name, plugin, prebuilt, &out)
            .await
            .map_err(|e| unreached(name, e))?;
    }
    Ok(())
}

/// The plugins `tangent run` must fetch first: those with `prebuilt` and
/// neither a local build nor a copy under `cache` fetched for that
/// `prebuilt` ([`plugins::compiled`]). A plugin without `prebuilt` is left
/// to `tangent plugin compile`.
fn wanted<'a>(
    cfg: &'a Config,
    plugins_dir: &Path,
    cache: Option<&Path>,
) -> Vec<(&'a str, &'a PluginConfig, &'a Prebuilt)> {
    cfg.plugins
        .iter()
        .filter_map(|(name, plugin)| Some((name.as_ref(), plugin, plugin.prebuilt.as_ref()?)))
        .filter(|(name, plugin, _)| plugins::compiled(name, plugin, plugins_dir, cache).is_none())
        .collect()
}

/// A fetch for `tangent run` that could not reach the release: the plugin
/// and the request's error, which names the URL, then why tangent needs the
/// network. Any other failure is left as it is.
fn unreached(name: &str, e: anyhow::Error) -> anyhow::Error {
    if !e.chain().any(|c| c.is::<reqwest::Error>()) {
        return e;
    }
    anyhow!("{name}: {e:#}\ntangent fetches each pack's plugin once per version and needs the network for it")
}

fn client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(format!("tangent/{VERSION}"))
        .build()
}

async fn fetch_one(
    client: &reqwest::Client,
    name: &str,
    plugin: &PluginConfig,
    p: &Prebuilt,
    out: &Path,
) -> Result<Attested> {
    let release = p.release(VERSION);
    let asset = p.asset(name);
    let bundle_name = format!("{asset}.sigstore.json");
    // Written beside their destination, so the move into place is a rename.
    let tmp = tempfile::tempdir_in(out)?;

    println!("⬇️  {name}: {asset} from {}/{} {release}", p.host(), p.repo);
    let url = p.asset_url(VERSION, &asset);
    let Some(bytes) = download(client, &url).await? else {
        bail!(not_there(name, plugin, p, &url));
    };
    let digest = hex::encode(Sha256::digest(&bytes));
    if let Some(pin) = p.pinned_sha256() {
        if pin != digest {
            bail!("{name}: {asset} is sha256 {digest}, and the config pins {pin}");
        }
    }
    let component = tmp.path().join(&asset);
    fs::write(&component, &bytes)?;

    let Some(bundle) = download(client, &p.asset_url(VERSION, &bundle_name)).await? else {
        bail!(
            "{name}: {} {release} has no {bundle_name} beside {asset}: the attestation of its \
             build, which tangent checks before it keeps a plugin",
            p.repo
        );
    };
    let bundle_path = tmp.path().join(&bundle_name);
    fs::write(&bundle_path, &bundle)?;

    let dest_component = out.join(format!("{name}.component.wasm"));
    let dest_bundle = out.join(format!("{name}.component.wasm.sigstore.json"));
    let verified = std::str::from_utf8(&bundle)
        .context("the attestation bundle is not text")
        .and_then(|bundle| attest::verify(&digest, &asset, bundle, p, &release))
        .with_context(|| format!("{name}: {asset} did not verify, and is not kept"))?;
    println!(
        "✅ {name}: sha256 {digest}\n   built by {} from {} ({})",
        verified.signer,
        short(&verified.commit),
        verified.source_ref
    );

    let cwasm = tmp.path().join(format!("{name}.cwasm"));
    compile_wasm::precompile(&component, &cwasm)
        .with_context(|| format!("{name}: {asset} is not a component tangent can load"))?;

    // The .cwasm goes in last: until it is there, nothing takes what is
    // here for a plugin, and a fetch that died midway is fetched again.
    fs::rename(&component, &dest_component)?;
    fs::rename(&bundle_path, &dest_bundle)?;
    fs::rename(&cwasm, out.join(format!("{name}.cwasm")))?;
    Ok(verified)
}

/// Why plugin `name`'s component is not at `url`, its release's asset, and
/// what builds it instead: `tangent plugin compile` only for a plugin with
/// a source. A pack built into tangent has none, and compile skips it.
fn not_there(name: &str, plugin: &PluginConfig, p: &Prebuilt, url: &str) -> String {
    let compile = if plugin.path.as_os_str().is_empty() {
        ""
    } else {
        "; `tangent plugin compile` builds it from source"
    };
    format!(
        "{name}: {url} is not there: {} {} has no {}. A release before the plugin was prebuilt, \
         a tangent built from a checkout whose version has no release yet (set \
         `prebuilt.release`), or a pack of its own{compile}",
        p.repo,
        p.release(VERSION),
        p.asset(name)
    )
}

/// The body at `url`, or `None` when there is nothing there. A failed
/// request's or status's error names the URL itself; a body's does not.
async fn download(client: &reqwest::Client, url: &str) -> Result<Option<Vec<u8>>> {
    let resp = client.get(url).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let resp = resp.error_for_status()?;
    let bytes = resp
        .bytes()
        .await
        .with_context(|| format!("reading {url}"))?;
    Ok(Some(bytes.to_vec()))
}

fn short(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prebuilt() -> Prebuilt {
        serde_yaml::from_str("repo: EthanBlackburn/tangent").unwrap()
    }

    /// A fetch removes the plugin's own `tangent plugin compile` build,
    /// which would run in its place, and leaves a file of its name alone
    /// when the plugin has no source, since this config never built it.
    #[test]
    fn a_fetch_removes_the_local_build_that_would_run_in_its_place() {
        let dir = tempfile::tempdir().unwrap();
        let built = dir.path().join("plugins");
        let cfg: Config = serde_yaml::from_str(
            "plugins:
  cloudtrail: { module_type: rust, path: ., prebuilt: { repo: a/b } }
  okta: { module_type: rust, prebuilt: { repo: a/b } }
",
        )
        .unwrap();
        let (cloudtrail, okta) = (&cfg.plugins["cloudtrail"], &cfg.plugins["okta"]);
        assert_eq!(
            remove_local_build("cloudtrail", cloudtrail, &built).unwrap(),
            None
        );

        fs::create_dir_all(&built).unwrap();
        for name in ["cloudtrail", "okta"] {
            fs::write(built.join(format!("{name}.cwasm")), "").unwrap();
        }
        assert_eq!(
            remove_local_build("cloudtrail", cloudtrail, &built).unwrap(),
            Some(built.join("cloudtrail.cwasm"))
        );
        assert!(!built.join("cloudtrail.cwasm").exists());
        assert_eq!(remove_local_build("okta", okta, &built).unwrap(), None);
        assert!(built.join("okta.cwasm").exists());
    }

    /// Only a prebuilt plugin built nowhere, or fetched for another
    /// `prebuilt`, is fetched before a run; a file of its name in plugins/
    /// counts only for a plugin with a source.
    #[test]
    fn a_run_fetches_only_the_prebuilt_plugins_it_has_no_copy_of() {
        let dir = tempfile::tempdir().unwrap();
        let (built, cache) = (dir.path().join("plugins"), dir.path().join("cache"));
        let cfg: Config = serde_yaml::from_str(
            "plugins:
  compiled: { module_type: rust, path: . }
  built: { module_type: rust, path: ., prebuilt: { repo: a/b } }
  stray: { module_type: rust, prebuilt: { repo: a/b } }
  fetched: { module_type: rust, prebuilt: { repo: a/b } }
  moved: { module_type: rust, path: ., prebuilt: { repo: a/b, release: v2 } }
  missing: { module_type: rust, path: ., prebuilt: { repo: a/b } }
",
        )
        .unwrap();
        fs::create_dir_all(&built).unwrap();
        for name in ["built", "stray"] {
            fs::write(built.join(format!("{name}.cwasm")), "").unwrap();
        }
        for (name, prebuilt) in [
            ("fetched", "repo: a/b"),
            ("moved", "{ repo: a/b, release: v1 }"),
        ] {
            let out = plugins::fetched(&cache, &serde_yaml::from_str(prebuilt).unwrap());
            fs::create_dir_all(&out).unwrap();
            fs::write(out.join(format!("{name}.cwasm")), "").unwrap();
        }
        let names = |w: Vec<(&str, &PluginConfig, &Prebuilt)>| {
            w.into_iter()
                .map(|(n, ..)| n.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(wanted(&cfg, &built, Some(&cache))),
            ["missing", "moved", "stray"]
        );
        assert_eq!(
            names(wanted(&cfg, &built, None)),
            ["fetched", "missing", "moved", "stray"],
            "no cache: every prebuilt plugin not built here"
        );
        fs::write(built.join("missing.cwasm"), "").unwrap();
        fs::write(built.join("moved.cwasm"), "").unwrap();
        assert_eq!(names(wanted(&cfg, &built, Some(&cache))), ["stray"]);
    }

    /// A release out of reach fails the run naming the plugin and the
    /// request's error, then why tangent needs the network, and sends no one
    /// to `tangent plugin compile`, which has nothing to build for a pack's
    /// plugin; nothing leaves this machine (port 0 is never listened on).
    #[tokio::test]
    async fn a_release_out_of_reach_says_a_run_needs_the_network_once() {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let url = "http://127.0.0.1:0/cloudtrail.component.wasm";
        let e = download(&client, url).await.unwrap_err();
        let err = format!("{:#}", unreached("cloudtrail", e));
        assert!(
            err.starts_with(&format!(
                "cloudtrail: error sending request for url ({url})"
            )),
            "{err}"
        );
        assert_eq!(err.matches(url).count(), 1, "{err}");
        assert!(
            err.ends_with(
                "\ntangent fetches each pack's plugin once per version and needs the network for it"
            ),
            "{err}"
        );

        let other =
            anyhow!("cloudtrail: cloudtrail.component.wasm did not verify, and is not kept");
        assert_eq!(
            format!("{:#}", unreached("cloudtrail", other)),
            "cloudtrail: cloudtrail.component.wasm did not verify, and is not kept"
        );
    }

    /// A release without the plugin points to `tangent plugin compile` only
    /// for a plugin with a source: compile skips one without, so the next
    /// fetch would fail the same way.
    #[test]
    fn a_missing_asset_suggests_compile_only_for_a_plugin_with_a_source() {
        let cfg: Config = serde_yaml::from_str(
            "plugins:
  cloudtrail: { module_type: rust, path: ., prebuilt: { repo: a/b } }
  okta: { module_type: rust, prebuilt: { repo: a/b } }
",
        )
        .unwrap();
        let msg = |name: &str| {
            let plugin = &cfg.plugins[name];
            not_there(name, plugin, plugin.prebuilt.as_ref().unwrap(), "URL")
        };
        let want = |name: &str| {
            format!(
                "{name}: URL is not there: a/b v{VERSION} has no {name}.component.wasm. A release \
                 before the plugin was prebuilt, a tangent built from a checkout whose version has \
                 no release yet (set `prebuilt.release`), or a pack of its own"
            )
        };
        assert_eq!(
            msg("cloudtrail"),
            format!(
                "{}; `tangent plugin compile` builds it from source",
                want("cloudtrail")
            )
        );
        assert_eq!(msg("okta"), want("okta"));
    }
}
