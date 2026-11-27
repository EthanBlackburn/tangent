//! Background macOS service management: `tangent up`, `tangent down`,
//! `tangent status`, and `tangent uninstall`.
//!
//! Privilege split:
//! - `/Library/LaunchDaemons/com.ethanblackburn.tangent.sensor.plist` (root):
//!   runs `tangent-sensor daemon` from root's own copy of the app, under
//!   `/Library/Application Support/Tangent`, exclusively for Endpoint
//!   Security + tcpdump over `0600` user-owned Unix sockets under
//!   `/var/run/tangent`. Lazy-starts on client connect (0% CPU when paused).
//!   The copy in `/Applications` is never run as root: an administrator's
//!   programs can replace what is there without a password.
//! - `~/Library/LaunchAgents/com.ethanblackburn.tangent.watch.plist` (user):
//!   runs `tangent watch mac` unprivileged, connecting to the daemon sockets
//!   with zero sudo prompts.
//! - `~/Library/LaunchAgents/com.ethanblackburn.tangent.app.plist` (user Aqua):
//!   runs `/Applications/Tangent.app/Contents/MacOS/tangent-sensor menubar`.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::init::{self, Provider, Server};
use crate::mac::{self, Mac};
use crate::{fetch, local, status, watch};

pub const SENSOR_LABEL: &str = "com.ethanblackburn.tangent.sensor";
pub const WATCH_LABEL: &str = "com.ethanblackburn.tangent.watch";
pub const APP_LABEL: &str = "com.ethanblackburn.tangent.app";

const DAEMON_PLIST: &str = "/Library/LaunchDaemons/com.ethanblackburn.tangent.sensor.plist";
const DAEMON_LOG: &str = "/var/log/tangent-sensor.log";
/// How long a LaunchAgent told to stop is waited for. launchd kills what has
/// not ended twenty seconds after it asked.
const STOPS_WITHIN: Duration = Duration::from_secs(25);
const SERVICE_FILE: &str = "service.json";
const ENV_FILE: &str = "env";
const LAUNCHCTL: &str = "/bin/launchctl";
const FDA_SETTINGS_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";

/// A provider as `--provider` and service.json name it.
fn provider_name(provider: Provider) -> String {
    use clap::ValueEnum as _;
    let value = provider.to_possible_value().expect("no provider is hidden");
    value.get_name().to_string()
}

/// Who judged for the last `tangent up`, from `<data_dir>/service.json`, so
/// plain `tangent up` (and the menu bar's "Resume Watching" button) starts
/// the same again: a provider, or `None` for the model on this Mac. Nothing
/// when no `up` has said.
fn read_choice(dir: &Path) -> Option<Option<Provider>> {
    use clap::ValueEnum as _;
    let text = fs::read_to_string(dir.join(SERVICE_FILE)).ok()?;
    let val: Value = serde_json::from_str(&text).ok()?;
    match val.get("provider")? {
        Value::Null => Some(None),
        Value::String(name) => Provider::from_str(name, false).ok().map(Some),
        _ => None,
    }
}

fn write_choice(dir: &Path, provider: Option<Provider>) -> Result<()> {
    let body = serde_json::to_string_pretty(&json!({ "provider": provider.map(provider_name) }))?;
    fs::write(dir.join(SERVICE_FILE), format!("{body}\n"))
        .with_context(|| format!("writing {}", dir.join(SERVICE_FILE).display()))
}

/// Loads `KEY=VALUE` pairs from `path` into this process's environment when not
/// already set (used by `tangent watch mac --env-file ...` under launchd).
pub fn load_env_file(path: &Path) -> Result<()> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading env file {}", path.display()))?;
    for (key, value) in parse_env(&text) {
        if std::env::var_os(&key).is_none() {
            // Called at startup before background tasks are spawned.
            std::env::set_var(&key, &value);
        }
    }
    Ok(())
}

fn parse_env(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            if !key.is_empty() {
                map.insert(key.to_string(), v.trim().to_string());
            }
        }
    }
    map
}

fn write_env_file(path: &Path, vars: &BTreeMap<String, String>) -> Result<()> {
    let mut content = String::from("# Managed by `tangent up`. Mode 0600.\n");
    for (k, v) in vars {
        content.push_str(&format!("{k}={v}\n"));
    }
    let tmp = path.with_extension("tmp");
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))
}

/// `tangent up [--provider <name> | --local]`: installs the privileged
/// sensor daemon if needed (one sudo prompt) and starts the unprivileged Mac
/// watcher + native menu bar in the background.
pub async fn up(provider_flag: Option<Provider>, local_flag: bool) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("`tangent up` manages the macOS background watcher and menu bar, and this machine is not a Mac");
    }

    let dir = watch::data_dir("mac")?;
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    // What this one says, or what the last one did. Nothing is picked for
    // whoever has named none: that is the model on this Mac.
    let provider = match (provider_flag, local_flag) {
        (Some(provider), _) => Some(provider),
        (None, true) => None,
        (None, false) => read_choice(&dir).unwrap_or(None),
    };

    // Validate host eligibility (Apple Silicon + 32 GB for local).
    let mac = Mac::new(provider).watched();
    mac::runs_here_as(&mac, "tangent up")?;

    // What a provider's models read is kept for the watcher, which launchd
    // starts with none of this shell's environment: from here, or from the
    // 0600 file the last `up` kept.
    let env_path = dir.join(ENV_FILE);
    let mut saved_env = fs::read_to_string(&env_path)
        .map(|t| parse_env(&t))
        .unwrap_or_default();
    if provider.is_some() {
        for (var, _) in mac.needs() {
            if let Some(val) = std::env::var(var).ok().filter(|v| !v.trim().is_empty()) {
                saved_env.insert(var.to_string(), val);
            }
        }
        // As `tangent watch mac` asks it: a variable the file has a fallback
        // for, as Bedrock's profile has `default`, is not missing.
        let missing = watch::unset(&mac.config(), &mac.needs(), |name| {
            saved_env.get(name).map(std::ffi::OsString::from)
        });
        if !missing.is_empty() {
            let lines: Vec<String> = missing
                .iter()
                .map(|(v, d)| format!("  {v}  ({d})"))
                .collect();
            bail!(
                "it reads these from the environment, and they are not set:\n{}",
                lines.join("\n")
            );
        }
        if provider == Some(Provider::Bedrock)
            && init::set("AWS_ACCESS_KEY_ID")
            && !saved_env.contains_key("AWS_PROFILE")
        {
            println!(
                "This shell's AWS keys are not kept: the background watcher signs in with the profile `default` in ~/.aws. Set AWS_PROFILE to name another."
            );
        }
        write_env_file(&env_path, &saved_env)?;
    }

    // Write pipeline config & fetch plugins + sensor + local model if needed.
    crate::init::place(&dir, &mac.files())?;
    let config = dir.join("tangent.yaml");
    fetch::missing(&config).await?;

    if mac.server() == Server::Ollama {
        let root = local::root()?;
        let missing = local::missing(&root);
        if !missing.nothing() {
            if !crate::init::ask_to_fetch(&missing, &root) {
                bail!(
                    "the model is not on this Mac, so there is nothing to judge with: `tangent model fetch` downloads it"
                );
            }
            local::fetch(&root).await?;
        }
    }

    write_choice(&dir, provider)?;

    // 1. Ensure `/Applications/Tangent.app` + root LaunchDaemon are installed and running.
    let uid = current_uid()?;
    ensure_sensor_daemon(uid).await?;

    // 2. Install & bootstrap the unprivileged user LaunchAgents (watcher + menu bar).
    let agents_dir = launch_agents_dir()?;
    fs::create_dir_all(&agents_dir)
        .with_context(|| format!("creating {}", agents_dir.display()))?;

    // The path tangent was run by, not what it links to: Homebrew's
    // /opt/homebrew/bin/tangent is a link into a directory named for the
    // version, which the next upgrade removes.
    let tangent_bin = std::env::current_exe().context("finding current tangent executable")?;
    let tangent_bin = std::path::absolute(&tangent_bin).unwrap_or(tangent_bin);

    let watch_plist_path = agents_dir.join(format!("{WATCH_LABEL}.plist"));
    let watch_xml = watch_agent_plist(
        &tangent_bin,
        &dir,
        provider,
        provider.is_some().then_some(env_path.as_path()),
    );
    let app_plist_path = agents_dir.join(format!("{APP_LABEL}.plist"));
    let app_xml = app_agent_plist(&tangent_shared::sensor::installed_binary(), &dir, &tangent_bin);

    let gui_domain = format!("gui/{uid}");
    stop_agent(&gui_domain, WATCH_LABEL)?;
    // What the last watch left is not this one's: without this, the wait
    // below reads yesterday's error as today's.
    let _ = fs::remove_file(dir.join(status::FILE));
    fs::write(&watch_plist_path, watch_xml)
        .with_context(|| format!("writing {}", watch_plist_path.display()))?;
    start_agent(&gui_domain, WATCH_LABEL, &watch_plist_path)?;

    // The menu bar's Resume runs this very command, as the menu bar's child:
    // stopping the menu bar would end this before it was started again. One
    // that is up and was started as it would be now is left running.
    let menu_bar_is_current = is_agent_loaded(APP_LABEL)
        && fs::read_to_string(&app_plist_path).is_ok_and(|now| now == app_xml);
    if !menu_bar_is_current {
        stop_agent(&gui_domain, APP_LABEL)?;
        fs::write(&app_plist_path, app_xml)
            .with_context(|| format!("writing {}", app_plist_path.display()))?;
        start_agent(&gui_domain, APP_LABEL, &app_plist_path)?;
    }

    // 3. Wait briefly for watcher startup to confirm watching vs missing FDA.
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut final_snap = None;
    while Instant::now() < deadline {
        if let Some(snap) = status::read(&dir) {
            if snap.state == "watching" || snap.needs_fda || snap.state == "error" {
                final_snap = Some(snap);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let model_label = match provider {
        Some(_) => mac.models(),
        None => "Inkling 2 Mini (local)".to_string(),
    };

    if let Some(snap) = &final_snap {
        if snap.needs_fda {
            open_fda_settings();
            println!("Tangent is installed, and needs Full Disk Access for Tangent.app.");
            println!("  System Settings -> Privacy & Security -> Full Disk Access is open.");
            println!("  Toggle Tangent on — watching starts automatically within seconds.");
            println!("  Check anytime with `tangent status`.");
            return Ok(());
        }
        if snap.state == "error" {
            if let Some(err) = &snap.error {
                println!("Tangent background service started with an error:\n  {err}");
                println!("  Logs: {}", dir.join("watch.log").display());
                return Ok(());
            }
        }
    }

    println!("Tangent is watching this Mac in the background.");
    println!("  Menu bar   Tangent icon in your top bar");
    println!("  Models     {model_label}");
    println!("  Logs       {}", dir.join("watch.log").display());
    println!("\nTry `tangent simulate agent` to see it catch an attack, or `tangent status` anytime.");
    Ok(())
}

/// `tangent down [--all]`: stops the background Mac watcher (zero sudo; sensor
/// daemon automatically drops to 0% CPU). Keeps the menu bar running showing
/// "Paused" unless `--all` is passed.
pub async fn down(all: bool) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("`tangent down` manages the macOS background watcher, and this machine is not a Mac");
    }
    let uid = current_uid()?;
    let gui_domain = format!("gui/{uid}");
    let _ = bootout(&gui_domain, WATCH_LABEL);
    if all {
        let _ = bootout(&gui_domain, APP_LABEL);
    }

    if let Ok(dir) = watch::data_dir("mac") {
        if let Some(mut snap) = status::read(&dir) {
            if snap.state != "stopped" {
                snap.state = "stopped".to_string();
                snap.pid = None;
                snap.pending = 0;
                snap.error = None;
                snap.needs_fda = false;
                snap.updated_at = status::now_rfc3339();
                if let Ok(bytes) = serde_json::to_vec_pretty(&snap.to_json()) {
                    let _ = fs::write(dir.join(status::FILE), bytes);
                }
            }
        }
    }

    if all {
        println!("Tangent watching and menu bar stopped. Run `tangent up` to resume.");
    } else {
        println!("Tangent watching paused (sensor idle). Run `tangent up` or click Resume in the menu bar.");
    }
    Ok(())
}

/// `tangent status [--json]`: instant, zero-sudo view of the background Mac
/// watcher, sensor daemon, menu bar, and recent alerts.
pub async fn show_status(as_json: bool) -> Result<()> {
    let dir = watch::data_dir("mac")?;
    let snap = status::read(&dir);
    let sock_dir = tangent_shared::sensor::daemon_dir();
    let es_sock = tangent_shared::sensor::es_socket(&sock_dir);
    let daemon_socket = es_sock.exists();
    let app_installed = tangent_shared::sensor::installed_binary().is_file();
    let alive = snap
        .as_ref()
        .and_then(|s| s.pid)
        .is_some_and(|pid| pid_alive(pid));
    let menubar_running = cfg!(target_os = "macos") && is_agent_loaded(APP_LABEL);

    let effective_state = match &snap {
        Some(s) if (s.state == "watching" || s.state == "starting") && alive => s.state.as_str(),
        Some(s) if s.needs_fda => "needs_fda",
        Some(s) if s.state == "error" => "error",
        _ => "stopped",
    };

    if as_json {
        let saved = fs::read_to_string(dir.join(ENV_FILE))
            .map(|t| parse_env(&t))
            .unwrap_or_default();
        let choices = choices(read_choice(&dir).flatten(), init::no_inkling(), |var| {
            init::set(var) || saved.get(var).is_some_and(|v| !v.trim().is_empty())
        });
        let out = json!({
            "choices": choices,
            "state": effective_state,
            "alive": alive,
            "daemon_socket": daemon_socket,
            "daemon_socket_path": es_sock.display().to_string(),
            "app_installed": app_installed,
            "menubar_running": menubar_running,
            "data_dir": dir.display().to_string(),
            "status": snap.as_ref().map(status::Snapshot::to_json),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let state_line = match effective_state {
        "watching" => {
            let pid = snap.as_ref().and_then(|s| s.pid).unwrap_or(0);
            format!("watching this Mac (pid {pid})")
        }
        "starting" => "starting...".to_string(),
        "needs_fda" => "needs Full Disk Access (System Settings -> Privacy & Security -> Full Disk Access -> Tangent)".to_string(),
        "error" => {
            let msg = snap
                .as_ref()
                .and_then(|s| s.error.as_deref())
                .unwrap_or("unknown error");
            format!("error: {msg}")
        }
        _ => "paused / not running (run `tangent up` to start)".to_string(),
    };

    println!("Tangent    {state_line}");
    let sensor_line = if daemon_socket && alive {
        format!("connected ({})", es_sock.display())
    } else if daemon_socket {
        format!("idle ({})", es_sock.display())
    } else if app_installed {
        "installed, daemon not running".to_string()
    } else {
        "not installed".to_string()
    };
    println!("  Sensor   {sensor_line}");
    if let Some(s) = &snap {
        if !s.models.is_empty() {
            println!("  Models   {}", s.models);
        }
        if alive {
            let mut line = format!("{} sessions checked · {} flagged", s.checked, s.flagged);
            if s.pending > 0 {
                line.push_str(&format!(" · {} reviewing", s.pending));
            }
            println!("  Checked  {line}");
        }
        if !s.recent_alerts.is_empty() {
            println!("  Alerts   {} recent:", s.recent_alerts.len());
            for a in &s.recent_alerts {
                println!("           [{}] {} — {}", a.verdict, a.subject, a.summary);
            }
        }
    }
    println!(
        "  Menu bar {}",
        if menubar_running { "running" } else { "stopped" }
    );
    println!("  Logs     {}", dir.join("watch.log").display());
    Ok(())
}

/// Who can judge this Mac, for the menu bar's Models menu: the model on this
/// Mac and each provider's pair, in `--provider`'s order. Each has the
/// arguments `tangent up` starts it with, whether it is the one `up` last
/// started, whether it can be started from where there is nobody to ask, and
/// when it cannot, why. `set` says whether a variable has a value, here or
/// kept by an earlier `up`.
fn choices(current: Option<Provider>, no_inkling: Option<String>, set: impl Fn(&str) -> bool) -> Vec<Value> {
    use clap::ValueEnum as _;
    let mut choices = vec![json!({
        "label": "Inkling 2 Mini, on this Mac: nothing leaves it",
        "args": ["up", "--local"],
        "current": current.is_none(),
        "ready": no_inkling.is_none(),
        "note": no_inkling,
    })];
    for provider in Provider::value_variants() {
        let mac = Mac::new(Some(*provider)).watched();
        let missing = watch::unset(&mac.config(), &mac.needs(), |name| {
            set(name).then(|| std::ffi::OsString::from("set"))
        });
        let note = (!missing.is_empty()).then(|| {
            let vars: Vec<&str> = missing.iter().map(|(var, _)| *var).collect();
            format!(
                "needs {}: run `tangent up --provider {}` in a terminal that has it",
                vars.join(", "),
                provider_name(*provider)
            )
        });
        choices.push(json!({
            "label": mac.models(),
            "args": ["up", "--provider", provider_name(*provider)],
            "current": current == Some(*provider),
            "ready": missing.is_empty(),
            "note": note,
        }));
    }
    choices
}

/// `tangent uninstall [--purge]`: cleanly stops and removes the user
/// LaunchAgents, root LaunchDaemon, `/var/run/tangent`, both copies of
/// `Tangent.app`, and the API keys `tangent up --provider` kept. Keeps the rest
/// of `~/.local/share/tangent/mac` unless `--purge` is passed.
pub async fn uninstall(purge: bool) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("`tangent uninstall` removes the macOS background service, and this machine is not a Mac");
    }

    let uid = current_uid()?;
    let gui_domain = format!("gui/{uid}");
    let agents_dir = launch_agents_dir()?;

    for label in [WATCH_LABEL, APP_LABEL] {
        let _ = bootout(&gui_domain, label);
        let plist = agents_dir.join(format!("{label}.plist"));
        let _ = fs::remove_file(&plist);
    }

    let needs_root = Path::new(DAEMON_PLIST).exists()
        || tangent_shared::sensor::installed_app().exists()
        || Path::new(tangent_shared::sensor::DAEMON_APP_DIR).exists()
        || Path::new(tangent_shared::sensor::DAEMON_DIR).exists();

    if needs_root {
        println!("Removing root sensor daemon and /Applications/Tangent.app (requires sudo)...");
        let script = format!(
            "launchctl bootout system/{SENSOR_LABEL} 2>/dev/null || true; \
             rm -f '{DAEMON_PLIST}' '{DAEMON_LOG}'; \
             rm -rf '{}' '{}' '{}'",
            tangent_shared::sensor::DAEMON_DIR,
            tangent_shared::sensor::DAEMON_APP_DIR,
            tangent_shared::sensor::installed_app().display()
        );
        let status = Command::new("sudo")
            .args(["-p", "tangent uninstall password: ", "--", "/bin/sh", "-c", &script])
            .status()
            .context("running sudo for uninstall")?;
        if !status.success() {
            bail!("sudo uninstall failed ({status})");
        }
    }

    if let Ok(dir) = watch::data_dir("mac") {
        // The keys are a secret, and nothing reads them once this is gone.
        let _ = fs::remove_file(dir.join(ENV_FILE));
        if purge {
            if dir.exists() {
                fs::remove_dir_all(&dir)
                    .with_context(|| format!("removing {}", dir.display()))?;
                println!("Removed data directory {}.", dir.display());
            }
        } else if dir.exists() {
            println!("Your logs and Parquet lake were kept in {} (pass --purge to delete).", dir.display());
        }
    }

    println!("Tangent background service and menu bar removed.");
    Ok(())
}

// MARK: root LaunchDaemon installation

/// Whether the app at `installed` is the one at `source`: the same sensor
/// and the same Info.plist, which has its version.
fn same_app(source: &Path, installed: &Path) -> bool {
    ["Contents/MacOS/tangent-sensor", "Contents/Info.plist"]
        .iter()
        .all(|file| match (fs::read(source.join(file)), fs::read(installed.join(file))) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        })
}

/// Installs or updates both copies of `Tangent.app` and the root LaunchDaemon
/// unless they are this tangent's sensor already, with the daemon listening.
/// Needs zero `sudo` when already up to date.
async fn ensure_sensor_daemon(uid: u32) -> Result<()> {
    let installed_app = tangent_shared::sensor::installed_app();
    let daemon_app = tangent_shared::sensor::daemon_app();
    let sock_dir = tangent_shared::sensor::daemon_dir();
    let es_sock = tangent_shared::sensor::es_socket(&sock_dir);

    // The daemon's sockets are one user's. Another's `tangent up` would find
    // them listening and never be let in.
    #[cfg(unix)]
    if let Ok(meta) = fs::metadata(&es_sock) {
        use std::os::unix::fs::MetadataExt as _;
        if meta.uid() != uid {
            bail!(
                "the sensor daemon on this Mac is installed for user {}, and serves one user: \
                 `tangent uninstall` as them, then `tangent up` here",
                meta.uid()
            );
        }
    }

    // The app to install: this version's, from the cache, or the one named.
    let custom_app = std::env::var_os("TANGENT_SENSOR_APP")
        .map(PathBuf::from)
        .filter(|p| p.exists());
    let verified = custom_app.is_none();
    let source_app = if let Some(custom) = custom_app {
        custom
    } else {
        let cache_dir = tangent_shared::sensor::dir()?;
        if !tangent_shared::sensor::binary(&cache_dir).is_file() {
            fetch::sensor(&cache_dir).await?;
        }
        tangent_shared::sensor::check(&cache_dir)?;
        cache_dir.join(tangent_shared::sensor::APP)
    };

    // Fast path: both copies are this sensor, the plist is there, and the
    // daemon is listening. An upgrade of tangent brings a new sensor, and is
    // not this.
    if same_app(&source_app, &installed_app)
        && same_app(&source_app, &daemon_app)
        && Path::new(DAEMON_PLIST).is_file()
        && es_sock.exists()
    {
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        bail!(
            "the sensor daemon is to be installed or updated, which asks for your password: \
             run `tangent up` in a terminal"
        );
    }

    let plist_xml = sensor_daemon_plist(&tangent_shared::sensor::daemon_binary(), &sock_dir, uid);
    let tmp_plist = tempfile::NamedTempFile::new().context("creating temporary daemon plist")?;
    fs::write(tmp_plist.path(), plist_xml)?;

    // Root's copy is made first, in a directory only root writes to, and it
    // is that copy that is checked, as root, after it is made: what was
    // checked above sits in your cache, where anything running as you could
    // change it while the password is typed. The copy in /Applications is
    // made from root's.
    let verify = if verified {
        format!(
            "{} --verify --strict --deep '-R={}' '{}'; ",
            tangent_shared::sensor::CODESIGN,
            shell_escape_str(&tangent_shared::sensor::requirement()),
            shell_escape(&daemon_app),
        )
    } else {
        println!(
            "TANGENT_SENSOR_APP is set: {} is installed to run as root without its signature being checked.",
            source_app.display()
        );
        String::new()
    };
    println!("Installing Tangent.app and root sensor daemon (asks for your password once)...");
    let install_script = format!(
        "set -eu; \
         launchctl bootout system/{SENSOR_LABEL} 2>/dev/null || true; \
         rm -rf '{daemon_dir}'; \
         mkdir -p '{daemon_dir}'; \
         chown root:wheel '{daemon_dir}'; \
         chmod 755 '{daemon_dir}'; \
         /usr/bin/ditto '{src_app}' '{daemon_app}'; \
         chown -R root:wheel '{daemon_app}'; \
         chmod -R go-w '{daemon_app}'; \
         {verify}\
         rm -rf '{dest_app}'; \
         /usr/bin/ditto '{daemon_app}' '{dest_app}'; \
         cp '{tmp_plist}' '{DAEMON_PLIST}'; \
         chown root:wheel '{DAEMON_PLIST}'; \
         chmod 644 '{DAEMON_PLIST}'; \
         launchctl bootstrap system '{DAEMON_PLIST}'",
        daemon_dir = shell_escape(Path::new(tangent_shared::sensor::DAEMON_APP_DIR)),
        daemon_app = shell_escape(&daemon_app),
        src_app = shell_escape(&source_app),
        dest_app = shell_escape(&installed_app),
        tmp_plist = shell_escape(tmp_plist.path()),
    );

    let status = Command::new("sudo")
        .args([
            "-p",
            "tangent installs the Mac sensor daemon once. Password: ",
            "--",
            "/bin/sh",
            "-c",
            &install_script,
        ])
        .status()
        .context("running sudo to install sensor daemon")?;
    if !status.success() {
        bail!("installing the sensor daemon failed ({status})");
    }

    // Wait briefly for the LaunchDaemon to bind `/var/run/tangent/es.sock`.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if es_sock.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!(
        "the sensor daemon was installed and is not listening on {}: {DAEMON_LOG} has what it said",
        es_sock.display()
    )
}

// MARK: launchd helpers & plist generators

fn launch_agents_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .context("HOME is not set to an absolute path")?;
    Ok(home.join("Library").join("LaunchAgents"))
}

fn current_uid() -> Result<u32> {
    let out = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .context("running /usr/bin/id -u")?;
    if !out.status.success() {
        bail!("id -u failed ({})", out.status);
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .context("parsing uid from id -u")
}

fn pid_alive(pid: u32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn is_agent_loaded(label: &str) -> bool {
    let Ok(uid) = current_uid() else {
        return false;
    };
    Command::new(LAUNCHCTL)
        .args(["print", &format!("gui/{uid}/{label}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn bootout(domain: &str, label: &str) -> Result<()> {
    let _ = Command::new(LAUNCHCTL)
        .args(["bootout", &format!("{domain}/{label}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

/// Stops a LaunchAgent and waits until launchd has let go of it. `bootout`
/// returns before that, and a `bootstrap` in the meantime is refused, or is
/// taken for done when it is the old one still ending.
fn stop_agent(domain: &str, label: &str) -> Result<()> {
    if !is_agent_loaded(label) {
        return Ok(());
    }
    let _ = bootout(domain, label);
    let deadline = Instant::now() + STOPS_WITHIN;
    while is_agent_loaded(label) {
        if Instant::now() >= deadline {
            bail!("{label} was told to stop and has not: `launchctl print {domain}/{label}` says what it is doing");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// Starts a LaunchAgent that is not loaded, from its plist.
fn start_agent(domain: &str, label: &str, plist: &Path) -> Result<()> {
    let out = Command::new(LAUNCHCTL)
        .args(["bootstrap", domain])
        .arg(plist)
        .output()
        .with_context(|| format!("running launchctl bootstrap for {label}"))?;
    if !out.status.success() {
        bail!(
            "launchctl bootstrap {label} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn open_fda_settings() {
    let _ = Command::new("/usr/bin/open")
        .arg(FDA_SETTINGS_URL)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn shell_escape(path: &Path) -> String {
    shell_escape_str(&path.display().to_string())
}

/// `text` as it is written between single quotes in a shell.
fn shell_escape_str(text: &str) -> String {
    text.replace('\'', "'\\''")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn plist_string_array(items: &[String]) -> String {
    items
        .iter()
        .map(|item| format!("        <string>{}</string>", xml_escape(item)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Root LaunchDaemon plist for `tangent-sensor daemon`.
pub fn sensor_daemon_plist(sensor_bin: &Path, socket_dir: &Path, uid: u32) -> String {
    let args = vec![
        sensor_bin.display().to_string(),
        "daemon".to_string(),
        "--socket-dir".to_string(),
        socket_dir.display().to_string(),
        "--uid".to_string(),
        uid.to_string(),
    ];
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{SENSOR_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{args}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardErrorPath</key>
    <string>/var/log/tangent-sensor.log</string>
</dict>
</plist>
"#,
        args = plist_string_array(&args),
    )
}

/// User LaunchAgent plist for `tangent watch mac`.
pub fn watch_agent_plist(
    tangent_bin: &Path,
    data_dir: &Path,
    provider: Option<Provider>,
    env_file: Option<&Path>,
) -> String {
    let mut args = vec![
        tangent_bin.display().to_string(),
        "watch".to_string(),
        "mac".to_string(),
    ];
    if let Some(provider) = provider {
        args.push("--provider".to_string());
        args.push(provider_name(provider));
    }
    if let Some(env_file) = env_file {
        args.push("--env-file".to_string());
        args.push(env_file.display().to_string());
    }
    let daemon_log = xml_escape(&data_dir.join("daemon.log").display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{WATCH_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{args}
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>{daemon_log}</string>
    <key>StandardErrorPath</key>
    <string>{daemon_log}</string>
</dict>
</plist>
"#,
        args = plist_string_array(&args),
    )
}

/// User Aqua LaunchAgent plist for the native menu bar (`tangent-sensor menubar`).
pub fn app_agent_plist(sensor_bin: &Path, data_dir: &Path, tangent_bin: &Path) -> String {
    let args = vec![
        sensor_bin.display().to_string(),
        "menubar".to_string(),
        "--dir".to_string(),
        data_dir.display().to_string(),
        "--tangent".to_string(),
        tangent_bin.display().to_string(),
    ];
    let log = xml_escape(&data_dir.join("menubar.log").display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{APP_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{args}
    </array>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
        args = plist_string_array(&args),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plists_escape_xml_and_include_expected_arguments() {
        let daemon = sensor_daemon_plist(
            &tangent_shared::sensor::daemon_binary(),
            Path::new("/var/run/tangent"),
            501,
        );
        // root runs its own copy, never the one in /Applications
        assert!(daemon.contains(
            "<string>/Library/Application Support/Tangent/Tangent.app/Contents/MacOS/tangent-sensor</string>"
        ));
        assert!(!daemon.contains("/Applications/"));
        assert!(daemon.contains("<string>com.ethanblackburn.tangent.sensor</string>"));
        assert!(daemon.contains("<string>daemon</string>"));
        assert!(daemon.contains("<string>501</string>"));

        let watch = watch_agent_plist(
            Path::new("/opt/homebrew/bin/tangent"),
            Path::new("/Users/a&b/.local/share/tangent/mac"),
            Some(Provider::Bedrock),
            Some(Path::new("/Users/a&b/.local/share/tangent/mac/env")),
        );
        assert!(watch.contains("<string>--provider</string>\n        <string>bedrock</string>"));
        assert!(watch.contains("<string>--env-file</string>"));
        assert!(watch.contains("/Users/a&amp;b/.local/share/tangent/mac/env"));

        let app = app_agent_plist(
            Path::new("/Applications/Tangent.app/Contents/MacOS/tangent-sensor"),
            Path::new("/Users/dev/.local/share/tangent/mac"),
            Path::new("/opt/homebrew/bin/tangent"),
        );
        assert!(app.contains("<string>menubar</string>"));
        assert!(app.contains("<string>Aqua</string>"));
    }

    #[test]
    fn env_file_roundtrips_with_0600_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");
        let mut vars = BTreeMap::new();
        vars.insert("ANTHROPIC_API_KEY".to_string(), "sk-ant-test-123".to_string());
        write_env_file(&path, &vars).unwrap();

        let parsed = parse_env(&fs::read_to_string(&path).unwrap());
        assert_eq!(parsed.get("ANTHROPIC_API_KEY").map(String::as_str), Some("sk-ant-test-123"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn an_app_is_the_same_when_its_sensor_and_its_version_are() {
        let dir = tempfile::tempdir().unwrap();
        let app = |name: &str, sensor: &str, plist: &str| {
            let app = dir.path().join(name);
            fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
            fs::write(app.join("Contents/MacOS/tangent-sensor"), sensor).unwrap();
            fs::write(app.join("Contents/Info.plist"), plist).unwrap();
            app
        };
        let this = app("this", "sensor", "0.3.3");
        assert!(same_app(&this, &app("same", "sensor", "0.3.3")));
        assert!(!same_app(&this, &app("older", "sensor", "0.3.2")));
        assert!(!same_app(&this, &app("other", "another", "0.3.3")));
        assert!(!same_app(&this, &dir.path().join("absent")));
    }

    #[test]
    fn a_requirement_is_quoted_whole_for_the_shell() {
        assert_eq!(shell_escape_str("it's \"x\""), "it'\\''s \"x\"");
    }

    /// The menu bar is given each way to judge this Mac: the one in use,
    /// and for one that cannot be started from there, why.
    #[test]
    fn the_menu_bar_is_told_who_can_judge() {
        let small = Some("this Mac has 16 GB of memory".to_string());
        let said = choices(Some(Provider::Bedrock), small, |var| var == "OPENAI_API_KEY");
        assert_eq!(said.len(), 5, "this Mac, and four providers");
        assert_eq!(said[0]["args"], json!(["up", "--local"]));
        assert_eq!(said[0]["ready"], false);
        assert_eq!(said[0]["note"], "this Mac has 16 GB of memory");
        let by = |name: &str| {
            said.iter()
                .find(|c| c["args"] == json!(["up", "--provider", name]))
                .unwrap()
                .clone()
        };
        // Bedrock's profile has `default` to fall back on
        assert_eq!(by("bedrock")["current"], true);
        assert_eq!(by("bedrock")["ready"], true);
        assert!(by("bedrock")["label"].as_str().unwrap().contains("Amazon Bedrock"));
        assert_eq!(by("openai")["ready"], true);
        assert_eq!(by("anthropic")["current"], false);
        assert_eq!(by("anthropic")["ready"], false);
        assert!(by("anthropic")["note"].as_str().unwrap().contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn who_judges_persists_in_service_json() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_choice(dir.path()), None);
        write_choice(dir.path(), Some(Provider::Bedrock)).unwrap();
        assert_eq!(read_choice(dir.path()), Some(Some(Provider::Bedrock)));
        write_choice(dir.path(), None).unwrap();
        assert_eq!(read_choice(dir.path()), Some(None));
    }
}
