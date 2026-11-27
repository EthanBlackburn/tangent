//! The Mac's sensor as a release has it: packs/macos/sensor built, signed
//! with tangent's Developer ID and notarized by Apple, the asset
//! `tangent-sensor-macos.zip` beside the binaries. A `macos` source that
//! names no `sensor` runs this one from tangent's cache, where `tangent watch`
//! puts it once per version.
//!
//! The sensor runs as root, so it is checked where it is kept and again
//! before each start, by macOS's own `codesign`: the app must be the sensor
//! by its identifier, signed by tangent's team with a certificate Apple
//! issued, notarized by Apple, and whole, with no file of it changed since
//! it was signed. The ticket of its notarization is stapled to the app, so
//! the check asks nothing of the network.
//!
//! The cache is yours, and a program running as you can write to it: the
//! check finds a sensor that was replaced or changed, and does not stop one
//! swapped in between the check and the start.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// The release's asset: the app, zipped.
pub const ARCHIVE: &str = "tangent-sensor-macos.zip";

/// The app inside the archive, and the sensor inside the app.
pub const APP: &str = "Tangent.app";
const BINARY: &str = "Contents/MacOS/tangent-sensor";

/// Where `tangent up` installs the signed app bundle for the LaunchDaemon
/// and menu bar.
pub const INSTALLED_DIR: &str = "/Applications";

/// Where the root sensor daemon's own copy of the app is kept. Nothing but
/// root writes here or to any directory above it, which `/Applications` is
/// not: an administrator's programs may rename what is in it without a
/// password, and what launchd starts as root must not be theirs to replace.
/// The copy in `/Applications` is the one run as you, for the menu bar and
/// the notifications.
pub const DAEMON_APP_DIR: &str = "/Library/Application Support/Tangent";

/// Where the root sensor daemon listens on its Unix sockets (`es.sock`,
/// `net.sock`), unless overridden by `TANGENT_SENSOR_SOCKET_DIR`.
pub const DAEMON_DIR: &str = "/var/run/tangent";

/// Environment variable that overrides [`DAEMON_DIR`] (used in tests and
/// non-default daemon setups).
pub const SOCKET_DIR_ENV: &str = "TANGENT_SENSOR_SOCKET_DIR";

/// What the sensor is signed as: its bundle identifier, and the Apple
/// Developer team tangent's releases are signed by.
pub const IDENTIFIER: &str = "com.ethanblackburn.tangent.sensor";
const TEAM: &str = "8X5P8C448L";

/// macOS's own, by its full path: a `codesign` earlier on PATH is not asked.
pub const CODESIGN: &str = "/usr/bin/codesign";

/// Where the archive of tangent `version`'s sensor is.
pub fn url(version: &str) -> String {
    format!("https://github.com/EthanBlackburn/tangent/releases/download/v{version}/{ARCHIVE}")
}

/// Where this version's sensor is kept: `sensor` under tangent's cache
/// ([`crate::cache::dir`]), with the app in it.
pub fn dir() -> Result<PathBuf> {
    Ok(crate::cache::dir()?.join("sensor"))
}

/// The program a `macos` source starts, in the app under `dir`.
pub fn binary(dir: &Path) -> PathBuf {
    dir.join(APP).join(BINARY)
}

/// The installed app bundle under `/Applications`.
pub fn installed_app() -> PathBuf {
    Path::new(INSTALLED_DIR).join(APP)
}

/// The binary inside the installed app bundle under `/Applications`.
pub fn installed_binary() -> PathBuf {
    binary(Path::new(INSTALLED_DIR))
}

/// The root daemon's own copy of the app bundle.
pub fn daemon_app() -> PathBuf {
    Path::new(DAEMON_APP_DIR).join(APP)
}

/// The binary launchd starts as root, inside [`daemon_app`].
pub fn daemon_binary() -> PathBuf {
    binary(Path::new(DAEMON_APP_DIR))
}

/// Directory holding the sensor daemon's sockets.
pub fn daemon_dir() -> PathBuf {
    std::env::var_os(SOCKET_DIR_ENV)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from(DAEMON_DIR))
}

/// The Endpoint Security NDJSON socket inside `dir`.
pub fn es_socket(dir: &Path) -> PathBuf {
    dir.join("es.sock")
}

/// The tcpdump stream socket inside `dir`.
pub fn net_socket(dir: &Path) -> PathBuf {
    dir.join("net.sock")
}

/// What `codesign` holds the app to, in its own language: the sensor's
/// identifier, a certificate Apple issued to tangent's team, and Apple's
/// notarization.
pub fn requirement() -> String {
    format!(
        "identifier \"{IDENTIFIER}\" and anchor apple generic \
         and certificate leaf[subject.OU] = \"{TEAM}\" and notarized"
    )
}

/// Checks the app under `dir`: its signature is whole and meets
/// [`requirement`]. The error says which app, and what `codesign` said.
pub fn check(dir: &Path) -> Result<()> {
    let app = dir.join(APP);
    let out = Command::new(CODESIGN)
        .args(["--verify", "--strict", "--deep"])
        .arg(format!("-R={}", requirement()))
        .arg(&app)
        .output()
        .with_context(|| format!("running {CODESIGN}"))?;
    if !out.status.success() {
        bail!(
            "{} is not the sensor tangent's releases are signed as (team {TEAM}, notarized): {}",
            app.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sensor_is_this_version_s_under_the_cache() {
        assert_eq!(
            url("1.2.3"),
            "https://github.com/EthanBlackburn/tangent/releases/download/v1.2.3/tangent-sensor-macos.zip"
        );
        assert_eq!(
            binary(Path::new("/c/sensor")),
            PathBuf::from("/c/sensor/Tangent.app/Contents/MacOS/tangent-sensor")
        );
        assert!(dir()
            .unwrap()
            .ends_with(format!("tangent/{}/sensor", env!("CARGO_PKG_VERSION"))));
    }

    /// The check takes no app but the sensor: nothing there, and an app
    /// Apple signed as something else, both fail it.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_app_that_is_not_the_sensor_fails_the_check() {
        let empty = tempfile::tempdir().unwrap();
        let e = check(empty.path()).unwrap_err().to_string();
        assert!(e.contains("Tangent.app is not the sensor"), "{e}");

        let other = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            "/System/Applications/Calculator.app",
            other.path().join(APP),
        )
        .unwrap();
        let e = check(other.path()).unwrap_err().to_string();
        assert!(e.contains("is not the sensor"), "{e}");
    }
}
