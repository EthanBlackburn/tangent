use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// This Mac, as packs/macos reads it: what its Endpoint Security sensor
/// sees, with the programs that were already running when it started,
/// each new connection, from macOS's tcpdump, and each prompt typed to
/// Claude Code, from its transcripts under `~/.claude`. Tangent starts the
/// sensor and tcpdump itself, as root through `sudo`, which asks for the
/// password once, and stops them when the source stops. Tangent itself
/// runs as you.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MacosConfig {
    /// The sensor's binary. Left out, it is this release's, which tangent
    /// fetches once per version and checks before each start
    /// ([`crate::sensor`]). Named, it is one you built and signed:
    /// `tangent-sensor` inside Tangent.app (packs/macos/sensor),
    /// relative to the working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor: Option<PathBuf>,
}
