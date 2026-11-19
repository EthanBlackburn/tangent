use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// This Mac, as packs/macos reads it: what its Endpoint Security sensor
/// sees, with the programs that were already running when it started, and
/// each new connection, from macOS's tcpdump. Tangent starts the sensor and
/// tcpdump itself, as root through `sudo`, which asks for the password
/// once, and stops them when the source stops. Tangent itself runs as you.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MacosConfig {
    /// The sensor's binary, `tangent-sensor` inside TangentSensor.app
    /// (packs/macos/sensor), relative to the working directory: a
    /// release's, or one you built and signed.
    pub sensor: PathBuf,
}
