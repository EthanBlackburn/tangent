use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::sources::common::{bare_string, bare_string_opt};

/// A Vercel team's activity log, polled from the REST API
/// (`GET /v3/events?teamId=…`), which every plan has. Records are emitted
/// as Vercel returns them, with their `payload`, plus `source: vercel` and
/// `ts` (from `createdAt`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VercelConfig {
    /// The team's ID, e.g. `team_1a2b3c4d5e6f7g8h9i0j1k2l` (Settings →
    /// General). Empty, the source stays idle and says so.
    #[serde(default, deserialize_with = "bare_string_opt")]
    pub team_id: Option<String>,
    /// An access token that can read the team, e.g. `${VERCEL_TOKEN}`.
    #[serde(default, skip_serializing)]
    pub token: Option<SecretString>,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    /// On first start, how far back to read; afterwards from the cursor.
    #[serde(default = "default_since", deserialize_with = "bare_string")]
    pub since: String,
    /// The API root.
    #[serde(default = "default_api")]
    pub api: String,
}

const fn default_interval_secs() -> u64 {
    60
}
fn default_since() -> String {
    "1h".into()
}
fn default_api() -> String {
    "https://api.vercel.com".into()
}
