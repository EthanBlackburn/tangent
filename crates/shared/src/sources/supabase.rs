use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::sources::common::{bare_string, bare_string_opt};

/// A Supabase project's logs, queried from the Management API
/// (`GET /v1/projects/{ref}/analytics/endpoints/logs`: ClickHouse SQL over
/// a day at most). One log a source, `auth_logs` by default: the Auth
/// server's requests, and its audit events under `auth_event.*`. Records
/// are the rows Supabase returns (`id`, `timestamp`, `event_message`,
/// `severity_text`, `log_attributes`), plus `source: supabase`, `log` (the
/// log's name) and `ts` (from `timestamp`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupabaseConfig {
    /// The project's reference, e.g. `abcdefghijklmnopqrst` (Project
    /// Settings → General). Empty, the source stays idle and says so.
    #[serde(default, deserialize_with = "bare_string_opt")]
    pub project_ref: Option<String>,
    /// A Management API access token that can read the project's logs
    /// (`analytics:read`), e.g. `${SUPABASE_ACCESS_TOKEN}`.
    #[serde(default, skip_serializing)]
    pub token: Option<SecretString>,
    /// Which log: `auth_logs`, `auth_audit_logs`, `edge_logs`,
    /// `postgres_logs`, ... Another log is another source.
    #[serde(default = "default_log")]
    pub log: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    /// On first start, how far back to read; afterwards from the cursor.
    #[serde(default = "default_since", deserialize_with = "bare_string")]
    pub since: String,
    /// The API root.
    #[serde(default = "default_api")]
    pub api: String,
}

fn default_log() -> String {
    "auth_logs".into()
}
const fn default_interval_secs() -> u64 {
    60
}
fn default_since() -> String {
    "1h".into()
}
fn default_api() -> String {
    "https://api.supabase.com".into()
}
