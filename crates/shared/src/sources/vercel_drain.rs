use std::net::SocketAddr;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// A Vercel log drain, received: Vercel POSTs a team's runtime logs
/// (requests, function output, builds, firewall decisions) to this
/// listener as they happen, a JSON array or NDJSON a delivery. Each is
/// checked against `x-vercel-signature` (HMAC-SHA1 of the body under the
/// drain's signature secret) and refused without it. Records are Vercel's
/// log objects, plus `source: vercel_drain`, `log` (Vercel's own `source`:
/// `lambda`, `edge`, `static`, `build`, `external`, `firewall`,
/// `redirect`) and `ts` (from `timestamp`).
///
/// The listener is plain HTTP; Vercel delivers over HTTPS, so something in
/// front of it (a load balancer, a tunnel) ends TLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VercelDrainConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: SocketAddr,
    /// The path Vercel is given, after the host.
    #[serde(default = "default_path")]
    pub path: String,
    /// The drain's signature secret (Team Settings → Drains), e.g.
    /// `${VERCEL_DRAIN_SECRET}`. Empty, the source stays idle and says so:
    /// it does not listen unsigned.
    #[serde(default, skip_serializing)]
    pub secret: Option<SecretString>,
}

fn default_bind_address() -> SocketAddr {
    "0.0.0.0:9000"
        .parse()
        .expect("default bind address should be valid")
}

fn default_path() -> String {
    "/vercel".into()
}
