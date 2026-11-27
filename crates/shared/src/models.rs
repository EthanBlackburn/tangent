use std::collections::BTreeMap;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// A model, as tangent reaches it: where it is served, which model, with
/// whose credentials, and how hard it may be pushed. An inference node names
/// one (`model: <name>`) and holds what is asked of it. Nodes that name the
/// same entry share its `concurrency`: a server that answers one request at a
/// time is asked one at a time, whoever asks, a conversation's turn before
/// the request of a node's records.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfig {
    /// The API it is served through.
    #[serde(rename = "type")]
    pub kind: ModelKind,

    /// Base URL of the chat completions API (`openai`); [`DEFAULT_URL`] when
    /// unset. `anthropic` and `responses` take one only to reach their API at
    /// another address (a gateway), and `bedrock` reads none, so none of them
    /// gets a default.
    #[serde(
        default,
        deserialize_with = "some_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub url: Option<String>,

    /// The key: an `openai` server's bearer token, e.g.
    /// "${OPENAI_API_KEY}", or `anthropic`'s or `responses`'s, which need
    /// one, e.g. "${ANTHROPIC_API_KEY}".
    #[serde(default, skip_serializing)]
    pub api_key: Option<SecretString>,

    /// Model id as the server knows it, e.g. `mlx-community/GLM-4.7-Flash-4bit`,
    /// `claude-haiku-5-5` or `us.anthropic.claude-haiku-5-5`.
    pub model: String,

    /// AWS settings, for `bedrock`.
    #[serde(default)]
    pub aws: AwsConfig,

    /// Requests in flight at once to this model, from every node that names
    /// it and every worker together.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    /// A request past this is a failure; it also frees the concurrency slot it
    /// held. 30 s by default; a local model may need more.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Attempts after the first for a request that got no reply (a timeout, a
    /// connection or server error), which back off 1 s, 2 s, 4 s, ..., and
    /// for one record's reply with no answer in it (no text, not JSON, an
    /// empty list). A reply to several records that answers none is asked
    /// again in halves instead.
    #[serde(default = "default_retries")]
    pub retries: u32,

    /// The model asked what this one declines: an id the same server knows,
    /// e.g. `claude-sonnet-5`, asked with the same key and limits. A request
    /// is declined when the reply says the model refused it or the provider
    /// filtered it (`stop_reason: refusal`, `finish_reason: content_filter`);
    /// it is then sent once more, as it was, to this model, and that reply
    /// is the reply. Unset, a declined request is the node's error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<String>,

    /// Its server, when tangent is to run it; unset when the server is
    /// someone else's to run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve: Option<ServeConfig>,
}

/// A model's server that tangent runs. It is started with the pipeline unless
/// something already answers at the model's `url`, nothing is read from a
/// source until it answers there, and it is stopped when tangent stops. One
/// that was already answering is left as it was found.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServeConfig {
    /// The program and its arguments, e.g.
    /// `[llama-server, -m, model.gguf, --port, "8080"]`.
    pub command: Vec<String>,

    /// Variables it is started with, beside tangent's own.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelKind {
    /// An OpenAI-compatible chat completions endpoint at `url`: OpenAI,
    /// mlx_lm.server, llama-server, vLLM, Bedrock's OpenAI endpoint, ...
    Openai,
    /// Anthropic's own Messages API, with `api_key`.
    Anthropic,
    /// Amazon Bedrock through the Converse API, with the AWS credential chain.
    Bedrock,
    /// OpenAI's Responses API, with `api_key`: what its models that think
    /// take tools through, which chat completions refuses them.
    Responses,
}

/// A `bedrock` model's AWS settings.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AwsConfig {
    /// Region; the SDK's default when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Profile; the default credential chain when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// Where an `openai` model that names no `url` is asked.
pub const DEFAULT_URL: &str = "http://localhost:8080/v1";

impl ModelConfig {
    /// Gives an `openai` model without a `url` the default, as the config
    /// shows it. An `anthropic` or `bedrock` model keeps what it was given.
    pub fn default_url(&mut self) {
        if self.kind == ModelKind::Openai && self.url.is_none() {
            self.url = Some(DEFAULT_URL.into());
        }
    }
}

/// A `url:` written but left empty is the empty string, as it was when
/// `url` was a `String`; only a `url` not written at all is unset.
fn some_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

const fn default_concurrency() -> usize {
    1
}
const fn default_timeout_ms() -> u64 {
    30_000
}
const fn default_retries() -> u32 {
    2
}
