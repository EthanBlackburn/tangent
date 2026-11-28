use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::path::PathBuf;
use std::sync::Arc;
pub use tangent_compact::{CompactConfig, SourceSpec};

/// Ask a model about each record. The node names its model, an entry under
/// `models`, and holds what is asked of it: it sends `prompt_file` as the system
/// message and the records it is handed (or their listed `fields`), a JSON
/// or logfmt line each, as the user message, and adds each record's answer to it under
/// the node's name. It adds and forwards; it never drops. What happens next
/// is a plugin's call: a plugin whose `probe` selects on `<node name>.flag`
/// is that filter.
///
/// The node runs inside each worker, in DAG order with the plugins, so a
/// batch's records reach the model and leave it in order.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceConfig {
    /// The nodes whose records this one takes, by name: sources, plugins and
    /// inference nodes. A node with none never runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<Arc<str>>,

    /// The model it asks: an entry under `models`, by name.
    pub model: Arc<str>,

    /// System prompt (relative to the file that names it).
    pub prompt_file: PathBuf,

    /// A JSON Schema (relative to the file that names it) the reply must satisfy,
    /// enforced by the model's API: `response_format` on an OpenAI-compatible
    /// server, structured output on Anthropic and Bedrock. Without one, an
    /// `openai` server is asked for JSON mode (any object) and an `anthropic`
    /// or `bedrock` model is held to the prompt alone. Either way the node reads the reply as JSON and
    /// nothing else: a reply that is not a JSON object lands as the error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_file: Option<PathBuf>,

    /// Record fields to show the model; the whole record when empty.
    #[serde(default)]
    pub fields: Vec<String>,

    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: usize, // a request past this is split

    /// How the records are written into the user message: `ndjson`, a JSON
    /// line each (the default), or `logfmt`, the same records, every field
    /// and value, a logfmt line each in about half the tokens, also split at
    /// `budget_tokens`.
    #[serde(default)]
    pub encoding: Encoding,

    #[serde(default)]
    pub group_by: Vec<String>, // a request holds one value of these

    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32, // per record

    /// Sent only when set; the model's default otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,

    /// Extra request parameters merged into the body, e.g.
    /// `chat_template_kwargs: {enable_thinking: false}` for mlx_lm.server or
    /// `reasoning_effort: low` for gpt-oss. These win over what the node sets.
    #[serde(default)]
    pub extra: Map<String, Value>,

    /// What becomes of records whose request never got an answer to read:
    /// the model could not be reached (no reply, a dropped connection, a
    /// 429 or a 5xx, every try) or would not serve the key (a 401, a 403,
    /// a sign-in that has run out). `pass`, the default, sends them on with
    /// the error where the answer would be. `hold` keeps them in the state
    /// store and asks again each minute until the model answers, so an
    /// outage leaves nothing unjudged: they go on late, and in the order
    /// they are answered. A reply that cannot be read is an error either
    /// way, since asking again gets the same.
    #[serde(default, skip_serializing_if = "Unreached::is_pass")]
    pub unreached: Unreached,
}

/// [`InferenceConfig::unreached`].
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Unreached {
    #[default]
    Pass,
    Hold,
}

impl Unreached {
    fn is_pass(&self) -> bool {
        *self == Unreached::Pass
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Encoding {
    #[default]
    Ndjson,
    Logfmt(CompactConfig),
}

const fn default_batch_bytes() -> usize {
    32_768
}
const fn default_max_tokens() -> u32 {
    2_000
}
