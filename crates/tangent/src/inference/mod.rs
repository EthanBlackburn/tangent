//! Inference nodes: a model reads each record. A node lives inside each
//! worker and runs in DAG order with the plugins: the worker hands it the
//! records that reached it, waits for the replies (its model's `concurrency` at
//! a time, [`Model`]),
//! and carries the annotated records on to the node's outputs. The system
//! prompt is a file; the user message is the records of one `group_by` value
//! (or selected fields), a JSON line each; each record's answer is added to
//! it under the node's name. The node adds and forwards, never drops: a
//! failure lands as `{"error": ...}` in the same field, and a plugin
//! downstream decides what goes on.
//!
//! The reply is read as JSON and nothing else. The model's API is asked to make
//! it so: a schema (`schema_file`) through rig's structured output, or JSON
//! mode on an OpenAI-compatible server. A server that ignores both (mlx_lm)
//! is held to the prompt, and a reply that is not a JSON object is the error.

use ahash::HashMap;
use anyhow::{anyhow, bail, Context, Result};
use rig_core::completion::message::CallId;
use rig_core::completion::message::StopReason;
use rig_core::completion::request::{CompletionRequest, ToolDefinition};
use rig_core::completion::{AssistantContent, CacheRetention, Message, OnUnsupported};
use rig_core::schemars;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tangent_compact as compact;
use tangent_shared::inference::{Encoding, InferenceConfig};
use tangent_shared::models::{ModelConfig, ModelKind};

mod model;
pub mod price;
pub mod serve;
pub use model::Model;

use crate::stop::Stop;

pub struct InferenceNode {
    pub name: Arc<str>,
    cfg: InferenceConfig,
    prompt: String,
    /// The shape the model's API is asked to enforce, from `schema_file`.
    schema: Option<schemars::Schema>,
    /// The model it asks, which every node that names it shares.
    model: Arc<Model>,
    /// Whether the run has somewhere to keep records: `unreached: hold`
    /// holds nothing in a run without (a replay), where what is held would
    /// be lost.
    keeps: std::sync::atomic::AtomicBool,
    /// Whether the provider has refused a conversation its cache
    /// checkpoint: its turns are then asked without one.
    uncached: std::sync::atomic::AtomicBool,
}

fn resolve(config_dir: &Path, file: &Path) -> PathBuf {
    if file.is_absolute() {
        file.to_path_buf()
    } else {
        config_dir.join(file)
    }
}

/// Whether a provider's error is its refusal of a cache checkpoint, which
/// the same request without one would not get.
fn refuses_the_cache(error: &str) -> bool {
    let e = error.to_ascii_lowercase();
    (e.contains("cachepoint")
        || e.contains("cache_control")
        || e.contains("cache point")
        || e.contains("cache checkpoint"))
        && (e.contains("400") || e.contains("validation") || e.contains("invalid"))
}

/// The log target a traced conversation's turns are told at
/// ([`InferenceNode::chat`]).
pub const TRACE: &str = "tangent::agent";

/// The most of a text a traced turn tells.
const TOLD: usize = 1500;

/// `text` cut at [`TOLD`].
fn cut(text: &str) -> String {
    match text.char_indices().nth(TOLD) {
        None => text.to_string(),
        Some((at, _)) => format!(
            "{}\n[cut: {} more characters]",
            &text[..at],
            text[at..].chars().count()
        ),
    }
}

impl InferenceNode {
    pub fn new(
        name: Arc<str>,
        cfg: InferenceConfig,
        model: Arc<Model>,
        config_dir: &Path,
    ) -> Result<Self> {
        let prompt_path = resolve(config_dir, &cfg.prompt_file);
        let prompt = std::fs::read_to_string(&prompt_path)
            .with_context(|| format!("reading prompt {}", prompt_path.display()))?;
        if prompt.trim().is_empty() {
            bail!("prompt {} is empty", prompt_path.display());
        }
        let schema = match &cfg.schema_file {
            Some(file) => {
                let path = resolve(config_dir, file);
                let text = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading schema {}", path.display()))?;
                let value: Value = serde_json::from_str(&text)
                    .with_context(|| format!("schema {} is not JSON", path.display()))?;
                Some(
                    schemars::Schema::try_from(value)
                        .map_err(|e| anyhow!("schema {}: {e}", path.display()))?,
                )
            }
            None => None,
        };
        tracing::info!(node = %name, model = %cfg.model, "inference ready");
        Ok(Self {
            name,
            cfg,
            prompt,
            schema,
            model,
            keeps: std::sync::atomic::AtomicBool::new(false),
            uncached: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// One turn of a conversation a plugin holds (`model.chat`): the
    /// plugin's messages and tools to the model, in one of its model's
    /// places and with the node's prompt, timeout and retries, and the model's
    /// turn back, as the plugin interface describes both. A turn the model
    /// did not finish is the error: one it failed or refused, one with
    /// neither text nor a call after `retries` more tries, one `max_tokens`
    /// cut with a call in it.
    ///
    /// A request with a `trace` (a name for its conversation, the plugin's
    /// to choose) is one whose turns are told as they happen, each a line of
    /// JSON logged at target [`TRACE`]: `results` as a turn is asked (what
    /// the model's last calls were given back, cut), then `turn` (the
    /// reasoning the model showed, what it said and its calls) or `error`.
    pub async fn chat(&self, request: &str) -> Result<String> {
        let asked: Value = serde_json::from_str(request).context("the request is not JSON")?;
        let Some(trace) = asked.get("trace").and_then(Value::as_str) else {
            return self.turn(asked).await;
        };
        let tell = |mut line: Value| {
            line["trace"] = json!(trace);
            line["node"] = json!(self.name);
            tracing::info!(target: TRACE, line = %line);
        };
        let last = asked["messages"].as_array().and_then(|m| m.last());
        match last.and_then(|m| m["results"].as_array()) {
            Some(results) => tell(
                json!({"kind": "results", "results": results.iter().map(|r| {
                json!({"name": r["name"], "text": cut(r["text"].as_str().unwrap_or("")),
                       "failed": r["error"] == true})
            }).collect::<Vec<_>>()}),
            ),
            // the conversation's first turn, or one asked for again
            None => tell(
                json!({"kind": "asked", "first": asked["messages"].as_array().is_some_and(|m| m.len() <= 2)}),
            ),
        }
        let reply = self.turn(asked.clone()).await;
        match &reply {
            Ok(reply) => {
                let reply: Value = serde_json::from_str(reply).unwrap_or_default();
                tell(
                    json!({"kind": "turn", "thinking": cut(reply["thinking"].as_str().unwrap_or("")),
                            "said": cut(reply["text"].as_str().unwrap_or("")),
                            "calls": reply["calls"].as_array().map(|calls| calls.iter().map(|c| {
                                json!({"name": c["name"], "arguments": c["arguments"]})
                            }).collect::<Vec<_>>())}),
                );
            }
            Err(e) => tell(json!({"kind": "error", "error": format!("{e:#}")})),
        }
        reply
    }

    /// One turn of [`Self::chat`], its request read.
    async fn turn(&self, request: Value) -> Result<String> {
        let said = request
            .get("messages")
            .and_then(Value::as_array)
            .context("the request has no `messages`")?;
        if said.last().context("`messages` is empty")?["role"] != "user" {
            bail!("the last message is not the user's");
        }
        if said.iter().skip(1).any(|m| m["role"] == "system") {
            bail!("a system message goes ahead of the others");
        }
        let mut messages = said
            .iter()
            .map(chat_message)
            .collect::<Result<Vec<Message>>>()?;
        let last = messages.pop().expect("checked above");
        let tools: Vec<ToolDefinition> = match request.get("tools") {
            Some(tools) => serde_json::from_value(tools.clone()).context("`tools`")?,
            None => Vec::new(),
        };
        let mut turn = CompletionRequest::new(last)
            .messages(messages)
            .preamble(self.prompt.trim_end())
            .tools(tools)
            .max_tokens(u64::from(self.cfg.max_tokens));
        if let Some(t) = self.cfg.temperature {
            turn = turn.temperature(t);
        }
        if !self.cfg.extra.is_empty() {
            turn = turn.additional_params(Value::Object(self.cfg.extra.clone()));
        }
        // The conversation so far is kept by the provider for the next turn
        // where it can be: the client leaves the checkpoint out where it
        // knows the provider has none, and a provider that refuses the one
        // it is sent is asked again without, from then on.
        let uncached = &self.uncached;
        let plain = turn.clone();
        let mut cached = request.get("cache").and_then(Value::as_bool) == Some(true)
            && !uncached.load(std::sync::atomic::Ordering::Relaxed);
        if cached {
            turn = turn
                .cache(CacheRetention::Short)
                .on_unsupported(OnUnsupported::Ignore);
        }
        // A turn with neither text nor a call (a model that thought and
        // stopped, a server that dropped what it wrote) is asked for again as
        // one that never came is, `retries` times: the same request does not
        // get the same turn twice. The last one is the turn, and the error
        // below.
        let mut attempt = 0;
        let (reply, content, calls) = loop {
            attempt += 1;
            let reply = {
                let _place = self.model.turn().await;
                // A turn that waited for its place while the run began to
                // stop is one not yet sent.
                if self.model.stop().finishing() {
                    bail!("tangent is stopping: the turn was not sent");
                }
                match self.model.send(&self.name, turn.clone()).await {
                    Err(e) if cached && refuses_the_cache(&format!("{e:#}")) => {
                        tracing::warn!(
                            node = %self.name,
                            "the provider refused the conversation's cache checkpoint, asking without it: {e:#}"
                        );
                        uncached.store(true, std::sync::atomic::Ordering::Relaxed);
                        cached = false;
                        turn = plain.clone();
                        self.model.send(&self.name, turn.clone()).await?
                    }
                    reply => reply?,
                }
            };
            // A call the client kept as an item it does not understand is the
            // call it is ([`tool_call`]); the turn then goes back with it so.
            let content: Vec<AssistantContent> = reply
                .choice
                .iter()
                .map(|block| tool_call(block).unwrap_or_else(|| block.clone()))
                .collect();
            let calls: Vec<Value> = content
                .iter()
                .filter_map(|block| match block {
                    AssistantContent::ToolCall(c) => Some(
                        json!({"id": c.id, "name": c.function.name, "arguments": c.function.arguments}),
                    ),
                    _ => None,
                })
                .collect();
            let silent = calls.is_empty()
                && reply.text().trim().is_empty()
                && !matches!(reply.stop(), StopReason::Error(_) | StopReason::Aborted(_));
            if !silent || attempt > self.model.cfg.retries {
                break (reply, content, calls);
            }
            tracing::warn!(
                node = %self.name,
                attempt,
                "the turn has no text and no call (finish: {:?}), asking again",
                reply.finish_reason()
            );
        };
        let text = reply.text();
        let stop = match reply.stop() {
            StopReason::Error(e) | StopReason::Aborted(e) => {
                bail!("the model failed the turn: {e}")
            }
            StopReason::Length if !calls.is_empty() => bail!(
                "max_tokens ({}) cut the turn with a tool call in it, so its arguments may not be whole",
                self.cfg.max_tokens
            ),
            _ if calls.is_empty() && text.trim().is_empty() => bail!(
                "reply has no text and no call (finish: {:?}; the model may have spent its budget thinking)",
                reply.finish_reason()
            ),
            StopReason::Length => "length",
            _ if calls.is_empty() => "stop",
            _ => "tool_use",
        };
        // the reasoning the model showed before the turn, for whoever reads
        // how a conversation went: a model that shows none has none here
        let thinking: Vec<String> = content
            .iter()
            .filter_map(|block| match block {
                AssistantContent::Reasoning(r) if !r.text.trim().is_empty() => {
                    Some(r.text.trim().to_string())
                }
                _ => None,
            })
            .collect();
        let message = if content == reply.choice {
            reply.message()
        } else {
            Some(Message::Assistant(reply.continued(content)))
        };
        tracing::debug!(node = %self.name, stop, calls = calls.len(), "chat turn");
        Ok(json!({
            "message": message,
            "text": text,
            "thinking": thinking.join("\n\n"),
            "calls": calls,
            "stop": stop,
            "usage": reply.usage,
        })
        .to_string())
    }

    /// Every record annotated, in the order given. For tests: a run asks
    /// with [`Self::annotate_unsent`], which a stop can leave part unsent.
    #[cfg(test)]
    pub async fn annotate_all(&self, records: Vec<Value>) -> Vec<Value> {
        let annotated = self.annotate_unsent(records).await;
        annotated
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect()
    }

    /// Each record annotated, in the order given, or none for a record
    /// whose request was not sent: once the run is finishing
    /// ([`crate::stop::Stop`]) a request still waiting for one of the
    /// model's places is left unsent, and the ones out are waited for.
    /// Tells the node the run keeps what it holds ([`Self::holds`]).
    pub fn keep(&self, keeps: bool) {
        self.keeps
            .store(keeps, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether records the model could not be asked about are held to be
    /// asked again: `unreached: hold`, in a run that keeps them.
    pub fn holds(&self) -> bool {
        self.cfg.unreached == tangent_shared::inference::Unreached::Hold
            && self.keeps.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether its model's last request went unanswered.
    pub fn down(&self) -> bool {
        self.model.down()
    }

    /// Whether held records may go back to it now: all of them once its
    /// model answers, and while it is down one request in `every`.
    pub fn takes_again(&self, every: std::time::Duration) -> bool {
        !self.model.down() || self.model.probe(every)
    }

    pub async fn annotate_unsent(&self, records: Vec<Value>) -> Vec<Option<Value>> {
        let n = records.len();
        // told to a watcher as being asked about, until they are answered
        let _asking: Vec<crate::underway::Mark> = records
            .iter()
            .map(|v| crate::underway::mark(crate::underway::Stage::Asking, &self.name, v))
            .collect();
        let mut groups: Vec<(String, Vec<(usize, Value)>)> = Vec::new();
        for (i, v) in records.into_iter().enumerate() {
            let key: Vec<Option<&Value>> =
                self.cfg.group_by.iter().map(|f| lookup(&v, f)).collect();
            let key = json!(key).to_string();
            match groups.iter_mut().find(|(k, _)| *k == key) {
                Some((_, g)) => g.push((i, v)),
                None => groups.push((key, vec![(i, v)])),
            }
        }
        let mut jobs: Vec<(Vec<usize>, Vec<Value>)> = Vec::new();
        for (_, group) in groups {
            let (ids, values): (Vec<usize>, Vec<Value>) = group.into_iter().unzip();
            let mut at = 0;
            for chunk in self.chunks(values) {
                let len = chunk.len();
                jobs.push((ids[at..at + len].to_vec(), chunk));
                at += len;
            }
        }
        let done = futures::future::join_all(jobs.into_iter().map(|(ids, chunk)| async move {
            let _place = self.model.place().await;
            if self.model.stop().finishing() {
                return (ids, None);
            }
            (ids, Some(self.annotate(chunk).await))
        }))
        .await;
        let mut slots = vec![None; n];
        for (ids, out) in done {
            for (i, v) in ids.into_iter().zip(out.into_iter().flatten()) {
                // null is a record held for a model that was not reached
                // (`annotate`): unsent, as one the stop kept back is
                slots[i] = (!v.is_null()).then_some(v);
            }
        }
        slots
    }

    /// Records in one request. A reply with nothing to read for any of them
    /// (not JSON, or JSON that answers none) is asked again in halves, and
    /// for one record, which has no halves, again as it is, `retries` times;
    /// the records a reply skipped are asked again without the ones it
    /// answered.
    async fn annotate(&self, records: Vec<Value>) -> Vec<Value> {
        let n = records.len();
        let start = Instant::now();
        let mut attempt = 0;
        let answers = loop {
            attempt += 1;
            let answers = match self.user(&records) {
                Ok(user) => self.ask(user, n).await.and_then(|reply| {
                    let said = head(&reply.to_string(), 200);
                    let answers = spread(reply, n, matches!(self.cfg.encoding, Encoding::Ndjson));
                    match answers.iter().any(Option::is_some) {
                        true => Ok(answers),
                        false => bail!("reply answers no record: {said}"),
                    }
                }),
                Err(e) => Err(e),
            };
            match &answers {
                Err(e)
                    if n == 1
                        && attempt <= self.model.cfg.retries
                        && e.to_string().starts_with("reply ") =>
                {
                    tracing::warn!(node = %self.name, attempt, "asking again: {e:#}");
                }
                _ => break answers,
            }
        };
        let answers = match answers {
            Ok(answers) => {
                // A model given several records now and then answers some and
                // stops: the reply is whole JSON, and each skipped record
                // would go on with an error where its verdict should be.
                // Fewer records each time, so this ends.
                let skipped: Vec<usize> = (0..n).filter(|k| answers[*k].is_none()).collect();
                if !skipped.is_empty() {
                    tracing::warn!(
                        node = %self.name,
                        records = n,
                        skipped = skipped.len(),
                        "reply skipped records, asking for them again"
                    );
                    let again: Vec<Value> = skipped.iter().map(|k| records[*k].clone()).collect();
                    let mut redone = Box::pin(self.annotate(again)).await.into_iter();
                    return records
                        .into_iter()
                        .zip(answers)
                        .map(|(v, a)| match a {
                            Some(a) => attach(&self.name, v, a),
                            None => redone.next().unwrap_or(v),
                        })
                        .collect();
                }
                answers.into_iter().flatten().collect()
            }
            // a failed request would fail the same in halves
            Err(e) if n > 1 && e.to_string().starts_with("reply ") => {
                tracing::warn!(
                    node = %self.name,
                    records = n,
                    "reply unreadable, asking again in halves: {e:#}"
                );
                let mut records = records;
                let tail = records.split_off(n / 2);
                let mut out = Box::pin(self.annotate(records)).await;
                out.extend(Box::pin(self.annotate(tail)).await);
                return out;
            }
            // The model was not reached, or would not serve the key: with
            // `unreached: hold` the records wait to be asked again, and go
            // on with no error in the answer's place.
            Err(e) if self.holds() && e.downcast_ref::<model::Unreached>().is_some() => {
                tracing::warn!(
                    node = %self.name,
                    records = n,
                    "the model was not reached, and the records are held to be asked again: {e:#}"
                );
                return vec![Value::Null; n];
            }
            Err(e) => {
                tracing::warn!(node = %self.name, records = n, "inference failed: {e:#}");
                vec![json!({"error": format!("{e:#}")}); n]
            }
        };
        tracing::debug!(
            node = %self.name,
            records = n,
            ms = start.elapsed().as_millis() as u64,
            "inference"
        );
        records
            .into_iter()
            .zip(answers)
            .map(|(v, a)| attach(&self.name, v, a))
            .collect()
    }

    /// About `batch_bytes` of JSON per request; with `logfmt`, also within its `budget_tokens`.
    fn chunks(&self, records: Vec<Value>) -> Vec<Vec<Value>> {
        let parts = self.split(records);
        let Encoding::Logfmt(cfg) = &self.cfg.encoding else {
            return parts;
        };
        let mut out = Vec::new();
        for part in parts {
            let views: Vec<Value> = part.iter().map(|v| self.object(v)).collect();
            let mut part = part.into_iter();
            // objects no deeper than serde_json reads: nothing it cannot write
            match compact::encode(&views, cfg) {
                Ok(chunks) => out.extend(
                    chunks
                        .iter()
                        .map(|c| part.by_ref().take(c.records.len()).collect()),
                ),
                Err(_) => out.extend(part.map(|r| vec![r])),
            }
        }
        out
    }

    fn split(&self, records: Vec<Value>) -> Vec<Vec<Value>> {
        let max_bytes = self.cfg.batch_bytes.max(1);
        let mut out = Vec::new();
        let mut cur: Vec<Value> = Vec::new();
        let mut bytes = 0usize;
        for v in records {
            let size = self.view(&v).to_string().len();
            if !cur.is_empty() && bytes + size > max_bytes {
                out.push(std::mem::take(&mut cur));
                bytes = 0;
            }
            bytes += size;
            cur.push(v);
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }

    /// The record as the model sees it: whole, or the listed `fields`.
    fn view(&self, v: &Value) -> Value {
        if self.cfg.fields.is_empty() {
            return v.clone();
        }
        let mut m = Map::new();
        for f in &self.cfg.fields {
            if let Some(x) = lookup(v, f) {
                m.insert(f.clone(), x.clone());
            }
        }
        Value::Object(m)
    }

    /// The user message: a JSON line per record, or `logfmt` text.
    fn user(&self, records: &[Value]) -> Result<String> {
        match &self.cfg.encoding {
            Encoding::Ndjson => Ok(records
                .iter()
                .enumerate()
                .map(|(k, v)| self.line(k, v))
                .collect::<Vec<_>>()
                .join("\n")),
            Encoding::Logfmt(cfg) => {
                let views: Vec<Value> = records.iter().map(|v| self.object(v)).collect();
                Ok(compact::encode_chunk(&views, cfg)?.0)
            }
        }
    }

    /// The view as an object: a record that is not one shows nothing, as in `line`.
    fn object(&self, v: &Value) -> Value {
        match self.view(v) {
            o @ Value::Object(_) => o,
            _ => Value::Object(Map::new()),
        }
    }

    fn line(&self, k: usize, v: &Value) -> String {
        let mut m = Map::new();
        m.insert("i".into(), json!(k));
        if let Value::Object(fields) = self.view(v) {
            m.extend(fields);
        }
        serde_json::to_string(&Value::Object(m)).unwrap_or_default()
    }

    fn request(&self, user: String, n: usize) -> CompletionRequest {
        // logfmt text groups records, so its answers go by index rather than as written
        let (format, order) = match self.cfg.encoding {
            Encoding::Ndjson => (
                "The records are one JSON object per line, each with its index `i`.",
                "in the same order",
            ),
            Encoding::Logfmt(_) => (compact::LEGEND, "in order of index"),
        };
        let preamble = format!(
            "{}\n\n{format} Reply with one JSON object, \
             {{\"answers\": [...]}}, holding one answer per record, {n} in all, {order}, each the \
             record's answer with its index first: {{\"i\": k, ...}}. Keep going through \
             every record: the reply is not finished until the answer with \"i\": {last} is written, then close \
             the array and the object. The reply is the JSON object itself: no code fence, no text before or \
             after it.",
            self.prompt.trim_end(),
            last = n.saturating_sub(1)
        );
        let mut request = CompletionRequest::new(user)
            .preamble(preamble)
            .max_tokens(u64::from(self.cfg.max_tokens) * n as u64);
        if let Some(t) = self.cfg.temperature {
            request = request.temperature(t);
        }
        let mut params = Map::new();
        match (&self.schema, self.model.cfg.kind) {
            (Some(schema), _) => {
                request = request.output_schema(answers_schema(schema));
            }
            // JSON mode: any object. Messages and Converse have no such
            // mode without a schema.
            (None, ModelKind::Openai) => {
                params.insert("response_format".into(), json!({"type": "json_object"}));
            }
            (None, ModelKind::Anthropic | ModelKind::Bedrock | ModelKind::Responses) => {}
        }
        for (k, v) in &self.cfg.extra {
            params.insert(k.clone(), v.clone());
        }
        if !params.is_empty() {
            request = request.additional_params(Value::Object(params));
        }
        request
    }

    /// The reply as a JSON object.
    async fn ask(&self, user: String, n: usize) -> Result<Value> {
        let request = self.request(user, n);
        let uncached = &self.uncached;
        let cached = self.cfg.cache && !uncached.load(std::sync::atomic::Ordering::Relaxed);
        let reply = if cached {
            let kept = request
                .clone()
                .cache(CacheRetention::Short)
                .on_unsupported(OnUnsupported::Ignore);
            match self.model.send(&self.name, kept).await {
                Err(e) if refuses_the_cache(&format!("{e:#}")) => {
                    tracing::warn!(
                        node = %self.name,
                        "the provider refused the prompt's cache checkpoint, asking without it: {e:#}"
                    );
                    uncached.store(true, std::sync::atomic::Ordering::Relaxed);
                    self.model.send(&self.name, request).await?
                }
                reply => reply?,
            }
        } else {
            self.model.send(&self.name, request).await?
        };
        // Reasoning comes back as its own block, so the text is the answer.
        let text = reply.text();
        if text.trim().is_empty() {
            bail!(
                "reply has no text (finish: {:?}; the model may have spent its budget thinking)",
                reply.finish_reason()
            );
        }
        let value: Value = serde_json::from_str(text.trim())
            .map_err(|e| anyhow!("reply is not JSON ({e}): {}", head(&text, 200)))?;
        if !value.is_object() {
            bail!("reply is not a JSON object: {}", head(&text, 200));
        }
        Ok(value)
    }
}

/// A tool call Bedrock marks `"type": "tool_use"`, as Claude 5 does on
/// Converse, which rig-bedrock 0.45 reads as a hosted tool's use and keeps
/// as an item with no meaning: the call it is. None for any other block.
fn tool_call(block: &AssistantContent) -> Option<AssistantContent> {
    let AssistantContent::Opaque(_) = block else {
        return None;
    };
    let block = serde_json::to_value(block).ok()?;
    let call = block.get("item")?.get("toolUse")?;
    if call.get("type").and_then(Value::as_str) != Some("tool_use") {
        return None;
    }
    let id = CallId::from_wire(call.get("toolUseId")?.as_str()?);
    serde_json::from_value(json!({
        "type": "toolcall",
        "id": id,
        "function": {"name": call.get("name")?, "arguments": call.get("input")?},
    }))
    .ok()
}

/// A message of a plugin's conversation as the model's client holds it: the
/// plugin's own text or tool results, or a reply's `message` as it came.
/// Anything else is the error, rather than a guess at what was meant.
fn chat_message(m: &Value) -> Result<Message> {
    let text = |of: &Value| -> Result<Value> {
        let text = of.get("text").and_then(Value::as_str);
        Ok(json!({"type": "text", "text": text.context("`text` is not a string")?}))
    };
    let role = m.get("role").and_then(Value::as_str);
    let shaped = match (role, m.get("text"), m.get("results")) {
        (Some("system"), Some(Value::String(text)), None) => {
            json!({"role": "system", "content": text})
        }
        (Some("user"), Some(_), None) => json!({"role": "user", "content": [text(m)?]}),
        (Some("user"), None, Some(Value::Array(results))) => {
            let content = results
                .iter()
                .map(|r| {
                    // the call's id as the reply gave it, whatever its shape
                    let id = r.get("id").filter(|id| !id.is_null());
                    let (Some(id), Some(name)) = (id, r["name"].as_str()) else {
                        bail!("a result has no `id` or no `name`");
                    };
                    Ok(json!({
                        "type": "toolresult",
                        "call": id,
                        "name": name,
                        "content": [text(r)?],
                        "is_error": r.get("error").and_then(Value::as_bool).unwrap_or(false),
                    }))
                })
                .collect::<Result<Vec<Value>>>()?;
            json!({"role": "user", "content": content})
        }
        (Some("assistant"), None, None) => m.clone(),
        _ => bail!("neither `text`, `results` nor a reply's `message`"),
    };
    serde_json::from_value(shaped).context("not a message the model's client reads")
}

fn attach(name: &str, v: Value, reply: Value) -> Value {
    let mut obj = match v {
        Value::Object(m) => m,
        other => {
            let mut m = Map::new();
            m.insert("value".into(), other);
            m
        }
    };
    obj.insert(name.to_string(), reply);
    Value::Object(obj)
}

/// Each record's answer, by its `i`; by position when none is missing one
/// and the text is in index order (`in_order`; logfmt groups its rows). None
/// for a record the reply has no JSON object for.
fn spread(reply: Value, n: usize, in_order: bool) -> Vec<Option<Value>> {
    let items = reply
        .get("answers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let indexed = !in_order
        || !items.is_empty()
            && items
                .iter()
                .all(|a| a.get("i").and_then(Value::as_u64).is_some());
    let mut slots: Vec<Option<Value>> = vec![None; n];
    for (pos, a) in items.into_iter().enumerate() {
        let k = if indexed {
            a["i"].as_u64().unwrap_or(u64::MAX) as usize
        } else {
            pos
        };
        if k < n && slots[k].is_none() {
            slots[k] = Some(a);
        }
    }
    slots
        .into_iter()
        .map(|slot| match slot {
            Some(Value::Object(mut m)) => {
                m.remove("i");
                Some(Value::Object(m))
            }
            _ => None,
        })
        .collect()
}

/// `{"answers": [...]}`, each answer with its record's index `i`.
fn answers_schema(item: &schemars::Schema) -> schemars::Schema {
    let mut item = serde_json::to_value(item).unwrap_or(Value::Null);
    let defs: Vec<(&str, Value)> = ["$defs", "definitions"]
        .into_iter()
        .filter_map(|k| Some((k, item.as_object_mut()?.remove(k)?)))
        .collect();
    if item.get("properties").is_some() {
        indexed(&mut item);
    }
    if let Some(shapes) = item.get_mut("anyOf").and_then(Value::as_array_mut) {
        for shape in shapes.iter_mut() {
            if shape.get("properties").is_some()
                || shape.get("type").and_then(Value::as_str) == Some("object")
            {
                indexed(shape);
            }
        }
    }
    let mut wrapped = json!({
        "title": "Answers",
        "type": "object",
        "properties": {
            // At least one: a list closed empty is whole JSON with no answer
            // in it. Not the count, which providers refuse (Anthropic's and
            // Bedrock's take 0 or 1 here).
            "answers": {"type": "array", "minItems": 1, "items": item}
        },
        "required": ["answers"],
        "additionalProperties": false
    });
    for (k, d) in defs {
        wrapped[k] = d;
    }
    schemars::Schema::try_from(wrapped).expect("a schema wrapped in an object is a schema")
}

/// `i` first in the shape's properties, and required.
fn indexed(shape: &mut Value) {
    let Some(obj) = shape.as_object_mut() else {
        return;
    };
    let mut props = Map::new();
    props.insert(
        "i".into(),
        json!({"type": "integer", "description": "the record's index"}),
    );
    if let Some(Value::Object(old)) = obj.remove("properties") {
        props.extend(old.into_iter().filter(|(k, _)| k != "i"));
    }
    obj.insert("properties".into(), Value::Object(props));
    let mut required = vec![json!("i")];
    if let Some(Value::Array(old)) = obj.remove("required") {
        required.extend(old.into_iter().filter(|r| r != "i"));
    }
    obj.insert("required".into(), Value::Array(required));
}

fn head(s: &str, n: usize) -> String {
    let mut t: String = s.trim().chars().take(n).collect();
    if t.len() < s.trim().len() {
        t.push('…');
    }
    t
}

/// Dot-path lookup into a JSON value: "a.b.c", "events.0.name".
/// The config's inference nodes by name: one of each for the process, so
/// the model sees at most a node's `concurrency` requests from it, however
/// many workers hand it records and plugins hold conversations with it.
pub type Nodes = Arc<HashMap<Arc<str>, Arc<InferenceNode>>>;

/// The pipeline's inference nodes, each with the model it names: one
/// [`Model`] for each entry under `models`, whichever nodes ask it.
pub fn nodes(
    models: &BTreeMap<Arc<str>, ModelConfig>,
    cfgs: &BTreeMap<Arc<str>, InferenceConfig>,
    config_dir: &Path,
    stop: &Stop,
) -> Result<Nodes> {
    let mut built: HashMap<&Arc<str>, Arc<Model>> = HashMap::default();
    let mut nodes = HashMap::default();
    for (name, cfg) in cfgs {
        let model = match built.get(&cfg.model) {
            Some(model) => Arc::clone(model),
            None => {
                let (model_name, model_cfg) =
                    models.get_key_value(&cfg.model).with_context(|| {
                        format!(
                            "inference node {name}: model names `{}`, which is no entry under `models`",
                            cfg.model
                        )
                    })?;
                let model = Arc::new(
                    Model::new(model_name, model_cfg.clone(), stop.clone())
                        .with_context(|| format!("model {model_name}"))?,
                );
                built.insert(model_name, Arc::clone(&model));
                model
            }
        };
        let node = InferenceNode::new(Arc::clone(name), cfg.clone(), model, config_dir)?;
        nodes.insert(Arc::clone(name), Arc::new(node));
    }
    Ok(Arc::new(nodes))
}

pub fn lookup<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(direct) = v.get(path) {
        return Some(direct);
    }
    let mut cur = v;
    for seg in path.split('.') {
        cur = match (cur, seg.parse::<usize>()) {
            (Value::Array(a), Ok(k)) => a.get(k)?,
            _ => cur.get(seg)?,
        };
    }
    Some(cur)
}

/// A frame may carry several NDJSON lines (a plugin returns one blob per
/// batch); yield each non-empty line.
pub fn lines(payload: &[u8]) -> impl Iterator<Item = &[u8]> {
    payload
        .split(|b| *b == b'\n')
        .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
}

/// An OpenAI-compatible chat server in a few lines, for tests here and in the
/// worker: it answers each record line, flagging one that mentions "bad",
/// answers in prose to a request that mentions "prose", fails the first two
/// requests that mention "flaky" with a 500, cuts off its reply to one with
/// three "loop"s, and records every request body. A request that offers
/// tools gets a call to the first of them, and once a tool's result is among
/// its messages, "done".
#[cfg(test)]
pub(crate) mod stub {
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    pub async fn model() -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let flaky_failures = Arc::new(AtomicUsize::new(0));
        let quiet_turns = Arc::new(AtomicUsize::new(0));
        let empty_replies = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let log = Arc::clone(&log);
                let flaky_failures = Arc::clone(&flaky_failures);
                let quiet_turns = Arc::clone(&quiet_turns);
                let empty_replies = Arc::clone(&empty_replies);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let (body_start, body_len) = loop {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
                            let len = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (pos + 4, len);
                        }
                    };
                    while buf.len() < body_start + body_len {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let body = String::from_utf8_lossy(&buf[body_start..]).into_owned();
                    log.lock().await.push(body.clone());
                    if body.contains("flaky") && flaky_failures.fetch_add(1, Ordering::SeqCst) < 2 {
                        let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                        return;
                    }
                    if body.contains("refused") {
                        let resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                        return;
                    }
                    let verdict = |text: &str| {
                        if text.contains("bad") {
                            json!({"flag": true, "one_line": "bad thing"})
                        } else {
                            json!({"flag": false, "one_line": "fine"})
                        }
                    };
                    let req: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                    if let Some(tool) = req["tools"][0]["function"]["name"].as_str() {
                        let answered = req["messages"]
                            .as_array()
                            .is_some_and(|m| m.iter().any(|m| m["role"] == "tool"));
                        let call = json!({"role": "assistant", "content": null, "tool_calls": [{
                            "id": "call_1", "type": "function",
                            "function": {"name": tool, "arguments": "{\"sql\": \"SELECT 1\"}"}}]});
                        let silence = json!({"role": "assistant", "content": ""});
                        let (message, finish) = if body.contains("cut short") {
                            (call, "length")
                        } else if body.contains("filtered") && req["model"] != "second" {
                            (silence, "content_filter")
                        } else if body.contains("say nothing") {
                            (silence, "stop")
                        } else if body.contains("quiet at first")
                            && quiet_turns.fetch_add(1, Ordering::SeqCst) < 2
                        {
                            (silence, "stop")
                        } else if answered {
                            (json!({"role": "assistant", "content": "done"}), "stop")
                        } else {
                            (call, "tool_calls")
                        };
                        let reply = json!({
                            "choices": [{"message": message, "finish_reason": finish}],
                            "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}
                        })
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            reply.len(),
                            reply
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                        return;
                    }
                    let user = text(&req["messages"][1]["content"]);
                    let content = if body.contains("prose") {
                        "Looks fine to me, nothing to flag.".to_string()
                    } else if body.contains("empty at first")
                        && empty_replies.fetch_add(1, Ordering::SeqCst) < 2
                    {
                        "{\"answers\": []}".to_string()
                    } else if user.matches("loop").count() >= 3 {
                        "{\"answers\": [{\"flag\": false, \"one_line\": \"a7a7a7a7".to_string()
                    } else {
                        // logfmt rows are not in index order: those answers carry `i`
                        let logfmt = user.starts_with("# compacted logfmt");
                        let records: Vec<String> = if logfmt {
                            tangent_compact::decode(&user, None)
                                .map(|rs| rs.iter().map(|r| r.to_string()).collect())
                                .unwrap_or_default()
                        } else {
                            user.lines()
                                .filter(|l| l.starts_with("{\"i\":"))
                                .map(String::from)
                                .collect()
                        };
                        // a `shy` record gets no answer beside others, as a
                        // model that stops early leaves one out
                        let skips = records.len() > 1 && records.iter().any(|r| r.contains("shy"));
                        // and `crowded` ones none at all unless asked alone
                        let mute =
                            records.len() > 1 && records.iter().any(|r| r.contains("crowded"));
                        let answers: Vec<_> = records
                            .iter()
                            .enumerate()
                            .filter(|(_, r)| !(mute || skips && r.contains("shy")))
                            .map(|(k, r)| {
                                let mut a = verdict(r);
                                if logfmt || skips {
                                    a["i"] = json!(k);
                                }
                                a
                            })
                            .collect();
                        json!({"answers": answers}).to_string()
                    };
                    let reply = json!({
                        "choices": [{"message": {"content": content}, "finish_reason": "stop"}]
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        reply.len(),
                        reply
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (url, seen)
    }

    /// A model that never answers: its url, and how many requests it took.
    pub async fn silent() -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let taken = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&taken);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut tmp = [0u8; 4096];
                    while sock.read(&mut tmp).await.unwrap_or(0) > 0 {}
                });
            }
        });
        (url, taken)
    }

    /// A message's text: a string, or a list of text parts.
    pub fn text(content: &serde_json::Value) -> String {
        match content {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(parts) => parts
                .iter()
                .filter_map(|p| p["text"].as_str())
                .collect::<Vec<_>>()
                .join(""),
            _ => String::new(),
        }
    }

    /// A node and the model it asks, as a test sets them.
    #[derive(Clone)]
    pub struct Asked {
        pub model: tangent_shared::models::ModelConfig,
        pub node: tangent_shared::inference::InferenceConfig,
    }

    impl Asked {
        /// The node, named `name`, with a model of its own.
        pub fn node(
            self,
            name: &str,
            dir: &std::path::Path,
        ) -> anyhow::Result<super::InferenceNode> {
            let model = super::Model::new(&self.node.model, self.model, Default::default())?;
            super::InferenceNode::new(name.into(), self.node, model.into(), dir)
        }

        /// The pipeline's nodes with this one alone in it, named `name`.
        pub fn nodes(self, name: &str, dir: &std::path::Path) -> anyhow::Result<super::Nodes> {
            self.nodes_until(name, dir, &Default::default())
        }

        /// The same, in a run that `stop` stops.
        pub fn nodes_until(
            self,
            name: &str,
            dir: &std::path::Path,
            stop: &crate::stop::Stop,
        ) -> anyhow::Result<super::Nodes> {
            super::nodes(
                &[(self.node.model.clone(), self.model)].into(),
                &[(name.into(), self.node)].into(),
                dir,
                stop,
            )
        }
    }

    /// A node against a model at `url`, with the prompt (and a schema, when
    /// given) written under a fresh directory the caller removes.
    pub fn config(url: &str) -> Asked {
        let mut extra = serde_json::Map::new();
        extra.insert(
            "chat_template_kwargs".into(),
            json!({"enable_thinking": false}),
        );
        Asked {
            model: tangent_shared::models::ModelConfig {
                kind: tangent_shared::models::ModelKind::Openai,
                url: Some(url.to_string()),
                api_key: None,
                model: "stub".into(),
                aws: Default::default(),
                concurrency: 2,
                timeout_ms: 5_000,
                retries: 0,
                fallback: None,
                serve: None,
            },
            node: tangent_shared::inference::InferenceConfig {
                inputs: Vec::new(),
                model: "stub".into(),
                prompt_file: "judge.md".into(),
                schema_file: None,
                fields: Vec::new(),
                batch_bytes: 32_768,
                encoding: Default::default(),
                group_by: Vec::new(),
                max_tokens: 50,
                temperature: None,
                extra,
                unreached: Default::default(),
                cache: false,
            },
        }
    }

    pub fn dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tangent-inference-{tag}-{}-{}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "-")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("judge.md"),
            "You are a test judge. Reply in JSON.\n",
        )
        .unwrap();
        dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// One request to a stand-in for Anthropic's Messages API: answers it
    /// with a flag on record 0, and gives back the request as it came, head
    /// and body.
    async fn messages_api() -> (String, tokio::task::JoinHandle<(String, Value)>) {
        one_request(json!({
            "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
            "content": [{"type": "text", "text": FLAGGED}],
            "stop_reason": "end_turn", "stop_sequence": null,
            "usage": {"input_tokens": 7, "output_tokens": 3}
        }))
        .await
    }

    /// The same for OpenAI's Responses API.
    async fn responses_api() -> (String, tokio::task::JoinHandle<(String, Value)>) {
        one_request(json!({
            "id": "resp_1", "object": "response", "created_at": 0, "status": "completed",
            "model": "gpt-6-luna",
            "output": [{"type": "message", "id": "msg_1", "status": "completed", "role": "assistant",
                "content": [{"type": "output_text", "text": FLAGGED, "annotations": []}]}],
            "usage": {"input_tokens": 7, "output_tokens": 3, "total_tokens": 10}
        }))
        .await
    }

    /// A reply's text: a flag on record 0.
    const FLAGGED: &str =
        "{\"answers\": [{\"i\": 0, \"flag\": true, \"one_line\": \"bad thing\"}]}";

    /// A server for one request: answers it with `reply`, and gives back
    /// the request as it came, head and body.
    async fn one_request(reply: Value) -> (String, tokio::task::JoinHandle<(String, Value)>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let served = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut buf, mut tmp) = (Vec::new(), [0u8; 4096]);
            let (head, body) = loop {
                let n = sock.read(&mut tmp).await.unwrap();
                assert!(n > 0, "the request ended early");
                buf.extend_from_slice(&tmp[..n]);
                let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map_or(0, |v| v.trim().parse().unwrap());
                if buf.len() >= end + 4 + len {
                    break (head, serde_json::from_slice(&buf[end + 4..]).unwrap());
                }
            };
            let reply = reply.to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            let _ = sock.shutdown().await;
            (head, body)
        });
        (url, served)
    }

    /// `type: anthropic` asks Anthropic's Messages API: the key as
    /// `x-api-key`, the prompt as `system`, `extra` in the body, and the
    /// schema as the format the reply must take. The reply's text is read as
    /// any other type's.
    #[tokio::test]
    async fn an_anthropic_model_is_asked_through_the_messages_api() {
        let (url, served) = messages_api().await;
        let dir = stub::dir("anthropic");
        std::fs::write(
            dir.join("verdict.json"),
            r#"{"type": "object", "properties": {"flag": {"type": "boolean"}, "one_line": {"type": "string"}},
                "required": ["flag", "one_line"], "additionalProperties": false}"#,
        )
        .unwrap();
        let mut cfg = stub::config(&url);
        cfg.model.kind = ModelKind::Anthropic;
        cfg.model.api_key = Some("sk-test".to_string().into());
        cfg.model.model = "claude-haiku-5-5".into();
        cfg.node.schema_file = Some("verdict.json".into());
        cfg.node.extra = serde_json::from_value(json!({"thinking": {"type": "disabled"}})).unwrap();
        let node = cfg.node("judge", &dir).unwrap();
        let outs = node
            .annotate_all(vec![json!({"id": 1, "msg": "bad login"})])
            .await;
        assert_eq!(
            outs[0]["judge"],
            json!({"flag": true, "one_line": "bad thing"}),
            "{outs:?}"
        );

        let (head, body) = served.await.unwrap();
        assert!(head.starts_with("post /v1/messages "), "{head}");
        assert!(head.contains("x-api-key: sk-test"), "{head}");
        assert_eq!(body["model"], "claude-haiku-5-5");
        assert_eq!(body["max_tokens"], 50);
        assert_eq!(body["thinking"], json!({"type": "disabled"}));
        assert!(
            body["system"].to_string().contains("You are a test judge."),
            "{body}"
        );
        assert!(
            body["messages"][0].to_string().contains("bad login"),
            "{body}"
        );
        assert_eq!(
            body["output_config"]["format"]["schema"]["properties"]["answers"]["type"], "array",
            "{body}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `type: responses` asks OpenAI's Responses API: the key as a
    /// bearer token, the prompt as `instructions`, `extra` in the body, and
    /// the schema as the format the reply's text must take.
    #[tokio::test]
    async fn a_responses_model_is_asked_through_the_responses_api() {
        let (url, served) = responses_api().await;
        let dir = stub::dir("responses");
        std::fs::write(
            dir.join("verdict.json"),
            r#"{"type": "object", "properties": {"flag": {"type": "boolean"}, "one_line": {"type": "string"}},
                "required": ["flag", "one_line"], "additionalProperties": false}"#,
        )
        .unwrap();
        let mut cfg = stub::config(&url);
        cfg.model.kind = ModelKind::Responses;
        cfg.model.api_key = Some("sk-test".to_string().into());
        cfg.model.model = "gpt-6-luna".into();
        cfg.node.schema_file = Some("verdict.json".into());
        cfg.node.extra = serde_json::from_value(json!({"reasoning": {"effort": "low"}})).unwrap();
        let node = cfg.node("judge", &dir).unwrap();
        let outs = node
            .annotate_all(vec![json!({"id": 1, "msg": "bad login"})])
            .await;
        assert_eq!(
            outs[0]["judge"],
            json!({"flag": true, "one_line": "bad thing"}),
            "{outs:?}"
        );

        let (head, body) = served.await.unwrap();
        assert!(head.starts_with("post /responses "), "{head}");
        assert!(head.contains("authorization: bearer sk-test"), "{head}");
        assert_eq!(body["model"], "gpt-6-luna");
        assert_eq!(body["max_output_tokens"], 50);
        assert_eq!(body["reasoning"], json!({"effort": "low"}));
        assert!(body.to_string().contains("You are a test judge."), "{body}");
        assert!(body["input"].to_string().contains("bad login"), "{body}");
        assert_eq!(
            body["text"]["format"]["schema"]["properties"]["answers"]["type"], "array",
            "{body}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// An `anthropic` or `responses` model with no key, or one from a
    /// variable that is not set, is refused when the pipeline is built,
    /// naming what it needs.
    #[test]
    fn a_type_that_needs_a_key_says_so() {
        let dir = stub::dir("needs-key");
        for (kind, var) in [
            (ModelKind::Anthropic, "ANTHROPIC_API_KEY"),
            (ModelKind::Responses, "OPENAI_API_KEY"),
        ] {
            for key in [None, Some(String::new())] {
                let mut cfg = stub::config("http://127.0.0.1:9");
                cfg.model.kind = kind;
                cfg.model.api_key = key.map(Into::into);
                let err = cfg.node("judge", &dir).err().unwrap();
                assert!(format!("{err:#}").contains(var), "{err:#}");
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// An `openai` model whose key comes from a variable that is not set is
    /// refused when the pipeline is built; one with no `api_key` at all is a
    /// local server's, and is built.
    #[test]
    fn an_openai_model_refuses_an_empty_key() {
        let dir = stub::dir("openai-key");
        let mut cfg = stub::config("http://127.0.0.1:9");
        for key in ["", "  "] {
            cfg.model.api_key = Some(key.to_string().into());
            let err = cfg.clone().node("judge", &dir).err().unwrap();
            assert!(format!("{err:#}").contains("`api_key` is empty"), "{err:#}");
        }
        cfg.model.api_key = None;
        cfg.node("judge", &dir).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn annotates_every_record_with_the_verdict() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("verdict");
        let node = stub::config(&url).node("judge", &dir).unwrap();
        let outs = node
            .annotate_all(vec![
                json!({"id": 1, "msg": "all good"}),
                json!({"id": 2, "msg": "bad login"}),
                json!({"id": 3, "msg": "also fine"}),
            ])
            .await;
        // Every record comes back, in order, with the verdict under the node's name.
        assert_eq!(outs.len(), 3);
        assert_eq!(
            outs.iter()
                .map(|o| o["id"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(outs[1]["judge"]["flag"], true);
        assert_eq!(outs[1]["judge"]["one_line"], "bad thing");
        assert!(outs[1]["judge"].get("i").is_none());
        assert_eq!(outs[0]["judge"]["flag"], false);
        assert_eq!(outs[2]["judge"]["flag"], false);

        let seen = seen.lock().await;
        assert_eq!(seen.len(), 1, "the records handed over are one request");
        let req: Value = serde_json::from_str(&seen[0]).unwrap();
        assert_eq!(req["model"], "stub");
        assert_eq!(req["messages"][0]["role"], "system");
        let system = stub::text(&req["messages"][0]["content"]);
        assert!(system.starts_with("You are a test judge."), "{system}");
        assert!(system.contains("3 in all"), "{system}");
        assert_eq!(req["messages"][1]["role"], "user");
        let lines = user_lines(&seen[0]);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["i"], 0);
        assert_eq!(lines[1]["i"], 1);
        assert_eq!(lines[1]["id"], 2);
        assert_eq!(
            req["chat_template_kwargs"]["enable_thinking"], false,
            "extra is merged"
        );
        assert_eq!(req["max_tokens"], 150, "max_tokens is per record");
        assert_eq!(
            req["response_format"]["type"], "json_object",
            "JSON mode without a schema"
        );
        assert!(
            req.get("temperature").is_none(),
            "temperature is sent only when set: {req}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A plugin's conversation (`model.chat`): the model calls a tool, the
    /// plugin sends the reply's message back with the call's result, and the
    /// model answers.
    #[test]
    fn a_refused_cache_checkpoint_is_told_from_other_errors() {
        assert!(refuses_the_cache(
            "ProviderResponseError: status 400 Bad Request: ValidationException: cachePoint is not allowed after reasoningContent"
        ));
        assert!(refuses_the_cache(
            "HTTP 400: invalid_request_error: cache_control cannot be set here"
        ));
        assert!(!refuses_the_cache(
            "status 403 Forbidden: Model access is denied"
        ));
        assert!(!refuses_the_cache("status 429: too many requests"));
    }

    #[tokio::test]
    async fn a_conversation_calls_a_tool_and_takes_its_result() {
        let (url, seen) = stub::model().await;
        let node = stub::config(&url)
            .node("reviewer", &stub::dir("chat"))
            .unwrap();
        let tools = json!([{"name": "query", "description": "Run SQL.",
            "parameters": {"type": "object", "properties": {"sql": {"type": "string"}}}}]);
        let asked = json!({"role": "user", "text": "count the rows"});
        let first = node
            .chat(&json!({"messages": [asked], "tools": tools}).to_string())
            .await
            .unwrap();
        let first: Value = serde_json::from_str(&first).unwrap();
        assert_eq!(first["stop"], "tool_use", "{first}");
        assert_eq!(first["calls"][0]["name"], "query");
        assert_eq!(first["calls"][0]["arguments"]["sql"], "SELECT 1");
        assert_eq!(first["usage"]["input_tokens"], 7);

        let results = json!({"role": "user", "results": [
            {"id": first["calls"][0]["id"], "name": "query", "text": "| n |\n| 3 |"}]});
        let second = node
            .chat(
                &json!({"messages": [asked, first["message"], results], "tools": tools})
                    .to_string(),
            )
            .await
            .unwrap();
        let second: Value = serde_json::from_str(&second).unwrap();
        assert_eq!(second["text"], "done");
        assert_eq!(second["stop"], "stop");
        assert_eq!(second["calls"], json!([]));
        // no reasoning shown is none told
        assert_eq!(second["thinking"], "");

        // what the model was sent: the prompt as the system message, the
        // call it made, and the result under the call's id
        let bodies = seen.lock().await;
        let sent: Value = serde_json::from_str(bodies.last().unwrap()).unwrap();
        let messages = sent["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[2]["tool_calls"][0]["id"], "call_1");
        let result = messages.iter().find(|m| m["role"] == "tool").unwrap();
        assert_eq!(result["tool_call_id"], "call_1");
        assert!(stub::text(&result["content"]).contains("| 3 |"), "{result}");
        drop(bodies);

        // a traced turn is the same turn, and the trace is not the model's
        let traced = node
            .chat(&json!({"messages": [asked], "tools": tools, "trace": "501|w"}).to_string())
            .await
            .unwrap();
        let traced: Value = serde_json::from_str(&traced).unwrap();
        assert_eq!(traced["calls"][0]["name"], "query");
        assert!(!seen.lock().await.last().unwrap().contains("501|w"));
    }

    /// Bedrock's `"type": "tool_use"` on a call, which the client keeps as
    /// an item it does not understand, is read as the call.
    #[test]
    fn a_typed_tool_use_is_a_tool_call() {
        let kept: AssistantContent = serde_json::from_value(json!({
            "type": "opaque", "replay": true,
            "item": {"toolUse": {"type": "tool_use", "toolUseId": "tooluse_1", "name": "query",
                                 "input": {"sql": "SELECT 1"}}},
        }))
        .unwrap();
        let AssistantContent::ToolCall(call) = tool_call(&kept).unwrap() else {
            panic!("not a call");
        };
        assert_eq!(call.function.name, "query");
        assert_eq!(call.function.arguments["sql"], "SELECT 1");
        assert_eq!(call.id.wire(), "tooluse_1");
        // a hosted tool's use, and any other block, stay as they are
        let hosted: AssistantContent = serde_json::from_value(json!({
            "type": "opaque", "replay": true,
            "item": {"toolUse": {"type": "server_tool_use", "toolUseId": "srv_1", "name": "web_search", "input": {}}},
        }))
        .unwrap();
        assert!(tool_call(&hosted).is_none());
        let text: AssistantContent =
            serde_json::from_value(json!({"type": "text", "text": "hello"})).unwrap();
        assert!(tool_call(&text).is_none());
    }

    fn reviewer(url: &str, tag: &str) -> InferenceNode {
        stub::config(url).node("reviewer", &stub::dir(tag)).unwrap()
    }

    #[tokio::test]
    async fn a_request_that_is_not_a_conversation_is_an_error() {
        let (url, seen) = stub::model().await;
        let node = reviewer(&url, "chat-bad");
        for (request, says) in [
            ("not json", "not JSON"),
            ("{}", "no `messages`"),
            (r#"{"messages": []}"#, "empty"),
            (r#"{"messages": [{"role": "user"}]}"#, "neither `text`"),
            (
                r#"{"messages": [{"role": "user", "text": 7}]}"#,
                "not a string",
            ),
            (
                r#"{"messages": [{"role": "user", "text": "a", "results": []}]}"#,
                "neither `text`",
            ),
            (
                r#"{"messages": [{"role": "user", "results": [{"id": "c", "name": "query"}]}]}"#,
                "not a string",
            ),
            (
                r#"{"messages": [{"role": "user", "results": [{"name": "query", "text": "a"}]}]}"#,
                "no `id`",
            ),
            (
                r#"{"messages": [{"role": "system", "text": "a"}]}"#,
                "not the user's",
            ),
            (
                r#"{"messages": [{"role": "user", "text": "a"}, {"role": "system", "text": "b"}, {"role": "user", "text": "c"}]}"#,
                "ahead of the others",
            ),
        ] {
            let e = node.chat(request).await.unwrap_err();
            assert!(format!("{e:#}").contains(says), "{request}: {e:#}");
        }
        assert!(seen.lock().await.is_empty(), "none of them was sent");
    }

    /// A turn the model did not finish is the call's error, whatever came
    /// with it: a call `max_tokens` cut, a refusal, a reply with nothing in it.
    #[tokio::test]
    async fn a_turn_the_model_did_not_finish_is_an_error() {
        let (url, _) = stub::model().await;
        let node = reviewer(&url, "chat-unfinished");
        let tools = json!([{"name": "query", "description": "Run SQL.",
            "parameters": {"type": "object", "properties": {"sql": {"type": "string"}}}}]);
        for (asked, says) in [
            ("cut short", "cut the turn with a tool call in it"),
            ("filtered", "failed the turn"),
            ("say nothing", "no text and no call"),
        ] {
            let request =
                json!({"messages": [{"role": "user", "text": asked}], "tools": tools}).to_string();
            let e = node.chat(&request).await.unwrap_err();
            assert!(format!("{e:#}").contains(says), "{asked}: {e:#}");
        }
    }

    /// A turn the model declines is asked of its `fallback`, once, and that
    /// model's turn is the turn: its call, or a decline of its own, which is
    /// the error it is with no fallback.
    #[tokio::test]
    async fn a_turn_the_model_declines_is_asked_of_its_fallback() {
        let tools = json!([{"name": "query", "description": "Run SQL.",
            "parameters": {"type": "object", "properties": {"sql": {"type": "string"}}}}]);
        let request = |asked: &str| {
            json!({"messages": [{"role": "user", "text": asked}], "tools": tools}).to_string()
        };
        for (fallback, tag) in [
            ("second", "chat-fallback"),
            ("third", "chat-fallback-declines"),
        ] {
            let (url, seen) = stub::model().await;
            let mut cfg = stub::config(&url);
            cfg.model.fallback = Some(fallback.into());
            let node = cfg.node("reviewer", &stub::dir(tag)).unwrap();
            let turn = node.chat(&request("filtered")).await;
            let asked: Vec<Value> = seen
                .lock()
                .await
                .drain(..)
                .map(|body| serde_json::from_str::<Value>(&body).unwrap()["model"].take())
                .collect();
            assert_eq!(asked, [json!("stub"), json!(fallback)]);
            if fallback == "second" {
                let reply: Value = serde_json::from_str(&turn.unwrap()).unwrap();
                assert_eq!(reply["calls"][0]["name"], "query", "{reply}");
            } else {
                let e = turn.unwrap_err();
                assert!(format!("{e:#}").contains("failed the turn"), "{e:#}");
            }
            // one it does not decline is the model's own
            node.chat(&request("look")).await.unwrap();
            assert_eq!(seen.lock().await.len(), 1);
        }
    }

    /// A turn with nothing in it is asked for again, `retries` times: the
    /// model that says nothing twice and then calls a tool has made its call,
    /// and the one that never says anything is the error after the last try.
    #[tokio::test]
    async fn a_turn_with_nothing_in_it_is_asked_for_again() {
        let (url, seen) = stub::model().await;
        let mut cfg = stub::config(&url);
        cfg.model.retries = 2;
        let node = cfg.node("reviewer", &stub::dir("chat-quiet")).unwrap();
        let tools = json!([{"name": "query", "description": "Run SQL.",
            "parameters": {"type": "object", "properties": {"sql": {"type": "string"}}}}]);
        let request = |asked: &str| {
            json!({"messages": [{"role": "user", "text": asked}], "tools": tools}).to_string()
        };
        let reply: Value =
            serde_json::from_str(&node.chat(&request("quiet at first")).await.unwrap()).unwrap();
        assert_eq!(reply["calls"][0]["name"], "query", "{reply}");
        assert_eq!(seen.lock().await.len(), 3, "silent twice, then the call");
        let e = node.chat(&request("say nothing")).await.unwrap_err();
        assert!(format!("{e:#}").contains("no text and no call"), "{e:#}");
        assert_eq!(seen.lock().await.len(), 6, "three tries, each silent");
    }

    #[tokio::test]
    async fn a_request_the_model_refuses_is_not_sent_again() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("refused");
        let mut cfg = stub::config(&url);
        cfg.model.retries = 2;
        let node = cfg.node("judge", &dir).unwrap();
        let out = node
            .annotate_all(vec![json!({"id": 1, "msg": "refused"})])
            .await;
        assert!(out[0]["judge"]["error"].is_string(), "{out:?}");
        assert_eq!(seen.lock().await.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn logfmt_records_reach_the_model_and_read_back() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("logfmt");
        let mut cfg = stub::config(&url);
        cfg.node.encoding = serde_yaml::from_str("{type: logfmt, budget_tokens: 60}").unwrap();
        let node = cfg.node("judge", &dir).unwrap();
        let records: Vec<Value> = (0..6)
            .map(|k| json!({"source": "app", "user": "ann", "n": k, "msg": if k == 4 { "bad login" } else { "fine" }}))
            .collect();
        let outs = node.annotate_all(records.clone()).await;
        let flags: Vec<bool> = outs
            .iter()
            .map(|o| o["judge"]["flag"].as_bool().unwrap())
            .collect();
        assert_eq!(flags, [false, false, false, false, true, false]);

        // past the budget the group is split between records; together the parts are the records
        let seen = seen.lock().await;
        assert!(seen.len() > 1, "{} requests", seen.len());
        let users: Vec<String> = seen
            .iter()
            .map(|b| {
                stub::text(&serde_json::from_str::<Value>(b).unwrap()["messages"][1]["content"])
            })
            .collect();
        let back = compact::decode_all(users.iter().map(|u| (u.as_str(), None))).unwrap();
        assert_eq!(back, records);
        let system =
            stub::text(&serde_json::from_str::<Value>(&seen[0]).unwrap()["messages"][0]["content"]);
        assert!(system.contains("compacted logfmt"), "{system}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_reply_that_is_not_json_is_the_error() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("prose");
        let node = stub::config(&url).node("judge", &dir).unwrap();
        let out = node
            .annotate_all(vec![json!({"id": 7, "msg": "prose please"})])
            .await;
        assert_eq!(out[0]["id"], 7);
        let err = out[0]["judge"]["error"].as_str().unwrap();
        assert!(
            err.contains("not JSON") && err.contains("Looks fine"),
            "{err}"
        );
        assert_eq!(seen.lock().await.len(), 1, "no `retries`: one request");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// One record's reply with nothing in it for the record is asked for
    /// again, `retries` times, as a request that got no reply is.
    #[tokio::test]
    async fn a_reply_with_no_answer_for_its_one_record_is_asked_again() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("empty-reply");
        let mut cfg = stub::config(&url);
        cfg.model.retries = 2;
        let node = cfg.node("judge", &dir).unwrap();
        // Two empty lists, then the verdict.
        let out = node
            .annotate_all(vec![json!({"id": 3, "msg": "empty at first, bad"})])
            .await;
        assert_eq!(out[0]["judge"]["flag"], true, "{out:?}");
        assert_eq!(seen.lock().await.len(), 3);
        // A reply that is never JSON: three tries, then the error.
        let out = node
            .annotate_all(vec![json!({"id": 7, "msg": "prose please"})])
            .await;
        let err = out[0]["judge"]["error"].as_str().unwrap();
        assert!(err.contains("not JSON"), "{err}");
        assert_eq!(seen.lock().await.len(), 6);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A reply that answers none of several records is asked again in
    /// halves, as one that is not JSON is.
    #[tokio::test]
    async fn a_reply_that_answers_no_record_is_asked_in_halves() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("no-answers");
        let node = stub::config(&url).node("judge", &dir).unwrap();
        let outs = node
            .annotate_all(vec![
                json!({"id": 1, "msg": "crowded and bad"}),
                json!({"id": 2, "msg": "fine"}),
            ])
            .await;
        let flags: Vec<&Value> = outs.iter().map(|o| &o["judge"]["flag"]).collect();
        assert_eq!(flags, [&json!(true), &json!(false)], "{outs:?}");
        assert_eq!(seen.lock().await.len(), 3, "the two, then each alone");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A model that is not reached: its records go on with the error, or
    /// with `unreached: hold`, in a run that keeps them, are held unsent to
    /// be asked again.
    #[tokio::test]
    async fn records_whose_model_was_not_reached_are_held_when_asked() {
        // nothing listens here
        let url = "http://127.0.0.1:9/v1";
        let dir = stub::dir("unreached");
        let passes = stub::config(url).node("judge", &dir).unwrap();
        let out = passes.annotate_unsent(vec![json!({"id": 1})]).await;
        let said = out[0].as_ref().expect("it goes on");
        assert!(said["judge"]["error"].is_string(), "{said}");
        assert!(passes.down());

        let mut asked = stub::config(url);
        asked.node.unreached = tangent_shared::inference::Unreached::Hold;
        let holds = asked.node("judge", &dir).unwrap();
        // a replay keeps nothing, and holds nothing
        let out = holds.annotate_unsent(vec![json!({"id": 1})]).await;
        assert!(out[0].is_some(), "nowhere to keep it: {out:?}");
        holds.keep(true);
        let out = holds
            .annotate_unsent(vec![json!({"id": 1}), json!({"id": 2})])
            .await;
        assert_eq!(
            out,
            [None, None],
            "held, with no error in the answer's place"
        );
        // down, it takes back one request in a while, and not the rest
        let every = std::time::Duration::from_secs(60);
        assert!(holds.down());
        assert!(holds.takes_again(every), "the one that tries it");
        assert!(!holds.takes_again(every), "the rest wait behind it");
        assert!(
            holds.takes_again(std::time::Duration::ZERO),
            "and once the while is over"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_refusal_of_the_key_is_told_from_one_of_the_request() {
        for refused in [
            "ProviderResponseError: status 403 Forbidden: Model access is denied due to INVALID_PAYMENT_INSTRUMENT",
            "HTTP 401 Unauthorized: invalid x-api-key",
            "HttpError: Http client error: An unexpected error occurred. Verify Internet connection or AWS keys",
            "ExpiredTokenException: the SSO token has expired",
        ] {
            assert!(model::refuses_the_key(refused), "{refused}");
        }
        for other in [
            "status 400 Bad Request: prompt is too long",
            "reply is not JSON: Sure, here is",
        ] {
            assert!(!model::refuses_the_key(other), "{other}");
        }
    }

    #[tokio::test]
    async fn a_request_that_got_no_reply_is_retried() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("flaky");
        let mut cfg = stub::config(&url);
        cfg.model.retries = 2;
        let node = cfg.node("judge", &dir).unwrap();
        // Two 500s, then the verdict: three requests, one answer.
        let out = node
            .annotate_all(vec![json!({"id": 3, "msg": "flaky bad link"})])
            .await;
        assert_eq!(out[0]["judge"]["flag"], true, "{out:?}");
        assert_eq!(seen.lock().await.len(), 3);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn an_unreachable_model_leaves_an_error_on_the_record() {
        // Nothing listens on port 1. The record still goes on, with the error
        // where the verdict would be, so nothing is lost silently.
        let dir = stub::dir("dead");
        let node = stub::config("http://127.0.0.1:1/v1")
            .node("judge", &dir)
            .unwrap();
        let out = node.annotate_all(vec![json!({"id": 9})]).await;
        assert_eq!(out[0]["id"], 9);
        assert!(
            !out[0]["judge"]["error"].as_str().unwrap().is_empty(),
            "{out:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    fn user_lines(body: &str) -> Vec<Value> {
        let req: Value = serde_json::from_str(body).unwrap();
        stub::text(&req["messages"][1]["content"])
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn unreadable_reply_is_asked_in_halves() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("halves");
        let node = stub::config(&url).node("judge", &dir).unwrap();
        let outs = node
            .annotate_all(
                (1..=4)
                    .map(|i| json!({"id": i, "msg": format!("loop {i} bad")}))
                    .collect(),
            )
            .await;
        assert!(outs.iter().all(|o| o["judge"]["flag"] == true), "{outs:?}");
        assert_eq!(seen.lock().await.len(), 3, "the whole, then two halves");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A reply that answers some records and skips one is whole JSON, so no
    /// retry saw it: the skipped record is asked about again, alone.
    #[tokio::test]
    async fn a_record_the_reply_skipped_is_asked_again() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("skipped");
        let node = stub::config(&url).node("judge", &dir).unwrap();
        let outs = node
            .annotate_all(vec![
                json!({"id": 1, "msg": "fine"}),
                json!({"id": 2, "msg": "shy and bad"}),
                json!({"id": 3, "msg": "bad"}),
            ])
            .await;
        let flags: Vec<&Value> = outs.iter().map(|o| &o["judge"]["flag"]).collect();
        assert_eq!(
            flags,
            [&json!(false), &json!(true), &json!(true)],
            "{outs:?}"
        );
        assert!(
            outs.iter().all(|o| o["judge"].get("error").is_none()),
            "{outs:?}"
        );
        let seen = seen.lock().await;
        assert_eq!(seen.len(), 2, "the three, then the one it skipped");
        assert_eq!(user_lines(&seen[1]).len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Two workers' copies of a node with `concurrency: 1` send one request
    /// at a time between them, not one each.
    #[tokio::test]
    async fn a_node_s_callers_share_its_concurrency() {
        let (url, taken) = stub::silent().await;
        let dir = stub::dir("shared-permits");
        let mut cfg = stub::config(&url);
        cfg.model.concurrency = 1;
        let nodes = cfg.nodes("judge", &dir).unwrap();
        let calls: Vec<_> = (0..2)
            .map(|_| {
                let node = Arc::clone(&nodes["judge"]);
                tokio::spawn(async move { node.annotate_all(vec![json!({"id": 1})]).await })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            taken.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one request between the two callers"
        );
        for c in calls {
            c.abort();
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Two nodes that name one model with `concurrency: 1` send one request
    /// at a time between them: the limit is the model's, whoever asks.
    #[tokio::test]
    async fn nodes_that_name_one_model_share_its_concurrency() {
        let (url, taken) = stub::silent().await;
        let dir = stub::dir("shared-model");
        let mut cfg = stub::config(&url);
        cfg.model.concurrency = 1;
        let nodes = nodes(
            &[(cfg.node.model.clone(), cfg.model)].into(),
            &[
                ("judge".into(), cfg.node.clone()),
                ("reviewer".into(), cfg.node),
            ]
            .into(),
            &dir,
            &Stop::default(),
        )
        .unwrap();
        let calls = ["judge", "reviewer"].map(|name| {
            let node = Arc::clone(&nodes[name]);
            tokio::spawn(async move { node.annotate_all(vec![json!({"id": 1})]).await })
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            taken.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one request between the two nodes"
        );
        for c in calls {
            c.abort();
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A conversation's turn takes the model's next free place ahead of the
    /// records already waiting for one: an alert being reviewed is not kept
    /// waiting by what is still to be judged.
    #[tokio::test]
    async fn a_turn_goes_ahead_of_the_records_that_wait() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("turn-first");
        let mut cfg = stub::config(&url);
        cfg.model.concurrency = 1;
        cfg.node.group_by = vec!["who".into()];
        let nodes = nodes(
            &[(cfg.node.model.clone(), cfg.model)].into(),
            &[
                ("judge".into(), cfg.node.clone()),
                ("reviewer".into(), cfg.node),
            ]
            .into(),
            &dir,
            &Stop::default(),
        )
        .unwrap();
        let held = nodes["judge"].model.place().await;
        let judge = Arc::clone(&nodes["judge"]);
        let records = tokio::spawn(async move {
            // three actors' records, a request each, all in line
            let records = ["a", "b", "c"].map(|who| json!({"who": who})).to_vec();
            judge.annotate_all(records).await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let reviewer = Arc::clone(&nodes["reviewer"]);
        let turn = tokio::spawn(async move {
            let asked = json!({"messages": [{"role": "user", "text": "is the alert right"}]});
            reviewer.chat(&asked.to_string()).await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(held);
        turn.await.unwrap().unwrap();
        assert_eq!(records.await.unwrap().len(), 3);
        let seen = seen.lock().await;
        assert_eq!(seen.len(), 4);
        assert!(
            seen[0].contains("is the alert right"),
            "the turn came last and was sent first: {}",
            seen[0]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A caller that stopped waiting for a place leaves it to the next in
    /// line.
    #[tokio::test]
    async fn a_place_passes_over_whoever_stopped_waiting() {
        let dir = stub::dir("gave-up");
        let mut cfg = stub::config("http://127.0.0.1:1/v1");
        cfg.model.concurrency = 1;
        let model = Arc::clone(&cfg.node("judge", &dir).unwrap().model);
        let held = model.place().await;
        let gone = {
            let model = Arc::clone(&model);
            tokio::spawn(async move { drop(model.turn().await) })
        };
        let waits = {
            let model = Arc::clone(&model);
            tokio::spawn(async move { drop(model.place().await) })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        gone.abort();
        let _ = gone.await;
        drop(held);
        tokio::time::timeout(Duration::from_secs(2), waits)
            .await
            .expect("the place came to the one still waiting")
            .unwrap();
        // and is free again after it
        tokio::time::timeout(Duration::from_secs(2), model.place())
            .await
            .expect("the place is free");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn group_by_keeps_requests_apart() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("group-by");
        let mut cfg = stub::config(&url);
        cfg.node.group_by = vec!["who.actor".into()];
        let node = cfg.node("judge", &dir).unwrap();
        let outs = node
            .annotate_all(vec![
                json!({"id": 1, "who": {"actor": "a"}}),
                json!({"id": 2, "who": {"actor": "b"}}),
                json!({"id": 3, "who": {"actor": "a"}, "msg": "bad"}),
                json!({"id": 4}),
                json!({"id": 5, "who": {"actor": "b"}}),
            ])
            .await;
        let ids: Vec<i64> = outs.iter().map(|o| o["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, [1, 2, 3, 4, 5]);
        assert_eq!(outs[2]["judge"]["flag"], true);
        assert_eq!(outs[0]["judge"]["flag"], false);

        let seen = seen.lock().await;
        assert_eq!(seen.len(), 3, "a, b, and none");
        for body in seen.iter() {
            let actors: std::collections::BTreeSet<String> = user_lines(body)
                .iter()
                .map(|l| l["who"]["actor"].to_string())
                .collect();
            assert_eq!(actors.len(), 1, "{body}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn spread_leaves_none_where_the_reply_has_no_answer() {
        let out = spread(
            json!({"answers": [{"i": 1, "flag": true}, {"i": 0, "flag": false}]}),
            3,
            true,
        );
        assert_eq!(
            out,
            [
                Some(json!({"flag": false})),
                Some(json!({"flag": true})),
                None
            ]
        );
        // an answer that is no object is none
        let out = spread(json!({"answers": ["x", {"flag": true}]}), 2, true);
        assert_eq!(out, [None, Some(json!({"flag": true}))]);
        assert_eq!(spread(json!({"verdict": true}), 1, true), [None]);
        // logfmt's rows are not in index order: an answer without `i` lands nowhere
        let out = spread(
            json!({"answers": [{"flag": true}, {"flag": false}]}),
            2,
            false,
        );
        assert_eq!(out, [None, None]);
    }

    #[tokio::test]
    async fn schema_wraps_each_answer() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("schema");
        std::fs::write(
            dir.join("verdict.json"),
            r#"{"title": "Verdict", "type": "object", "properties": {"flag": {"type": "boolean"}}, "required": ["flag"], "additionalProperties": false}"#,
        )
        .unwrap();
        let mut cfg = stub::config(&url);
        cfg.node.schema_file = Some("verdict.json".into());
        cfg.node.temperature = Some(0.0);
        let node = cfg.node("judge", &dir).unwrap();
        let outs = node
            .annotate_all(vec![json!({"id": 1, "msg": "bad"}), json!({"id": 2})])
            .await;
        assert_eq!(outs[0]["judge"]["flag"], true);
        let seen = seen.lock().await;
        let req: Value = serde_json::from_str(&seen[0]).unwrap();
        assert_eq!(req["response_format"]["type"], "json_schema", "{req}");
        assert_eq!(req["response_format"]["json_schema"]["name"], "Answers");
        assert_eq!(req["temperature"], 0.0);
        let answers = &req["response_format"]["json_schema"]["schema"]["properties"]["answers"];
        assert_eq!(answers["minItems"], 1, "an empty list is no reply");
        let item = &answers["items"];
        assert_eq!(item["properties"]["flag"]["type"], "boolean", "{item}");
        let first = item["properties"].as_object().unwrap().keys().next();
        assert_eq!(first.unwrap(), "i", "the index comes first: {item}");
        assert_eq!(item["required"][0], "i", "{item}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn two_shapes_both_get_the_index() {
        let verdict: schemars::Schema = serde_json::from_value(json!({
            "title": "Verdict",
            "anyOf": [
                {"type": "object", "properties": {"flag": {"type": "boolean", "const": false}},
                 "required": ["flag"], "additionalProperties": false},
                {"type": "object", "properties": {"flag": {"type": "boolean", "const": true}, "why": {"type": "string"}},
                 "required": ["flag", "why"], "additionalProperties": false}
            ]
        }))
        .unwrap();
        let schema = serde_json::to_value(answers_schema(&verdict)).unwrap();
        let shapes = schema["properties"]["answers"]["items"]["anyOf"]
            .as_array()
            .unwrap();
        assert_eq!(shapes.len(), 2);
        for shape in shapes {
            let props: Vec<&String> = shape["properties"].as_object().unwrap().keys().collect();
            assert_eq!(props[0], "i", "{shape}");
            assert_eq!(shape["additionalProperties"], false, "{shape}");
        }
        assert_eq!(shapes[1]["required"], json!(["i", "flag", "why"]));
    }

    #[test]
    fn batch_bytes_splits_a_group() {
        let dir = stub::dir("chunks");
        let mut cfg = stub::config("http://127.0.0.1:1/v1");
        cfg.node.batch_bytes = 80;
        let node = cfg.node("judge", &dir).unwrap();
        let lens = |v: Value| {
            node.chunks(vec![v; 5])
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>()
        };
        assert_eq!(lens(json!({"id": 1})), [5]);
        assert_eq!(
            lens(json!({"id": 1, "msg": "a record of some length"})),
            [2, 2, 1]
        );
        assert_eq!(lens(json!({"msg": "x".repeat(100)})), [1, 1, 1, 1, 1]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_prompt_file_that_is_missing_is_an_error_at_startup() {
        let dir = stub::dir("missing");
        let mut cfg = stub::config("http://127.0.0.1:1/v1");
        cfg.node.prompt_file = "nope.md".into();
        let err = cfg.node("judge", &dir).err().unwrap();
        assert!(format!("{err:#}").contains("nope.md"), "{err:#}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
