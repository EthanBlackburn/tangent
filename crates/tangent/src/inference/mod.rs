//! Inference nodes: a model reads each record. A node lives inside each
//! worker and runs in DAG order with the plugins: the worker hands it the
//! records that reached it, waits for the replies (`concurrency` at a time),
//! and carries the annotated records on to the node's outputs. The system
//! prompt is a file; the user message is the records of one `group_by` value
//! (or selected fields), a JSON line each; each record's answer is added to
//! it under the node's name. The node adds and forwards, never drops: a
//! failure lands as `{"error": ...}` in the same field, and a plugin
//! downstream decides what goes on.
//!
//! The reply is read as JSON and nothing else. The backend is asked to make
//! it so: a schema (`schema_file`) through rig's structured output, or JSON
//! mode on an OpenAI-compatible server. A server that ignores both (mlx_lm)
//! is held to the prompt, and a reply that is not a JSON object is the error.

use anyhow::{anyhow, bail, Context, Result};
use rig_core::completion::message::CallId;
use rig_core::completion::request::{CompletionRequest, ToolDefinition};
use rig_core::completion::{AssistantContent, CacheRetention, Message, OnUnsupported};
use rig_core::operation::Completion;
use rig_core::providers::openai::{OpenAIConfig, Route};
use rig_core::{schemars, DynModel};
use secrecy::ExposeSecret;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tangent_compact as compact;
use tangent_shared::inference::{Backend, Encoding, InferenceConfig, DEFAULT_URL};
use tokio::sync::Semaphore;

pub struct InferenceNode {
    pub name: Arc<str>,
    cfg: InferenceConfig,
    prompt: String,
    /// The shape the backend is asked to enforce, from `schema_file`.
    schema: Option<schemars::Schema>,
    model: DynModel<Completion>,
    /// `concurrency` permits: requests in flight to this node, shared by
    /// every worker's copy of it.
    sem: Arc<Semaphore>,
}

fn resolve(config_dir: &Path, file: &Path) -> PathBuf {
    if file.is_absolute() {
        file.to_path_buf()
    } else {
        config_dir.join(file)
    }
}

/// The model `cfg` points at, behind rig's erased handle.
fn model(cfg: &InferenceConfig) -> Result<DynModel<Completion>> {
    Ok(match cfg.backend {
        Backend::Openai => {
            // Local servers accept any key; a hosted one needs the real thing.
            let key = cfg.api_key.as_ref().map_or("none", |k| k.expose_secret());
            OpenAIConfig::new(key)
                .with_base_url(
                    cfg.url
                        .as_deref()
                        .unwrap_or(DEFAULT_URL)
                        .trim_end_matches('/'),
                )
                .with_route(Route::Chat)
                .client()
                .chat(&cfg.model)
                .erase()
        }
        Backend::Bedrock => {
            let mut runtime = rig_bedrock::client::BedrockRuntime::builder();
            if let Some(region) = &cfg.aws.region {
                runtime = runtime.region(region);
            }
            if let Some(profile) = &cfg.aws.profile {
                runtime = runtime.profile_name(profile);
            }
            runtime.build().completion(&cfg.model).erase()
        }
    })
}

impl InferenceNode {
    pub fn new(name: Arc<str>, cfg: InferenceConfig, config_dir: &Path) -> Result<Self> {
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
        let model = model(&cfg)?;
        let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
        tracing::info!(
            node = %name,
            backend = ?cfg.backend,
            model = %cfg.model,
            "inference ready"
        );
        Ok(Self {
            name,
            cfg,
            prompt,
            schema,
            model,
            sem,
        })
    }

    /// The node, its requests in flight counted against `sem` with every
    /// other copy given the same one.
    pub fn sharing(mut self, sem: Arc<Semaphore>) -> Self {
        self.sem = sem;
        self
    }

    /// One turn of a conversation a plugin holds (`model.chat`): the
    /// plugin's messages and tools to the model, under one of the node's
    /// permits and with its prompt, timeout and retries, and the model's
    /// turn back, as the plugin interface describes both.
    pub async fn chat(&self, request: &str) -> Result<String> {
        let request: Value = serde_json::from_str(request).context("the request is not JSON")?;
        let mut messages = request
            .get("messages")
            .and_then(Value::as_array)
            .context("the request has no `messages`")?
            .iter()
            .map(chat_message)
            .collect::<Result<Vec<Message>>>()?;
        let last = messages.pop().context("`messages` is empty")?;
        let tools: Vec<ToolDefinition> = match request.get("tools") {
            Some(tools) => serde_json::from_value(tools.clone()).context("`tools`")?,
            None => Vec::new(),
        };
        let cache = request.get("cache").and_then(Value::as_bool) == Some(true);
        let build = || {
            let mut r = CompletionRequest::new(last.clone())
                .messages(messages.iter().cloned())
                .preamble(self.prompt.trim_end())
                .tools(tools.iter().cloned())
                .max_tokens(u64::from(self.cfg.max_tokens));
            if let Some(t) = self.cfg.temperature {
                r = r.temperature(t);
            }
            if cache {
                // where the provider can: one that cannot at this point of
                // the conversation answers uncached
                r = r
                    .cache(CacheRetention::Short)
                    .on_unsupported(OnUnsupported::Ignore);
            }
            if !self.cfg.extra.is_empty() {
                r = r.additional_params(Value::Object(self.cfg.extra.clone()));
            }
            r
        };
        let _permit = self.sem.acquire().await.expect("semaphore is never closed");
        let attempts = self.cfg.retries.saturating_add(1);
        let mut attempt = 0;
        let reply = loop {
            attempt += 1;
            let tried = tokio::time::timeout(
                Duration::from_millis(self.cfg.timeout_ms),
                self.model.call(build()),
            )
            .await
            .map_err(|_| anyhow!("no reply within {} ms", self.cfg.timeout_ms))
            .and_then(|r| r.map_err(|e| anyhow!("{e}")));
            match tried {
                Ok(reply) => break reply,
                Err(e) if attempt < attempts => {
                    let wait = Duration::from_secs(1 << (attempt - 1).min(6));
                    tracing::warn!(node = %self.name, attempt, "chat failed, retrying in {wait:?}: {e:#}");
                    tokio::time::sleep(wait).await;
                }
                Err(e) => return Err(e),
            }
        };
        if let Some(e) = &reply.error {
            bail!("the model failed the turn: {e}");
        }
        // A call the client kept as an item it does not understand is the
        // call it is ([`tool_call`]); the turn then goes back with it so.
        let content: Vec<AssistantContent> = reply
            .choice
            .iter()
            .map(|block| tool_call(block).unwrap_or_else(|| block.clone()))
            .collect();
        let message = if content == reply.choice {
            reply.message()
        } else {
            Some(Message::Assistant(reply.continued(content.clone())))
        };
        let calls: Vec<Value> = content
            .iter()
            .filter_map(|block| match block {
                AssistantContent::ToolCall(c) => Some(
                    json!({"id": c.id, "name": c.function.name, "arguments": c.function.arguments}),
                ),
                _ => None,
            })
            .collect();
        let stop = if calls.is_empty() {
            json!(reply.stop())
        } else {
            json!("tool_use")
        };
        tracing::debug!(node = %self.name, %stop, calls = calls.len(), "chat turn");
        Ok(json!({
            "message": message,
            "text": reply.text(),
            "calls": calls,
            "stop": stop,
            "usage": reply.usage,
        })
        .to_string())
    }

    pub async fn annotate_all(&self, records: Vec<Value>) -> Vec<Value> {
        let n = records.len();
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
            let _permit = self.sem.acquire().await.expect("semaphore is never closed");
            (ids, self.annotate(chunk).await)
        }))
        .await;
        let mut slots = vec![Value::Null; n];
        for (ids, out) in done {
            for (i, v) in ids.into_iter().zip(out) {
                slots[i] = v;
            }
        }
        slots
    }

    /// Records in one request; an unreadable reply is asked again in halves.
    async fn annotate(&self, records: Vec<Value>) -> Vec<Value> {
        let n = records.len();
        let start = Instant::now();
        let answers = match self.user(&records) {
            Ok(user) => self.ask(user, n).await,
            Err(e) => Err(e),
        };
        let answers = match answers {
            Ok(reply) => spread(reply, n, matches!(self.cfg.encoding, Encoding::Ndjson)),
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
        match (&self.schema, self.cfg.backend) {
            (Some(schema), _) => {
                request = request.output_schema(answers_schema(schema));
            }
            // JSON mode: any object. Converse has no such mode without a schema.
            (None, Backend::Openai) => {
                params.insert("response_format".into(), json!({"type": "json_object"}));
            }
            (None, Backend::Bedrock) => {}
        }
        for (k, v) in &self.cfg.extra {
            params.insert(k.clone(), v.clone());
        }
        if !params.is_empty() {
            request = request.additional_params(Value::Object(params));
        }
        request
    }

    /// The reply as a JSON object, after `retries` more tries for a request
    /// that got no reply.
    async fn ask(&self, user: String, n: usize) -> Result<Value> {
        let attempts = self.cfg.retries.saturating_add(1);
        let mut attempt = 0;
        let text = loop {
            attempt += 1;
            match self.call(user.clone(), n).await {
                Ok(text) => break text,
                Err(e) if attempt < attempts => {
                    let wait = Duration::from_secs(1 << (attempt - 1).min(6));
                    tracing::warn!(
                        node = %self.name,
                        attempt,
                        "inference failed, retrying in {wait:?}: {e:#}"
                    );
                    tokio::time::sleep(wait).await;
                }
                Err(e) => return Err(e),
            }
        };
        let value: Value = serde_json::from_str(text.trim())
            .map_err(|e| anyhow!("reply is not JSON ({e}): {}", head(&text, 200)))?;
        if !value.is_object() {
            bail!("reply is not a JSON object: {}", head(&text, 200));
        }
        Ok(value)
    }

    /// One request: the reply's text, or why there is none.
    async fn call(&self, user: String, n: usize) -> Result<String> {
        let reply = tokio::time::timeout(
            Duration::from_millis(self.cfg.timeout_ms),
            self.model.call(self.request(user, n)),
        )
        .await
        .map_err(|_| anyhow!("no reply within {} ms", self.cfg.timeout_ms))?
        .map_err(|e| anyhow!("{e}"))?;

        // Reasoning comes back as its own block, so the text is the answer.
        let text: String = reply
            .choice
            .iter()
            .filter_map(|c| match c {
                AssistantContent::Text(t) => Some(t.text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("");
        if text.trim().is_empty() {
            bail!(
                "reply has no text (finish: {:?}; the model may have spent its budget thinking)",
                reply.finish_reason()
            );
        }
        Ok(text)
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
fn chat_message(m: &Value) -> Result<Message> {
    let text = |t: &Value| json!({"type": "text", "text": t.as_str().unwrap_or_default()});
    let shaped = if m.get("role").and_then(Value::as_str) == Some("system") {
        json!({"role": "system", "content": m.get("text").and_then(Value::as_str).unwrap_or_default()})
    } else if let Some(t) = m.get("text") {
        json!({"role": "user", "content": [text(t)]})
    } else if let Some(results) = m.get("results").and_then(Value::as_array) {
        let content: Vec<Value> = results
            .iter()
            .map(|r| {
                json!({
                    "type": "toolresult",
                    "call": r.get("id"),
                    "name": r.get("name"),
                    "content": [text(r.get("text").unwrap_or(&Value::Null))],
                    "is_error": r.get("error").and_then(Value::as_bool).unwrap_or(false),
                })
            })
            .collect();
        json!({"role": "user", "content": content})
    } else {
        m.clone()
    };
    serde_json::from_value(shaped)
        .context("a message is neither text, results nor a reply's message")
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

/// Answers by their `i`; by position when none is missing one and the text
/// is in index order (`in_order`; logfmt groups its rows).
fn spread(reply: Value, n: usize, in_order: bool) -> Vec<Value> {
    let Some(items) = reply.get("answers").and_then(Value::as_array).cloned() else {
        let err = format!(
            "reply has no `answers` array: {}",
            head(&reply.to_string(), 200)
        );
        return vec![json!({"error": err}); n];
    };
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
        .enumerate()
        .map(|(k, slot)| match slot {
            Some(Value::Object(mut m)) => {
                m.remove("i");
                Value::Object(m)
            }
            Some(other) => json!({"error": format!("answer {k} is not a JSON object: {}", head(&other.to_string(), 200))}),
            None => json!({"error": format!("no answer for record {k} in a reply to {n}")}),
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
            "answers": {"type": "array", "items": item}
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
/// One `concurrency` limit per inference node, for every worker that runs a
/// copy of it to share: the model sees at most that many requests from the
/// node, however many workers there are.
pub fn permits(cfgs: &BTreeMap<Arc<str>, InferenceConfig>) -> BTreeMap<Arc<str>, Arc<Semaphore>> {
    cfgs.iter()
        .map(|(name, cfg)| {
            (
                Arc::clone(name),
                Arc::new(Semaphore::new(cfg.concurrency.max(1))),
            )
        })
        .collect()
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
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let log = Arc::clone(&log);
                let flaky_failures = Arc::clone(&flaky_failures);
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
                        let message = if answered {
                            json!({"role": "assistant", "content": "done"})
                        } else {
                            json!({"role": "assistant", "content": null, "tool_calls": [{
                                "id": "call_1", "type": "function",
                                "function": {"name": tool, "arguments": "{\"sql\": \"SELECT 1\"}"}}]})
                        };
                        let finish = if answered { "stop" } else { "tool_calls" };
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
                        let answers: Vec<_> = records
                            .iter()
                            .enumerate()
                            .map(|(k, r)| {
                                let mut a = verdict(r);
                                if logfmt {
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

    /// A node config against `url`, with the prompt (and a schema, when
    /// given) written under a fresh directory the caller removes.
    pub fn config(url: &str) -> tangent_shared::inference::InferenceConfig {
        let mut extra = serde_json::Map::new();
        extra.insert(
            "chat_template_kwargs".into(),
            json!({"enable_thinking": false}),
        );
        tangent_shared::inference::InferenceConfig {
            backend: tangent_shared::inference::Backend::Openai,
            url: Some(url.to_string()),
            api_key: None,
            model: "stub".into(),
            aws: Default::default(),
            prompt_file: "judge.md".into(),
            schema_file: None,
            fields: Vec::new(),
            batch_bytes: 32_768,
            encoding: Default::default(),
            group_by: Vec::new(),
            concurrency: 2,
            timeout_ms: 5_000,
            retries: 0,
            max_tokens: 50,
            temperature: None,
            extra,
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

    #[tokio::test]
    async fn annotates_every_record_with_the_verdict() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("verdict");
        let node = InferenceNode::new(Arc::from("judge"), stub::config(&url), &dir).unwrap();
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
    #[tokio::test]
    async fn a_conversation_calls_a_tool_and_takes_its_result() {
        let (url, seen) = stub::model().await;
        let node = InferenceNode::new(
            Arc::from("reviewer"),
            stub::config(&url),
            &stub::dir("chat"),
        )
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

    #[tokio::test]
    async fn a_request_that_is_not_a_conversation_is_an_error() {
        let (url, _) = stub::model().await;
        let node = InferenceNode::new(
            Arc::from("reviewer"),
            stub::config(&url),
            &stub::dir("chat-bad"),
        )
        .unwrap();
        for (request, says) in [
            ("not json", "not JSON"),
            ("{}", "no `messages`"),
            (r#"{"messages": []}"#, "empty"),
            (r#"{"messages": [{"role": "user"}]}"#, "neither text"),
        ] {
            let e = node.chat(request).await.unwrap_err();
            assert!(format!("{e:#}").contains(says), "{request}: {e:#}");
        }
    }

    #[tokio::test]
    async fn logfmt_records_reach_the_model_and_read_back() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("logfmt");
        let mut cfg = stub::config(&url);
        cfg.encoding = serde_yaml::from_str("{type: logfmt, budget_tokens: 60}").unwrap();
        let node = InferenceNode::new(Arc::from("judge"), cfg, &dir).unwrap();
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
        let node = InferenceNode::new(Arc::from("judge"), stub::config(&url), &dir).unwrap();
        let out = node
            .annotate_all(vec![json!({"id": 7, "msg": "prose please"})])
            .await;
        assert_eq!(out[0]["id"], 7);
        let err = out[0]["judge"]["error"].as_str().unwrap();
        assert!(
            err.contains("not JSON") && err.contains("Looks fine"),
            "{err}"
        );
        assert_eq!(
            seen.lock().await.len(),
            1,
            "a reply that came back is not retried"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_request_that_got_no_reply_is_retried() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("flaky");
        let mut cfg = stub::config(&url);
        cfg.retries = 2;
        let node = InferenceNode::new(Arc::from("judge"), cfg, &dir).unwrap();
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
        let node = InferenceNode::new(
            Arc::from("judge"),
            stub::config("http://127.0.0.1:1/v1"),
            &dir,
        )
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
        let node = InferenceNode::new(Arc::from("judge"), stub::config(&url), &dir).unwrap();
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

    /// Two workers' copies of a node with `concurrency: 1` send one request
    /// at a time between them, not one each.
    #[tokio::test]
    async fn copies_of_a_node_share_its_concurrency() {
        let (url, taken) = stub::silent().await;
        let dir = stub::dir("shared-permits");
        let mut cfg = stub::config(&url);
        cfg.concurrency = 1;
        let permits = permits(&BTreeMap::from([(Arc::from("judge"), cfg.clone())]));
        let copies: Vec<_> = (0..2)
            .map(|_| {
                InferenceNode::new(Arc::from("judge"), cfg.clone(), &dir)
                    .unwrap()
                    .sharing(Arc::clone(&permits["judge"]))
            })
            .collect();
        let calls: Vec<_> = copies
            .into_iter()
            .map(|node| {
                tokio::spawn(async move { node.annotate_all(vec![json!({"id": 1})]).await })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            taken.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one request between the two copies"
        );
        for c in calls {
            c.abort();
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn group_by_keeps_requests_apart() {
        let (url, seen) = stub::model().await;
        let dir = stub::dir("group-by");
        let mut cfg = stub::config(&url);
        cfg.group_by = vec!["who.actor".into()];
        let node = InferenceNode::new(Arc::from("judge"), cfg, &dir).unwrap();
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
    fn spread_errors_missing_answers() {
        let out = spread(
            json!({"answers": [{"i": 1, "flag": true}, {"i": 0, "flag": false}]}),
            3,
            true,
        );
        assert_eq!(out[0], json!({"flag": false}));
        assert_eq!(out[1], json!({"flag": true}));
        assert!(out[2]["error"]
            .as_str()
            .unwrap()
            .contains("no answer for record 2"));
        // logfmt's rows are not in index order: an answer without `i` lands nowhere
        let out = spread(
            json!({"answers": [{"flag": true}, {"flag": false}]}),
            2,
            false,
        );
        assert!(out.iter().all(|a| a["error"].is_string()), "{out:?}");
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
        cfg.schema_file = Some("verdict.json".into());
        cfg.temperature = Some(0.0);
        let node = InferenceNode::new(Arc::from("judge"), cfg, &dir).unwrap();
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
        assert!(answers.get("minItems").is_none(), "backends reject bounds");
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
        cfg.batch_bytes = 80;
        let node = InferenceNode::new(Arc::from("judge"), cfg, &dir).unwrap();
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
        cfg.prompt_file = "nope.md".into();
        let err = InferenceNode::new(Arc::from("judge"), cfg, &dir)
            .err()
            .unwrap();
        assert!(format!("{err:#}").contains("nope.md"), "{err:#}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
