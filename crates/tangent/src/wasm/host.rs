use std::sync::Arc;

use ahash::HashMap;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use reqwest::Client;
use serde_json::Value as JSONValue;
use simd_json::base::ValueAsScalar;
use simd_json::derived::{TypedArrayValue, TypedScalarValue};
use simd_json::prelude::Writable;
use simd_json::prelude::{ValueAsArray, ValueAsObject, ValueObjectAccess};
use simd_json::{BorrowedValue, StaticNode};
use wasmtime::component::{bindgen, HasData, Resource, ResourceTable};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

use crate::enrichment::Tables;
use crate::inference::Nodes;
use crate::sinks::manager::Sink;
use crate::state::{StateStore, StateValue, Txn};
use crate::stop::Stop;
use crate::wasm::host::tangent::logs::log;
use crate::wasm::host::tangent::logs::remote;
use log::Scalar;

bindgen!({
    world: "processor",
    path: "../../assets/wit",
    exports: {default: async},
    imports: {
        "tangent:logs/remote.call-batch": async,
        "tangent:logs/state.get": async,
        "tangent:logs/state.set": async,
        "tangent:logs/state.del": async,
        "tangent:logs/state.incr": async,
        "tangent:logs/state.scan": async,
        "tangent:logs/state.begin": async,
        "tangent:logs/state.commit": async,
        "tangent:logs/lake.query": async,
        "tangent:logs/model.chat": async,
    },
    with: {
        "tangent:logs/log.logview": JsonLogView,
    }
});

/// What a plugin may query (`plugins.<name>.tables`): each table as
/// `NAME=PATH`, where its sink puts its Parquet files, and by the table's
/// name the sink itself, which holds the records it has put in none yet.
/// The sink and not the sink manager: shutdown must hold that alone.
#[derive(Default)]
pub struct Lake {
    pub tables: Vec<String>,
    pub sinks: Vec<(String, Arc<dyn Sink>)>,
}

pub struct HostEngine {
    pub ctx: WasiCtx,
    pub table: ResourceTable,
    http_client: Client,
    state: Arc<dyn StateStore>,
    /// Namespace of this plugin's state: the one every plugin shares, unless
    /// the plugin was given a `state_namespace` of its own.
    ns: Arc<str>,
    /// `runtime.state.max_ttl_ms`: the longest TTL this plugin's writes get
    /// (0: no cap).
    max_ttl_ms: u64,
    /// The transaction the guest began and has not ended.
    txn: Option<Box<dyn Txn>>,
    plugin_cfg: Arc<HashMap<String, JSONValue>>,
    /// The process's enrichment tables, shared with every other instance.
    tables: Arc<Tables>,
    /// The tables this plugin may query; None when its config names none.
    lake: Option<Arc<Lake>>,
    /// The inference nodes this plugin may hold a conversation with
    /// (`plugins.<name>.inference`).
    models: Nodes,
    /// The run's stop: a turn is not sent once it is finishing, and one
    /// under way ends when the requests are ended.
    stop: Stop,
    /// A turn of this call was not sent, or was ended, by the stop: what
    /// the plugin made of its records is not what it would have.
    cut: bool,
    /// The call's latest request of a model or of the lake went unanswered
    /// for a reason another time may not have ([`Self::take_unreached`]).
    unreached: bool,
    /// If true, short-circuit remote calls with successful empty responses,
    /// and fail a model's turn rather than ask for it.
    pub disable_remote_calls: bool,
}

impl HostEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctx: WasiCtx,
        state: Arc<dyn StateStore>,
        ns: Arc<str>,
        max_ttl_ms: u64,
        config: Arc<HashMap<String, JSONValue>>,
        tables: Arc<Tables>,
        lake: Option<Arc<Lake>>,
        models: Nodes,
        stop: Stop,
        disable_remote_calls: bool,
    ) -> Self {
        Self {
            ctx,
            table: ResourceTable::new(),
            http_client: Client::new(),
            state,
            ns,
            max_ttl_ms,
            txn: None,
            plugin_cfg: config,
            tables,
            lake,
            models,
            stop,
            cut: false,
            unreached: false,
            disable_remote_calls,
        }
    }

    /// Rolls back a transaction the guest left open when its call ended: it
    /// trapped, failed or never committed. True when there was one. Until
    /// then no other state call runs, so the worker ends every call.
    pub fn end_call(&mut self) -> bool {
        self.txn.take().is_some()
    }

    /// Whether the stop kept a turn of the call just ended from the model,
    /// which it asks once per call.
    pub fn take_cut(&mut self) -> bool {
        std::mem::take(&mut self.cut)
    }

    /// Whether the call just ended made its last request of a model or of
    /// the lake in vain, for a reason another time may not have: the model
    /// was not reached or would not serve the key, the query ran out of
    /// time or of files to open. A request answered after one that was not
    /// clears it: the plugin went on. Asked once per call.
    pub fn take_unreached(&mut self) -> bool {
        std::mem::take(&mut self.unreached)
    }

    /// A TTL the guest asked for, cut to `max_ttl_ms`. None (the default,
    /// which the store refuses to open above the cap) and 0 (never) stand.
    fn capped(&self, ttl_ms: Option<u64>) -> Option<u64> {
        match ttl_ms {
            Some(t) if self.max_ttl_ms > 0 && t > self.max_ttl_ms => Some(self.max_ttl_ms),
            t => t,
        }
    }

    async fn execute_single(client: Client, r: remote::Request) -> remote::Response {
        use remote::Method;

        let method = match r.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Put => reqwest::Method::PUT,
            Method::Delete => reqwest::Method::DELETE,
            Method::Patch => reqwest::Method::PATCH,
        };

        let mut req_builder = client.request(method, &r.url);

        for (name, value) in &r.headers {
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }

        if let Some(ms) = r.timeout_ms {
            req_builder = req_builder.timeout(std::time::Duration::from_millis(ms as u64));
        }

        if !r.body.is_empty() {
            req_builder = req_builder.body(r.body.clone());
        }

        match req_builder.send().await {
            Ok(res) => {
                let status = res.status().as_u16();
                let headers = res
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
                    .collect::<Vec<(String, String)>>();

                let body_bytes = match res.bytes().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => {
                        return remote::Response {
                            id: r.id,
                            status,
                            headers,
                            body: Vec::new(),
                            error: Some(format!("failed to read body: {e}")),
                        }
                    }
                };

                remote::Response {
                    id: r.id,
                    status,
                    headers,
                    body: body_bytes,
                    error: None,
                }
            }
            Err(e) => remote::Response {
                id: r.id,
                status: 0,
                headers: Vec::new(),
                body: Vec::new(),
                error: Some(e.to_string()),
            },
        }
    }
}

impl WasiView for HostEngine {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl From<Scalar> for StateValue {
    fn from(s: Scalar) -> Self {
        match s {
            Scalar::Str(s) => StateValue::Str(s),
            Scalar::Int(i) => StateValue::Int(i),
            Scalar::Float(f) => StateValue::Float(f),
            Scalar::Boolean(b) => StateValue::Bool(b),
            Scalar::Bytes(b) => StateValue::Bytes(b),
        }
    }
}

impl From<StateValue> for Scalar {
    fn from(v: StateValue) -> Self {
        match v {
            StateValue::Str(s) => Scalar::Str(s),
            StateValue::Int(i) => Scalar::Int(i),
            StateValue::Float(f) => Scalar::Float(f),
            StateValue::Bool(b) => Scalar::Boolean(b),
            StateValue::Bytes(b) => Scalar::Bytes(b),
            // The guest has no JSON scalar; it gets the text.
            StateValue::Json(j) => Scalar::Str(j.to_string()),
        }
    }
}

impl remote::Host for HostEngine {
    async fn call_batch(
        &mut self,
        reqs: Vec<remote::Request>,
    ) -> Result<Vec<remote::Response>, String> {
        if self.txn.is_some() {
            return Err("commit or roll back the state transaction first: it would hold every worker's state for the round trip".into());
        }
        if self.disable_remote_calls {
            // Short-circuit with successful empty responses.
            let out = reqs
                .into_iter()
                .map(|r| remote::Response {
                    id: r.id,
                    status: 204,
                    headers: Vec::new(),
                    body: Vec::new(),
                    error: None,
                })
                .collect();
            return Ok(out);
        }

        let mut out = Vec::with_capacity(reqs.len());
        let client = self.http_client.clone();

        for r in reqs {
            let resp = Self::execute_single(client.clone(), r);
            out.push(resp.await);
        }

        Ok(out)
    }
}

impl tangent::logs::config::Host for HostEngine {
    fn get(&mut self, key: String) -> Option<String> {
        self.plugin_cfg.get(&key).map(|v| {
            match v {
                // Plain string config (e.g. slack_channel)
                serde_json::Value::String(s) => s.clone(),
                // Anything else (objects, arrays, numbers, bools, null)
                // – serialize to JSON for the guest
                other => other.to_string(),
            }
        })
    }
}

/// A lookup is an index search in memory the tables already hold: no file,
/// no lock, nothing async.
impl tangent::logs::enrichment::Host for HostEngine {
    fn lookup(&mut self, table: String, key: String) -> Option<String> {
        self.tables.lookup(&table, &key)
    }
}

/// A turn of a conversation with one of the plugin's `inference`: the node's
/// own request, under its concurrency, timeout and retries. A run that is
/// stopping sends no turn, and one whose requests are ended ends the turn
/// under way: either is the call's error, and marks the plugin's call cut.
impl tangent::logs::model::Host for HostEngine {
    async fn chat(&mut self, node: String, request: String) -> Result<String, String> {
        if self.txn.is_some() {
            return Err("commit or roll back the state transaction first: it would hold every worker's state for the model's reply".into());
        }
        let Some(model) = self.models.get(node.as_str()) else {
            return Err(format!(
                "inference node `{node}` is not among this plugin's `inference` in the config"
            ));
        };
        if self.disable_remote_calls {
            return Err("the model was not asked: `runtime.disable_remote_calls` is set, as `tangent plugin test` sets it without --enable-http".into());
        }
        if self.stop.finishing() {
            self.cut = true;
            return Err("tangent is stopping: the turn was not sent".into());
        }
        match self.stop.unless_ended(model.chat(&request)).await {
            Some(Ok(reply)) => {
                self.unreached = false;
                Ok(reply)
            }
            // One that failed as the run began to stop was not sent, waiting
            // for the model's place, or was not sent again.
            Some(Err(e)) => {
                self.unreached = e
                    .downcast_ref::<crate::inference::model::Unreached>()
                    .is_some();
                self.cut = self.stop.finishing();
                Err(format!("{e:#}"))
            }
            None => {
                self.cut = true;
                Err("stopped before the model answered".into())
            }
        }
    }
}

/// How long a plugin's query runs when it names no time.
const QUERY_TIMEOUT_MS: u32 = 30_000;

/// SQL over the sinks' records the plugin's `tables` name: every record a
/// sink has acknowledged, in a Parquet file or not yet. The statement may
/// be a model's, so it runs as `tangent query`'s does: it reads the tables
/// and the plugin's views, and nothing else. It is not given a plan
/// (`EXPLAIN`), which would say which rows are in a file.
impl tangent::logs::lake::Host for HostEngine {
    async fn query(&mut self, s: tangent::logs::lake::Statement) -> Result<String, String> {
        if self.txn.is_some() {
            return Err("commit or roll back the state transaction first: it would hold every worker's state for the query".into());
        }
        let Some(lake) = &self.lake else {
            return Err("this plugin has no `tables` in the config to query".into());
        };
        let q = crate::query::Query {
            tables: lake.tables.clone(),
            views: s
                .views
                .into_iter()
                .map(|(name, select)| format!("{name}={select}"))
                .collect(),
            sql: s.sql,
            max_rows: s.max_rows as usize,
            max_cell: s.max_cell as usize,
            json: s.json,
        };
        let wait = s.timeout_ms.unwrap_or(QUERY_TIMEOUT_MS);
        match tokio::time::timeout(
            std::time::Duration::from_millis(u64::from(wait)),
            crate::query::run_with(&q, &lake.sinks),
        )
        .await
        {
            Ok(Ok(rows)) => {
                self.unreached = false;
                Ok(rows)
            }
            Ok(Err(e)) => {
                let said = format!("{e:#}");
                // the files could not be opened, not the statement read
                self.unreached = said.contains("Too many open files");
                Err(said)
            }
            Err(_) => {
                self.unreached = true;
                Err(format!("the query ran over {wait} ms"))
            }
        }
    }
}

/// The guest's state: the plugins' namespace of the state store, shared by
/// every record (a plugin keys per tenant itself). Each call stands alone,
/// unless the guest began a transaction: then they go through it until it
/// commits or rolls back. A write's TTL is held to `max_ttl_ms` here, where
/// plugin writes enter, so the runtime's own writes keep theirs.
impl tangent::logs::state::Host for HostEngine {
    async fn get(&mut self, key: String) -> Result<Option<Scalar>, String> {
        let got = match self.txn.as_mut() {
            Some(t) => t.get(&self.ns, &key).await,
            None => self.state.get(&self.ns, &key).await,
        };
        got.map(|v| v.map(Scalar::from)).map_err(|e| e.to_string())
    }

    async fn set(&mut self, key: String, value: Scalar, ttl_ms: Option<u64>) -> Result<(), String> {
        let value = value.into();
        let ttl_ms = self.capped(ttl_ms);
        match self.txn.as_mut() {
            Some(t) => t.set(&self.ns, &key, &value, ttl_ms).await,
            None => self.state.set(&self.ns, &key, &value, ttl_ms).await,
        }
        .map_err(|e| e.to_string())
    }

    async fn del(&mut self, key: String) -> Result<bool, String> {
        match self.txn.as_mut() {
            Some(t) => t.del(&self.ns, &key).await,
            None => self.state.del(&self.ns, &key).await,
        }
        .map_err(|e| e.to_string())
    }

    async fn incr(&mut self, key: String, by: i64, ttl_ms: Option<u64>) -> Result<i64, String> {
        let ttl_ms = self.capped(ttl_ms);
        match self.txn.as_mut() {
            Some(t) => t.incr(&self.ns, &key, by, ttl_ms).await,
            None => self.state.incr(&self.ns, &key, by, ttl_ms).await,
        }
        .map_err(|e| e.to_string())
    }

    async fn scan(
        &mut self,
        from: String,
        to: String,
        limit: u32,
    ) -> Result<Vec<(String, Scalar)>, String> {
        let limit = limit as usize;
        match self.txn.as_mut() {
            Some(t) => t.range(&self.ns, &from, &to, limit).await,
            None => self.state.range(&self.ns, &from, &to, limit).await,
        }
        .map(|entries| {
            entries
                .into_iter()
                .map(|e| (e.key, Scalar::from(e.value)))
                .collect()
        })
        .map_err(|e| e.to_string())
    }

    async fn begin(&mut self) -> Result<(), String> {
        if self.txn.is_some() {
            return Err("a transaction is open already".into());
        }
        self.txn = Some(self.state.begin().await.map_err(|e| e.to_string())?);
        Ok(())
    }

    async fn commit(&mut self) -> Result<(), String> {
        match self.txn.take() {
            Some(t) => t.commit().await.map_err(|e| e.to_string()),
            None => Err("no transaction is open".into()),
        }
    }

    fn rollback(&mut self) {
        self.txn = None;
    }
}

struct JsonDoc {
    _raw: Bytes,
    doc: BorrowedValue<'static>,
}

#[derive(Clone)]
pub struct JsonLogView(Arc<JsonDoc>);

impl JsonLogView {
    pub fn from_bytes(mut line: BytesMut) -> anyhow::Result<Self> {
        let v: simd_json::BorrowedValue<'_> = simd_json::to_borrowed_value(line.as_mut())?;
        let v_static: simd_json::BorrowedValue<'static> = unsafe { std::mem::transmute(v) };

        let raw = line.freeze();

        Ok(Self(Arc::new(JsonDoc {
            _raw: raw,
            doc: v_static,
        })))
    }

    /// Size of the record this view was parsed from.
    pub fn byte_len(&self) -> usize {
        self.0._raw.len()
    }

    /// The record as JSON text again.
    pub fn to_json(&self) -> String {
        self.0.doc.encode()
    }

    pub fn lookup<'a>(&'a self, path: &str) -> Option<&'a BorrowedValue<'a>> {
        let mut v = &self.0.doc;

        if let Some(val) = v.get(path) {
            return Some(val);
        }
        for seg in path.split('.') {
            if let Some((key, bracket)) = seg.split_once('[') {
                v = v.get(key)?;
                let mut rest = bracket;
                loop {
                    let start = 0;
                    let close = rest.find(']')?;
                    let idx: usize = rest[start..close].parse().ok()?;
                    v = v.as_array()?.get(idx)?;

                    if let Some(next_open) = rest[close + 1..].find('[') {
                        rest = &rest[close + 2 + next_open..];
                    } else {
                        break;
                    }
                }
            } else {
                v = v.get(seg)?;
            }
        }
        Some(v)
    }

    pub fn to_scalar(v: &BorrowedValue) -> Option<Scalar> {
        match v {
            BorrowedValue::String(s) => Some(Scalar::Str(s.to_string())),
            BorrowedValue::Static(StaticNode::I64(i)) => Some(Scalar::Int(*i)),
            BorrowedValue::Static(StaticNode::U64(i)) => Some(Scalar::Int(*i as i64)),
            BorrowedValue::Static(StaticNode::F64(f)) => Some(Scalar::Float(*f)),
            BorrowedValue::Static(StaticNode::Bool(b)) => Some(Scalar::Boolean(*b)),
            _ => None,
        }
    }
}

impl log::HostLogview for HostEngine {
    fn log(&mut self, h: Resource<JsonLogView>) -> String {
        // Serialized again rather than the input bytes: parsing de-escaped
        // strings in place, so the buffer is not JSON any more once a value
        // held a quote or a backslash.
        let v: &JsonLogView = self.table.get(&h).unwrap();
        v.to_json()
    }

    fn has(&mut self, h: Resource<JsonLogView>, path: String) -> bool {
        let present = {
            let v: &JsonLogView = match self.table.get(&h) {
                Ok(v) => v,
                Err(_) => return false,
            };
            v.lookup(&path).is_some()
        };
        present
    }

    fn get(&mut self, h: Resource<JsonLogView>, path: String) -> Option<log::Scalar> {
        let v: &JsonLogView = self.table.get(&h).ok()?;
        v.lookup(&path).and_then(JsonLogView::to_scalar)
    }

    fn len(&mut self, h: Resource<JsonLogView>, path: String) -> Option<u32> {
        let v: &JsonLogView = self.table.get(&h).ok()?;
        let item = v.lookup(&path)?;

        if item.is_array() {
            return Some(item.as_array().unwrap().len() as u32);
        }

        if item.is_str() {
            return Some(item.as_str().unwrap().len() as u32);
        }

        return None;
    }

    fn get_list(&mut self, h: Resource<JsonLogView>, path: String) -> Option<Vec<log::Scalar>> {
        let v: &JsonLogView = self.table.get(&h).ok()?;
        v.lookup(&path)?
            .as_array()
            .map(|arr| arr.iter().filter_map(JsonLogView::to_scalar).collect())
    }

    fn get_map(
        &mut self,
        h: Resource<JsonLogView>,
        path: String,
    ) -> Option<Vec<(String, log::Scalar)>> {
        let v: &JsonLogView = self.table.get(&h).ok()?;
        v.lookup(&path)?.as_object().map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| JsonLogView::to_scalar(v).map(|s| (k.to_string(), s)))
                .collect::<Vec<(String, log::Scalar)>>()
        })
    }

    fn keys(&mut self, h: Resource<JsonLogView>, path: String) -> Vec<String> {
        let out = {
            let v: &JsonLogView = match self.table.get(&h) {
                Ok(v) => v,
                Err(_) => return vec![],
            };
            v.lookup(&path)
                .and_then(|vv| {
                    vv.as_object()
                        .map(|m| m.keys().map(|k| k.to_string()).collect())
                })
                .unwrap_or_default()
        };
        out
    }

    fn drop(&mut self, h: Resource<JsonLogView>) -> wasmtime::Result<()> {
        let _ = self.table.delete(h)?;
        Ok(())
    }
}

impl HasData for HostEngine {
    type Data<'a> = &'a mut Self;
}

impl log::Host for HostEngine {}

#[cfg(test)]
mod tests {
    use super::*;

    /// simd-json parses in place: a de-escaped string is written over the
    /// input, so the bytes a view was parsed from are not JSON any more once
    /// a value held a quote or a backslash. `log()` encodes the tree again.
    #[test]
    fn a_record_with_an_escaped_quote_round_trips_through_the_view() {
        let input = br#"{"why":"he said \"hi\"","flag":true}"#;
        let view = JsonLogView::from_bytes(BytesMut::from(&input[..])).unwrap();
        let again: serde_json::Value = serde_json::from_str(&view.to_json()).unwrap();
        assert_eq!(again["why"], "he said \"hi\"");
        assert_eq!(again["flag"], true);
    }
    use tangent::logs::{remote::Host as _, state::Host as _};

    fn guest(store: &Arc<dyn StateStore>) -> HostEngine {
        HostEngine::new(
            wasmtime_wasi::WasiCtxBuilder::new().build(),
            Arc::clone(store),
            Arc::from("baseline"),
            tangent_shared::runtime::StateConfig::default().max_ttl_ms,
            Arc::new(HashMap::default()),
            Arc::new(Tables::default()),
            None,
            Nodes::default(),
            Default::default(),
            true,
        )
    }

    /// `lake.query`: the plugin's `tables` and its own views, read and
    /// nothing else; and no table for a plugin whose config names none.
    #[tokio::test]
    async fn a_plugin_queries_its_tables_and_only_reads() {
        use tangent::logs::lake::{Host as _, Statement};
        let lake = crate::query::tests::lake();
        let tmp = tempfile::tempdir().unwrap();
        let store = sqlite(tmp.path());
        let statement = |sql: &str| Statement {
            views: vec![("records".into(), "SELECT program, pid FROM lake".into())],
            sql: sql.into(),
            max_rows: 10,
            json: true,
            max_cell: 100,
            timeout_ms: None,
        };
        let mut g = guest(&store);
        g.lake = Some(Arc::new(Lake {
            tables: vec![format!("lake={}", lake.path().join("logs").display())],
            sinks: Vec::new(),
        }));
        let rows = g
            .query(statement("SELECT count(*) AS n FROM records"))
            .await
            .unwrap();
        assert_eq!(rows.trim(), r#"{"n":3}"#);
        let e = g
            .query(statement("CREATE TABLE mine AS SELECT 1"))
            .await
            .unwrap_err();
        assert!(e.contains("DDL"), "{e}");
        // not while a transaction holds the state
        g.begin().await.unwrap();
        let e = g.query(statement("SELECT 1")).await.unwrap_err();
        assert!(e.contains("transaction"), "{e}");
        g.rollback();

        let e = guest(&store)
            .query(statement("SELECT 1"))
            .await
            .unwrap_err();
        assert!(e.contains("no `tables`"), "{e}");
    }

    /// `lake.query` over a table its sink keeps: every record the sink has
    /// acknowledged, each once, wherever its WAL file is on the way to the
    /// lake.
    mod unsealed {
        use super::*;
        use crate::sinks::manager::SinkWrite;
        use crate::sinks::rolling_file::RollingFileSink;
        use crate::sinks::s3::S3SinkItem;
        use crate::sinks::wal::{DurableFileSink, WALSink};
        use std::path::Path;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        use tangent::logs::lake::{Host as _, Statement};
        use tangent_shared::sinks::common::{Compression, Encoding};
        use tokio::sync::Semaphore;

        /// The directory below the lake's root every record here goes to.
        const HOUR: &str = "2026/11/12/10";

        /// 49 bytes with its line break, 50 from the tenth.
        fn line(n: usize) -> String {
            format!(
                r#"{{"n":{n},"host":"web-{}.example.com","org":"acme"}}"#,
                n % 3
            )
        }

        /// A rolling_file sink of Parquet: its files under `root/out`, its
        /// WAL in `root/wal`, sealed only by `max_bytes` or a flush.
        async fn sink(
            root: &Path,
            far: Arc<dyn WALSink>,
            max_bytes: usize,
            in_flight: usize,
        ) -> Arc<DurableFileSink> {
            DurableFileSink::new(
                far,
                root.join("wal"),
                in_flight,
                max_bytes,
                Duration::from_secs(3600),
                Compression::Zstd { level: 3 },
                Encoding::Parquet {
                    schema: serde_yaml::from_str("{ n: int, host: string }").unwrap(),
                    record_column: Some("record".into()),
                },
            )
            .await
            .unwrap()
        }

        fn files_to(root: &Path) -> Arc<dyn WALSink> {
            Arc::new(RollingFileSink::new(root.join("out")))
        }

        /// Record `n`, acknowledged when this returns.
        async fn write(sink: &DurableFileSink, n: usize) {
            let write = SinkWrite {
                sink_name: Arc::from("lake"),
                payload: BytesMut::from(format!("{}\n", line(n)).as_str()),
                s3: Some(S3SinkItem {
                    bucket_name: Arc::from(""),
                    key_prefix: Some(Arc::from(HOUR)),
                }),
            };
            sink.write(write).await.unwrap();
        }

        /// A plugin whose table `lake` is the sink's, as `dag::load` gives
        /// it one.
        fn plugin(root: &Path, sink: &Arc<DurableFileSink>) -> HostEngine {
            let store: Arc<dyn StateStore> = Arc::new(
                crate::state::lru::LruStore::new(tangent_shared::runtime::StateConfig::default())
                    .unwrap(),
            );
            let mut g = guest(&store);
            g.lake = Some(Arc::new(Lake {
                tables: vec![format!("lake={}", root.join("out").display())],
                sinks: vec![("lake".into(), Arc::clone(sink) as Arc<dyn Sink>)],
            }));
            g
        }

        async fn rows(g: &mut HostEngine, sql: &str) -> Result<Vec<JSONValue>, String> {
            let statement = Statement {
                views: vec![("records".into(), "SELECT n, host, record FROM lake".into())],
                sql: sql.into(),
                max_rows: 1_000_000,
                json: true,
                max_cell: 100,
                timeout_ms: None,
            };
            let out = g.query(statement).await?;
            Ok(out
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect())
        }

        /// Every `n` in the table, in order.
        async fn ns(g: &mut HostEngine) -> Vec<u64> {
            let rows = rows(g, "SELECT n FROM records ORDER BY n").await.unwrap();
            rows.iter().map(|r| r["n"].as_u64().unwrap()).collect()
        }

        fn upto(n: u64) -> Vec<u64> {
            (0..n).collect()
        }

        /// The names in `dir` and below it, sorted; none if it is not there.
        fn names(dir: &Path) -> Vec<String> {
            let mut dirs = vec![dir.to_path_buf()];
            let mut names = Vec::new();
            while let Some(dir) = dirs.pop() {
                for e in std::fs::read_dir(&dir).into_iter().flatten() {
                    let e = e.unwrap();
                    match e.path().is_dir() {
                        true => dirs.push(e.path()),
                        false => names.push(e.file_name().into_string().unwrap()),
                    }
                }
            }
            names.sort();
            names
        }

        fn ending(names: &[String], end: &str) -> usize {
            names.iter().filter(|n| n.ends_with(end)).count()
        }

        async fn until(what: &str, mut holds: impl FnMut() -> bool) {
            let mut waited = Duration::ZERO;
            while !holds() {
                assert!(waited < Duration::from_secs(10), "waited 10 s for {what}");
                tokio::time::sleep(Duration::from_millis(5)).await;
                waited += Duration::from_millis(5);
            }
        }

        /// A rolling_file sink's far side, held at its two ends: a permit of
        /// `place` puts one Parquet file in the lake, and a permit of `back`
        /// then returns to the WAL, which removes its own file.
        struct Held {
            far: RollingFileSink,
            place: Semaphore,
            back: Semaphore,
            /// files that have come to be placed, and files placed
            came: AtomicUsize,
            placed: AtomicUsize,
        }

        impl Held {
            fn at(root: &Path) -> Arc<Self> {
                Arc::new(Self {
                    far: RollingFileSink::new(root.join("out")),
                    place: Semaphore::new(0),
                    back: Semaphore::new(0),
                    came: AtomicUsize::new(0),
                    placed: AtomicUsize::new(0),
                })
            }

            fn let_go(&self) {
                self.place.add_permits(1000);
                self.back.add_permits(1000);
            }
        }

        #[async_trait::async_trait]
        impl WALSink for Held {
            async fn write_path_with(
                &self,
                path: &Path,
                name: &str,
                encoding: &Encoding,
                compression: &Compression,
                meta: &S3SinkItem,
            ) -> Result<()> {
                self.came.fetch_add(1, Ordering::SeqCst);
                self.place.acquire().await?.forget();
                self.far
                    .write_path_with(path, name, encoding, compression, meta)
                    .await?;
                self.placed.fetch_add(1, Ordering::SeqCst);
                self.back.acquire().await?.forget();
                Ok(())
            }
        }

        /// A record in the sink's open file, in no Parquet file, is the
        /// table's, and so is a table with no file and no record at all;
        /// and the read leaves the lake and the WAL as they were.
        #[tokio::test]
        async fn a_record_not_yet_sealed_is_in_the_table() {
            let tmp = tempfile::tempdir().unwrap();
            let sink = sink(tmp.path(), files_to(tmp.path()), 1 << 20, 4).await;
            let mut g = plugin(tmp.path(), &sink);

            // no file and no record: a table of the sink's columns, empty
            assert!(!tmp.path().join("out").exists());
            let none = rows(&mut g, "SELECT n, host, record FROM lake WHERE n > 0").await;
            assert_eq!(none.unwrap(), Vec::<JSONValue>::new());
            let count = rows(&mut g, "SELECT count(*) AS n FROM records").await;
            assert_eq!(count.unwrap(), [serde_json::json!({"n": 0})]);

            write(&sink, 0).await;
            write(&sink, 1).await;
            let wal_before = names(&tmp.path().join("wal"));
            let got = rows(&mut g, "SELECT n, host, record FROM lake ORDER BY n").await;
            assert_eq!(
                got.unwrap(),
                [
                    serde_json::json!({"n": 0, "host": "web-0.example.com", "record": line(0)}),
                    serde_json::json!({"n": 1, "host": "web-1.example.com", "record": line(1)}),
                ]
            );
            // nothing sealed, nothing written
            assert_eq!(names(&tmp.path().join("wal")), wal_before);
            assert_eq!(ending(&wal_before, ".bin"), 1, "{wal_before:?}");
            assert!(!tmp.path().join("out").exists());

            sink.flush().await.unwrap();
            assert_eq!(ns(&mut g).await, upto(2));
            assert_eq!(names(&tmp.path().join("wal")), Vec::<String>::new());
        }

        /// The same records once, as their files go from open to sealed and
        /// waiting, to encoded, to in place with the WAL's file still
        /// there, to gone from the WAL.
        #[tokio::test]
        async fn each_record_once_wherever_its_file_is_on_the_way() {
            let tmp = tempfile::tempdir().unwrap();
            let (out, wal) = (tmp.path().join("out"), tmp.path().join("wal"));
            let held = Held::at(tmp.path());
            // a file holds three records, and one file is sent at a time
            let sink = sink(tmp.path(), held.clone(), 160, 1).await;
            let mut g = plugin(tmp.path(), &sink);

            // open
            for n in 0..3 {
                write(&sink, n).await;
            }
            assert_eq!(ending(&names(&wal), ".bin"), 1);
            assert_eq!(ns(&mut g).await, upto(3));

            // The fourth seals the first file and opens a second. The first
            // is encoded, and held before it is put in place.
            write(&sink, 3).await;
            until("the first file to be encoded", || {
                held.came.load(Ordering::SeqCst) == 1
            })
            .await;
            let in_wal = names(&wal);
            assert_eq!(ending(&in_wal, ".bin.sealed"), 1, "{in_wal:?}");
            assert_eq!(ending(&in_wal, ".parquet"), 1, "encoded: {in_wal:?}");
            assert_eq!(ending(&in_wal, ".bin"), 1, "the second: {in_wal:?}");
            assert_eq!(names(&out), Vec::<String>::new());
            assert_eq!(ns(&mut g).await, upto(4));

            // The fifth and sixth fill the second file, and the seventh
            // seals it: sealed, it waits for the one send there may be, and
            // so does the write that sealed it, which is not acknowledged.
            write(&sink, 4).await;
            write(&sink, 5).await;
            let seventh = {
                let sink = sink.clone();
                tokio::spawn(async move { write(&sink, 6).await })
            };
            until("the second file to be sealed", || {
                ending(&names(&wal), ".bin.sealed") == 2
            })
            .await;
            let in_wal = names(&wal);
            assert_eq!(ending(&in_wal, ".bin"), 0, "{in_wal:?}");
            assert_eq!(ending(&in_wal, ".parquet"), 1, "{in_wal:?}");
            assert_eq!(ns(&mut g).await, upto(6));
            // a file half encoded, as the second will be: it is no table's
            let second = in_wal.iter().rfind(|n| n.ends_with(".bin.sealed")).unwrap();
            let half = wal.join(second.replace(".bin.sealed", ".parquet.tmp"));
            std::fs::write(&half, b"PAR1 and no more").unwrap();
            assert_eq!(ns(&mut g).await, upto(6));
            std::fs::remove_file(&half).unwrap();

            // The first file is put in place, and its WAL file is still
            // there: the three records are in both.
            held.place.add_permits(1);
            until("the first file to be in place", || {
                held.placed.load(Ordering::SeqCst) == 1
            })
            .await;
            assert_eq!(ending(&names(&out), ".parquet"), 1);
            assert_eq!(ending(&names(&wal), ".bin.sealed"), 2);
            assert_eq!(ns(&mut g).await, upto(6));
            // as a copy from another filesystem is, before its rename
            let copying = out.join(HOUR).join(".01KOTHERFILESYSTEM.parquet.tmp");
            std::fs::write(&copying, b"PAR1 and no more").unwrap();
            assert_eq!(ns(&mut g).await, upto(6));
            std::fs::remove_file(&copying).unwrap();

            // The WAL removes the first file. The second is encoded and
            // held, and the seventh record is acknowledged, in a third.
            held.back.add_permits(1);
            seventh.await.unwrap();
            until("the second file to be encoded", || {
                held.came.load(Ordering::SeqCst) == 2
            })
            .await;
            let in_wal = names(&wal);
            assert_eq!(ending(&in_wal, ".bin.sealed"), 1, "{in_wal:?}");
            assert_eq!(ending(&in_wal, ".bin"), 1, "{in_wal:?}");
            assert_eq!(ns(&mut g).await, upto(7));

            // all in place, and nothing left in the WAL
            held.let_go();
            sink.flush().await.unwrap();
            assert_eq!(names(&wal), Vec::<String>::new());
            assert_eq!(ending(&names(&out), ".parquet"), 3);
            assert_eq!(ns(&mut g).await, upto(7));
        }

        /// What a process killed before its flush left open is sealed at
        /// the next start, cut back to its last whole line: its records are
        /// the table's once while they are sent. And a file a process put
        /// in place and was killed before removing from the WAL is sent
        /// again: its records are in both until it is, and read once.
        #[tokio::test]
        async fn each_record_once_across_a_restart() {
            let tmp = tempfile::tempdir().unwrap();
            let (out, wal) = (tmp.path().join("out"), tmp.path().join("wal"));
            let first = sink(tmp.path(), files_to(tmp.path()), 1 << 20, 4).await;
            for n in 0..3 {
                write(&first, n).await;
            }
            // killed, in the middle of a write it never acknowledged
            first.stop_without_flush().await;
            drop(first);
            let open = names(&wal).into_iter().find(|n| n.ends_with(".bin"));
            let open = wal.join(open.unwrap());
            let mut torn = std::fs::OpenOptions::new()
                .append(true)
                .open(&open)
                .unwrap();
            std::io::Write::write_all(&mut torn, br#"{"n":99,"host":"web-"#).unwrap();
            drop(torn);

            let held = Held::at(tmp.path());
            let second = sink(tmp.path(), held.clone(), 1 << 20, 4).await;
            let mut g = plugin(tmp.path(), &second);
            until("the file left open to be sent", || {
                held.came.load(Ordering::SeqCst) == 1
            })
            .await;
            assert_eq!(ending(&names(&wal), ".bin.sealed"), 1);
            assert_eq!(names(&out), Vec::<String>::new());
            assert_eq!(ns(&mut g).await, upto(3));
            write(&second, 3).await;
            assert_eq!(ns(&mut g).await, upto(4));

            // in place, and kept from the WAL's removing: the files a kill
            // here would leave, put by for the next start
            held.place.add_permits(1);
            until("the file to be in place", || {
                held.placed.load(Ordering::SeqCst) == 1
            })
            .await;
            assert_eq!(ns(&mut g).await, upto(4));
            let in_wal = names(&wal);
            let sealed = in_wal.iter().find(|n| n.ends_with(".bin.sealed")).unwrap();
            let left = [sealed.clone(), sealed.replace(".bin.sealed", ".meta")];
            for name in &left {
                std::fs::copy(wal.join(name), tmp.path().join(name)).unwrap();
            }
            held.let_go();
            second.flush().await.unwrap();
            drop(second);
            assert_eq!(names(&wal), Vec::<String>::new());
            for name in &left {
                std::fs::rename(tmp.path().join(name), wal.join(name)).unwrap();
            }

            let held = Held::at(tmp.path());
            let third = sink(tmp.path(), held.clone(), 1 << 20, 4).await;
            let mut g = plugin(tmp.path(), &third);
            until("the file left sealed to be sent again", || {
                held.came.load(Ordering::SeqCst) == 1
            })
            .await;
            assert_eq!(ending(&names(&out), ".parquet"), 2);
            assert_eq!(ns(&mut g).await, upto(4), "in the lake and in the WAL");
            held.let_go();
            third.flush().await.unwrap();
            assert_eq!(ending(&names(&out), ".parquet"), 2, "the same file again");
            assert_eq!(ns(&mut g).await, upto(4));
        }

        /// A write in progress is not seen, in part or whole: what is in
        /// the open file past the length acknowledged is no record yet.
        #[tokio::test]
        async fn a_write_in_progress_is_not_seen() {
            let tmp = tempfile::tempdir().unwrap();
            let sink = sink(tmp.path(), files_to(tmp.path()), 1 << 20, 4).await;
            let mut g = plugin(tmp.path(), &sink);
            write(&sink, 0).await;
            write(&sink, 1).await;
            assert_eq!(ns(&mut g).await, upto(2));
            let wal = tmp.path().join("wal");
            let open = names(&wal).into_iter().find(|n| n.ends_with(".bin"));
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(wal.join(open.unwrap()))
                .unwrap();
            let acknowledged = file.metadata().unwrap().len();
            // a write of two records, as far as its first, then into its second
            for part in [
                format!("{}\n", line(7)),
                r#"{"n":8,"host":"web-2.exa"#.into(),
            ] {
                std::io::Write::write_all(&mut file, part.as_bytes()).unwrap();
                assert_eq!(ns(&mut g).await, upto(2), "after {part:?}");
                let records = rows(&mut g, "SELECT record FROM lake").await.unwrap();
                assert_eq!(records.len(), 2, "{records:?}");
            }
            // it fails, and the sink cuts the file back: the next write is
            // seen once it is acknowledged, and nothing of the failed one
            file.set_len(acknowledged).unwrap();
            write(&sink, 2).await;
            assert_eq!(ns(&mut g).await, upto(3));
        }

        /// Two writers, to two directories, files sealed and sent all the
        /// while, and queries throughout: each sees every record
        /// acknowledged before it began, none twice, and none that was not
        /// yet written.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn queries_beside_writers_see_what_was_acknowledged_once() {
            const EACH: usize = 600;
            let tmp = tempfile::tempdir().unwrap();
            // some eight records a file
            let sink = sink(tmp.path(), files_to(tmp.path()), 400, 4).await;
            let mut g = plugin(tmp.path(), &sink);
            let (begun, acked) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
            let writers: Vec<_> = ["2026/11/12/10", "2026/11/12/11"]
                .into_iter()
                .enumerate()
                .map(|(w, hour)| {
                    let (sink, begun, acked) = (sink.clone(), begun.clone(), acked.clone());
                    tokio::spawn(async move {
                        for i in 0..EACH {
                            let write = SinkWrite {
                                sink_name: Arc::from("lake"),
                                payload: BytesMut::from(
                                    format!("{}\n", line(w * EACH + i)).as_str(),
                                ),
                                s3: Some(S3SinkItem {
                                    bucket_name: Arc::from(""),
                                    key_prefix: Some(Arc::from(hour)),
                                }),
                            };
                            begun.fetch_add(1, Ordering::SeqCst);
                            sink.write(write).await.unwrap();
                            acked.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_micros(500)).await;
                        }
                    })
                })
                .collect();

            let sql = "SELECT count(*) AS n, count(DISTINCT n) AS different FROM lake";
            let mut queries = 0;
            let mut last = 0;
            while writers.iter().any(|w| !w.is_finished()) {
                let before = acked.load(Ordering::SeqCst);
                let got = rows(&mut g, sql).await.unwrap();
                let after = begun.load(Ordering::SeqCst);
                let n = got[0]["n"].as_u64().unwrap() as usize;
                assert!(before <= n, "{n} of the {before} acknowledged before it");
                assert!(n <= after, "{n} of the {after} begun by its end");
                assert_eq!(got[0]["different"], n, "a record twice");
                assert!(last <= n, "{n} after {last}");
                last = n;
                queries += 1;
            }
            for w in writers {
                w.await.unwrap();
            }
            assert!(queries > 3, "{queries} queries beside the writers");
            // files in the lake, files on their way and a file open
            assert_eq!(ns(&mut g).await, upto(2 * EACH as u64));
            sink.flush().await.unwrap();
            assert!(ending(&names(&tmp.path().join("out")), ".parquet") > 100);
            assert_eq!(ns(&mut g).await, upto(2 * EACH as u64));
        }

        /// What holds the unsealed records for a statement is no more a
        /// statement's to name than a file is.
        #[tokio::test]
        async fn a_statement_reaches_nothing_new() {
            let tmp = tempfile::tempdir().unwrap();
            let sink = sink(tmp.path(), files_to(tmp.path()), 160, 4).await;
            let mut g = plugin(tmp.path(), &sink);
            for n in 0..4 {
                write(&sink, n).await;
            }
            sink.flush().await.unwrap();
            write(&sink, 4).await;
            assert_eq!(ns(&mut g).await, upto(5));
            let wal = tmp.path().join("wal");
            let open = names(&wal).into_iter().find(|n| n.ends_with(".bin"));
            let open = wal.join(open.unwrap());
            let object = open.file_name().unwrap().to_str().unwrap();
            let object = object.replace(".bin", ".parquet");
            for sql in [
                "SELECT * FROM 'unsealed://0/'".to_string(),
                "SELECT * FROM 'unsealed://0/0/'".to_string(),
                format!("SELECT * FROM \"unsealed://0/0/0/{object}\""),
                format!("SELECT * FROM '0/0/{object}'"),
                format!("SELECT * FROM '{}'", open.display()),
                format!("SELECT * FROM '{}'", wal.display()),
                "CREATE EXTERNAL TABLE t STORED AS PARQUET LOCATION 'unsealed://0/'".to_string(),
                "COPY lake TO 'unsealed://0/x.parquet'".to_string(),
                format!("COPY lake TO '{}/x.parquet'", tmp.path().display()),
                "SELECT * FROM unsealed".to_string(),
                "SELECT * FROM lake.unsealed".to_string(),
                "SELECT * FROM information_schema.tables".to_string(),
                // nor is it shown where a row is read from
                "EXPLAIN SELECT n FROM lake".to_string(),
                "EXPLAIN ANALYZE SELECT n FROM lake WHERE n = 4".to_string(),
            ] {
                let got = rows(&mut g, &sql).await;
                assert!(got.is_err(), "{sql} ran: {got:?}");
            }
            // the tables and views a statement finds are the plugin's two
            assert_eq!(ns(&mut g).await, upto(5));
            assert!(!tmp.path().join("x.parquet").exists());
        }
    }

    /// `model.chat` reaches the nodes the plugin's `inference` names, and no other.
    #[tokio::test]
    async fn a_plugin_talks_only_to_its_inference_nodes() {
        use tangent::logs::model::Host as _;
        let tmp = tempfile::tempdir().unwrap();
        let store = sqlite(tmp.path());
        let e = guest(&store)
            .chat("judge".into(), r#"{"messages": []}"#.into())
            .await
            .unwrap_err();
        assert!(e.contains("not among this plugin's `inference`"), "{e}");
    }

    /// A turn whose model is not reached marks the call unanswered, for a
    /// plugin with `attempts` to be given its records again.
    #[tokio::test]
    async fn a_turn_whose_model_is_not_reached_marks_the_call_unanswered() {
        use crate::inference::stub;
        use tangent::logs::model::Host as _;
        let dir = stub::dir("chat-unreached");
        // nothing listens here
        let nodes = stub::config("http://127.0.0.1:9/v1")
            .nodes("reviewer", &dir)
            .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let store = sqlite(tmp.path());
        let mut on = guest(&store);
        on.models = nodes;
        on.disable_remote_calls = false;
        assert!(!on.take_unreached());
        let request = r#"{"messages": [{"role": "user", "text": "hello"}]}"#;
        on.chat("reviewer".into(), request.into())
            .await
            .unwrap_err();
        assert!(!on.take_cut(), "not the stop's doing");
        assert!(on.take_unreached(), "the call is marked, once");
        assert!(!on.take_unreached());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A stop ends a turn the model has not answered, and a runtime told to
    /// call nothing outside does not ask the model.
    #[tokio::test]
    async fn a_turn_ends_at_a_stop_and_is_not_asked_with_remote_calls_off() {
        use crate::inference::stub;
        use tangent::logs::model::Host as _;
        let (url, taken) = stub::silent().await;
        let dir = stub::dir("chat-stop");
        let nodes = stub::config(&url).nodes("reviewer", &dir).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let store = sqlite(tmp.path());
        let request = r#"{"messages": [{"role": "user", "text": "hello"}]}"#;

        let mut off = guest(&store);
        off.models = Arc::clone(&nodes);
        let e = off.chat("reviewer".into(), request.into()).await;
        assert!(e.unwrap_err().contains("disable_remote_calls"));
        assert_eq!(taken.load(std::sync::atomic::Ordering::SeqCst), 0);

        let mut on = guest(&store);
        on.models = nodes;
        on.disable_remote_calls = false;
        on.stop.end();
        assert!(!on.take_cut());
        let e = on.chat("reviewer".into(), request.into()).await;
        assert_eq!(e.unwrap_err(), "tangent is stopping: the turn was not sent");
        assert!(on.take_cut(), "the call is marked cut, once");
        assert!(!on.take_cut());
        assert_eq!(taken.load(std::sync::atomic::Ordering::SeqCst), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn sqlite(dir: &std::path::Path) -> Arc<dyn StateStore> {
        Arc::new(crate::state::sqlite::SqliteStore::open(&Default::default(), dir).unwrap())
    }

    /// Whether a call on `store` from elsewhere gets through within 50 ms.
    async fn free(store: &Arc<dyn StateStore>) -> bool {
        let store = Arc::clone(store);
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            tokio::spawn(async move { store.get("baseline", "x").await.unwrap() }),
        )
        .await
        .is_ok()
    }

    /// Eight instances of a plugin, as on eight workers, each call reading a
    /// count and writing it back one higher inside a transaction: none of
    /// the 200 is lost.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_transaction_holds_a_read_and_its_write_across_workers() {
        let dir = tempfile::tempdir().unwrap();
        let store = sqlite(dir.path());
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    let mut g = guest(&store);
                    for _ in 0..25 {
                        g.begin().await.unwrap();
                        let n = match g.get("count".into()).await.unwrap() {
                            Some(Scalar::Int(n)) => n,
                            _ => 0,
                        };
                        tokio::task::yield_now().await;
                        g.set("count".into(), Scalar::Int(n + 1), None)
                            .await
                            .unwrap();
                        g.commit().await.unwrap();
                        assert!(!g.end_call(), "nothing left open");
                    }
                })
            })
            .collect();
        for w in workers {
            w.await.unwrap();
        }
        assert_eq!(
            store.get("baseline", "count").await.unwrap(),
            Some(StateValue::Int(200))
        );
    }

    /// Without `begin`, each state call lands at once and holds nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn without_a_transaction_each_call_stands_alone() {
        let dir = tempfile::tempdir().unwrap();
        let store = sqlite(dir.path());
        let mut g = guest(&store);
        g.set("a".into(), Scalar::Int(1), None).await.unwrap();
        assert!(free(&store).await);
        assert_eq!(
            store.get("baseline", "a").await.unwrap(),
            Some(StateValue::Int(1))
        );
        assert!(!g.end_call());
    }

    /// Only a commit keeps a transaction's writes: a rollback, or a call
    /// that returns with one open, undoes them and frees the store.
    #[tokio::test(flavor = "multi_thread")]
    async fn only_a_commit_keeps_a_transactions_writes() {
        let dir = tempfile::tempdir().unwrap();
        let store = sqlite(dir.path());
        let mut g = guest(&store);
        g.begin().await.unwrap();
        g.set("a".into(), Scalar::Int(1), None).await.unwrap();
        g.rollback();
        assert_eq!(store.get("baseline", "a").await.unwrap(), None);

        g.begin().await.unwrap();
        g.set("b".into(), Scalar::Int(2), None).await.unwrap();
        assert!(!free(&store).await, "an open transaction holds the store");
        assert!(g.end_call(), "left open");
        assert!(free(&store).await);
        assert_eq!(store.get("baseline", "b").await.unwrap(), None);
    }

    /// `max_ttl_ms` (an hour by default) caps a plugin's TTL, not the
    /// runtime's: google_workspace's poller remembers each event it sent for
    /// three times its hour of lateness, as long as its polls read it.
    #[tokio::test(flavor = "multi_thread")]
    async fn max_ttl_ms_caps_a_plugins_ttl_and_not_a_pollers() {
        const HOUR: u64 = 3_600_000;
        let dir = tempfile::tempdir().unwrap();
        let store = sqlite(dir.path());
        let at = crate::state::now_ms();
        store
            .set(
                crate::sources::poll::SOURCES_NS,
                "google_workspace:seen:a",
                &StateValue::Bool(true),
                Some(3 * HOUR),
            )
            .await
            .unwrap();
        guest(&store)
            .set("a".into(), Scalar::Boolean(true), Some(3 * HOUR))
            .await
            .unwrap();
        // Each write's TTL, give or take the milliseconds since `at`.
        let ttl = |ns: &'static str| {
            let store = Arc::clone(&store);
            async move {
                let rows = store.scan(Some(ns), "", 1).await.unwrap();
                rows[0].expires_at_ms.unwrap() - at
            }
        };
        let poller = ttl(crate::sources::poll::SOURCES_NS).await;
        assert!(
            (3 * HOUR..3 * HOUR + 60_000).contains(&poller),
            "the poller's: {poller} ms"
        );
        let plugin = ttl("baseline").await;
        assert!(
            (HOUR..HOUR + 60_000).contains(&plugin),
            "the plugin's: {plugin} ms"
        );
    }

    /// Inside a transaction a second `begin` and a remote call fail, and a
    /// commit needs one to commit.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_transaction_refuses_a_second_begin_and_a_remote_call() {
        let dir = tempfile::tempdir().unwrap();
        let store = sqlite(dir.path());
        let mut g = guest(&store);
        assert!(g.commit().await.is_err(), "nothing to commit");
        g.begin().await.unwrap();
        assert!(g.begin().await.is_err());
        assert!(g.call_batch(Vec::new()).await.is_err());
        g.commit().await.unwrap();
        assert!(g.call_batch(Vec::new()).await.is_ok());
    }
}
