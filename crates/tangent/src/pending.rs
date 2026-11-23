//! What a stop left waiting for a model, kept for the next start.
//!
//! A run that is stopped sends no more requests ([`crate::stop::Stop`]), and
//! the records that were about to be asked about are saved here, in the
//! state store, with the node they were about to enter: an inference node's
//! unsent records, the alerts of a conversation a plugin could not finish,
//! and the groups still open in front of a grouped plugin. The next start
//! hands each back to its node before a source is read
//! ([`crate::dag::DagRuntime`]), and forgets it once it is through the DAG.
//!
//! So a record saved is delivered: its source is acked. One whose walk had
//! already reached a sink before the stop may reach it again.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use serde_json::{json, Value};
use tangent_shared::dag::NodeRef;

use crate::state::{StateStore, StateValue};
use crate::wasm::host::JsonLogView;
use crate::worker::Ack;

/// The namespace the saved records are kept in.
pub const PENDING_NS: &str = "pending";

pub struct Pending {
    store: Arc<dyn StateStore>,
    /// Tells apart what is saved in the same millisecond.
    seq: AtomicU64,
}

/// Records read back, for the node they were about to enter.
pub struct Saved {
    pub key: String,
    pub node: NodeRef,
    pub records: Vec<JsonLogView>,
}

impl Pending {
    pub fn new(store: Arc<dyn StateStore>) -> Arc<Self> {
        Arc::new(Self {
            store,
            seq: AtomicU64::new(0),
        })
    }

    /// Keeps `records` for `node`, a plugin or an inference node, until the
    /// next start. They never expire.
    pub async fn save(&self, node: &NodeRef, records: &[JsonLogView]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let (kind, name) = match node {
            NodeRef::Plugin { name } => ("plugin", name),
            NodeRef::Inference { name } => ("inference", name),
            other => bail!("{other:?} takes no saved records"),
        };
        let lines: Vec<String> = records.iter().map(JsonLogView::to_json).collect();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        // In the order saved, which is the order read back.
        let key = format!("{now:013}-{:08}", self.seq.fetch_add(1, Ordering::Relaxed));
        let value = StateValue::Json(json!({"kind": kind, "name": **name, "records": lines}));
        self.store.set(PENDING_NS, &key, &value, Some(0)).await
    }

    /// Everything saved, oldest first. An entry that cannot be read is left
    /// where it is and said.
    pub async fn saved(&self) -> Result<Vec<Saved>> {
        let entries = self
            .store
            .scan(Some(PENDING_NS), "", usize::MAX >> 1)
            .await?;
        let mut saved = Vec::with_capacity(entries.len());
        for entry in entries {
            match read(&entry.value) {
                Ok((node, records)) => saved.push(Saved {
                    key: entry.key,
                    node,
                    records,
                }),
                Err(e) => {
                    tracing::warn!(key = %entry.key, "saved records left unread: {e:#}");
                }
            }
        }
        Ok(saved)
    }

    pub async fn forget(&self, key: &str) -> Result<()> {
        self.store.del(PENDING_NS, key).await.map(|_| ())
    }
}

fn read(value: &StateValue) -> Result<(NodeRef, Vec<JsonLogView>)> {
    let StateValue::Json(v) = value else {
        bail!("not what a stop saves");
    };
    let name: Arc<str> = Arc::from(v["name"].as_str().context("no node")?);
    let node = match v["kind"].as_str() {
        Some("plugin") => NodeRef::Plugin { name },
        Some("inference") => NodeRef::Inference { name },
        kind => bail!("a node of kind {kind:?}"),
    };
    let records = v["records"]
        .as_array()
        .context("no records")?
        .iter()
        .filter_map(Value::as_str)
        .map(|line| JsonLogView::from_bytes(BytesMut::from(line)))
        .collect::<Result<_>>()?;
    Ok((node, records))
}

/// The ack of saved records handed back to their node: fired once they are
/// through the DAG, it forgets them.
pub struct Forget {
    pub pending: Arc<Pending>,
    pub key: String,
}

#[async_trait]
impl Ack for Forget {
    async fn ack(&self) -> Result<()> {
        self.pending.forget(&self.key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::lru::LruStore;
    use tangent_shared::runtime::StateConfig;

    fn rec(id: i64) -> JsonLogView {
        JsonLogView::from_bytes(format!("{{\"id\":{id}}}").as_str().into()).unwrap()
    }

    /// What is saved is read back for its node, oldest first, until it is
    /// forgotten.
    #[tokio::test]
    async fn saved_records_are_read_back_in_order_until_forgotten() {
        let store: Arc<dyn StateStore> = Arc::new(LruStore::new(StateConfig::default()).unwrap());
        let pending = Pending::new(store);
        let judge = NodeRef::Inference {
            name: Arc::from("judge"),
        };
        let review = NodeRef::Plugin {
            name: Arc::from("review"),
        };
        pending.save(&judge, &[rec(1), rec(2)]).await.unwrap();
        pending.save(&review, &[rec(3)]).await.unwrap();
        pending.save(&judge, &[]).await.unwrap();

        let saved = pending.saved().await.unwrap();
        let read: Vec<(NodeRef, Vec<String>)> = saved
            .iter()
            .map(|s| {
                (
                    s.node.clone(),
                    s.records.iter().map(JsonLogView::to_json).collect(),
                )
            })
            .collect();
        assert_eq!(
            read,
            [
                (
                    judge,
                    vec![r#"{"id":1}"#.to_string(), r#"{"id":2}"#.to_string()]
                ),
                (review, vec![r#"{"id":3}"#.to_string()]),
            ]
        );

        pending.forget(&saved[0].key).await.unwrap();
        let left = pending.saved().await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].key, saved[1].key);
    }

    /// Only a plugin and an inference node take records back.
    #[tokio::test]
    async fn a_sink_takes_no_saved_records() {
        let store: Arc<dyn StateStore> = Arc::new(LruStore::new(StateConfig::default()).unwrap());
        let sink = NodeRef::Sink {
            name: Arc::from("out"),
        };
        assert!(Pending::new(store).save(&sink, &[rec(1)]).await.is_err());
    }
}
