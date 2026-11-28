//! What the pipeline has in hand and has not yet finished with, for someone
//! watching it: the groups still open in front of a grouped plugin, and the
//! records an inference node is asking its model about.
//!
//! Each is here from the moment it begins to the moment it is over, by a
//! [`Mark`] its holder keeps: dropped, it is gone. Only the small fields of
//! a record are kept, enough to name it (a session's id and entry point),
//! so a thousand open groups are not a thousand records held twice.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use serde_json::{Map, Value};

/// Where a record is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// In an open group, which more records may join.
    Grouping,
    /// With an inference node, waiting for its model's place or its answer.
    Asking,
}

/// One thing in hand.
#[derive(Debug, Clone)]
pub struct Underway {
    pub stage: Stage,
    /// The grouped plugin, or the inference node.
    pub node: Arc<str>,
    /// The small fields of the record: of a group, its first.
    pub record: Value,
    /// How many records: a group's so far, or one.
    pub records: usize,
    pub since: SystemTime,
}

struct Held {
    stage: Stage,
    node: Arc<str>,
    record: Value,
    records: Arc<AtomicUsize>,
    since: SystemTime,
}

lazy_static::lazy_static! {
    static ref HELD: parking_lot::Mutex<HashMap<u64, Held>> = parking_lot::Mutex::new(HashMap::new());
}
static NEXT: AtomicU64 = AtomicU64::new(0);

/// Keeps its record among what is underway until it is dropped.
pub struct Mark {
    id: u64,
    records: Arc<AtomicUsize>,
}

impl Mark {
    /// One more record has joined the group.
    pub fn more(&self) {
        self.records.fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for Mark {
    fn drop(&mut self) {
        HELD.lock().remove(&self.id);
    }
}

/// `record` is in hand at `node` from now until the mark is dropped.
pub fn mark(stage: Stage, node: &Arc<str>, record: &Value) -> Mark {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let records = Arc::new(AtomicUsize::new(1));
    HELD.lock().insert(
        id,
        Held {
            stage,
            node: Arc::clone(node),
            record: small(record),
            records: Arc::clone(&records),
            since: SystemTime::now(),
        },
    );
    Mark { id, records }
}

/// Everything in hand now, in no order.
pub fn underway() -> Vec<Underway> {
    HELD.lock()
        .values()
        .map(|h| Underway {
            stage: h.stage,
            node: Arc::clone(&h.node),
            record: h.record.clone(),
            records: h.records.load(Ordering::Relaxed),
            since: h.since,
        })
        .collect()
}

/// A string kept whole is no longer than this.
const SMALL: usize = 200;

/// The record's small fields: a number, a boolean, a short string, and an
/// object of a few of those. What says which record it is, without what it
/// carries.
fn small(record: &Value) -> Value {
    let scalar = |v: &Value| match v {
        Value::String(s) => s.len() <= SMALL,
        Value::Number(_) | Value::Bool(_) => true,
        _ => false,
    };
    let Value::Object(fields) = record else {
        return Value::Null;
    };
    let mut kept = Map::new();
    for (name, v) in fields {
        match v {
            v if scalar(v) => {
                kept.insert(name.clone(), v.clone());
            }
            Value::Object(inner) if inner.len() <= 12 => {
                let inner: Map<String, Value> = inner
                    .iter()
                    .filter(|(_, v)| scalar(v))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if !inner.is_empty() {
                    kept.insert(name.clone(), Value::Object(inner));
                }
            }
            _ => {}
        }
    }
    Value::Object(kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_record_is_underway_until_its_mark_is_dropped_and_only_its_small_fields_are_kept() {
        let node: Arc<str> = Arc::from("underway-test-node");
        let mine =
            || -> Vec<Underway> { underway().into_iter().filter(|u| u.node == node).collect() };
        let record = json!({
            "session": {"id": "41", "entry": "/bin/zsh", "events": 3, "files": ["a", "b"]},
            "event": "exec",
            "transcript": "x".repeat(SMALL + 1),
            "parents": ["/sbin/launchd"],
        });
        let mark = mark(Stage::Grouping, &node, &record);
        mark.more();
        let held = mine();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].stage, Stage::Grouping);
        assert_eq!(held[0].records, 2);
        assert_eq!(
            held[0].record,
            json!({"session": {"id": "41", "entry": "/bin/zsh", "events": 3}, "event": "exec"})
        );
        drop(mark);
        assert!(mine().is_empty());
    }
}
