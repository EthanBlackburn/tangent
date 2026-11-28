//! Grouping in front of a plugin: records reaching the plugin wait in a
//! group per value of its
//! `group_by` fields, and the plugin gets a group at a time. One task per
//! grouped plugin owns its groups, so the workers that hand it records share
//! nothing.
//!
//! A group closes when it holds `max_events` records, when no record has
//! joined it for `expire_after_ms` of wall-clock time, or `max_age_ms` after
//! it opened, however often records join it; at the end of input every open
//! group closes. A closed group goes whole to the plugin's own
//! workers, and one group per key is out at a time: the next waits until the
//! last is through the DAG. With `history`, a key's latest records are kept
//! in the state store and go again, marked `"_context": true`, ahead of its
//! next group.
//!
//! A group whose walk fails at a node that could not do its work (a model
//! not reached, a call that ended unanswered) comes back: its records go
//! ahead of what its key has gathered since, and go again as one group.
//! From then until a group is through, what the groups go on to is taken
//! to be down: they stay open, gathering, and the oldest is sent each
//! `probe_every` to try it.
//!
//! Groups live in memory: records are acked once they are in one, and a
//! crash loses the groups still open, those that came back among them.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::Value;
use tangent_shared::dag::NodeRef;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::record;
use crate::state::{StateStore, StateValue};
use crate::wasm::host::JsonLogView;
use crate::worker::Ack;

/// The namespace a grouped plugin's history is kept in, under
/// `<plugin>:<group key>`.
pub const GROUPS_NS: &str = "groups";

/// How a plugin groups what reaches it.
#[derive(Clone, Debug)]
pub struct GroupConfig {
    pub group_by: Vec<String>,
    pub max_events: Option<usize>,
    pub expire_after: Duration,
    pub max_age: Option<Duration>,
    pub history: usize,
    /// While a group has failed and none has been through since, how often
    /// one is sent to try again; the rest stay open.
    pub probe_every: Duration,
}

/// How often a grouped plugin tries again while what its groups go on to
/// does not answer.
pub const PROBE_EVERY: Duration = Duration::from_secs(60);

/// How a group's walk ended.
enum Outcome {
    /// Through the DAG.
    Through,
    /// Through it with its last try's failure, which goes on as it is.
    Spent,
    /// A node could not do its work: the records go back to their key's
    /// group, to go again with what has joined since.
    Failed,
    /// Stopped by a signal, or lost to an error.
    Dropped,
}

/// A closed group on its way to the grouped plugin's workers.
pub struct Group {
    /// Where the group's walk of the DAG starts: the grouped plugin, or for
    /// records a stop saved ([`crate::pending`]) the node they were about
    /// to enter.
    pub node: NodeRef,
    /// The key's history first, marked `"_context": true`, then the group.
    pub records: Vec<JsonLogView>,
    /// How many of `records`, from the first, are the key's history.
    pub context: usize,
    /// Fires once the group is through the DAG.
    pub done: Arc<dyn Ack>,
    /// Records a stop saved, read back: `done` forgets them.
    pub saved: bool,
    /// How many times the plugin's call has been made with them and ended
    /// unanswered ([`crate::pending::Saved::tries`]).
    pub tries: usize,
}

/// Where closed groups go: the grouped plugin's worker pool.
#[async_trait]
pub trait Dispatch: Send + Sync {
    async fn dispatch(&self, group: Group) -> Result<()>;
}

enum Msg {
    Records(Vec<JsonLogView>),
    /// Close every open group.
    Close,
    /// Close every open group; answer once none is open, waiting or out.
    Flush(oneshot::Sender<()>),
    /// Hand back the records of every group open or waiting, and hold none.
    Take(oneshot::Sender<Vec<JsonLogView>>),
}

/// A grouped plugin's grouping task, as the workers hand it records.
#[derive(Clone)]
pub struct Grouper {
    /// The grouped plugin.
    pub node: Arc<str>,
    tx: mpsc::Sender<Msg>,
    held: Arc<AtomicUsize>,
}

impl Grouper {
    /// Records in groups not yet out: in an open group, or in a closed one
    /// waiting for its key's group out to be through. What grows in memory
    /// while records come faster than groups close and the plugin takes
    /// them.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Relaxed)
    }

    /// Closes every open group now, whatever its age, and does not wait for
    /// them: each goes to the plugin, or waits behind its key's group out.
    pub async fn close_open(&self) -> Result<()> {
        self.tx
            .send(Msg::Close)
            .await
            .map_err(|_| anyhow!("the grouping task is gone"))
    }

    pub async fn add(&self, records: Vec<JsonLogView>) -> Result<()> {
        self.tx
            .send(Msg::Records(records))
            .await
            .map_err(|_| anyhow!("the grouping task is gone"))
    }

    /// The records of every group not yet out, open or waiting behind its
    /// key's group out, which are held no longer: a stop saves them for the
    /// next start rather than hand the plugin groups cut short.
    pub async fn take(&self) -> Result<Vec<JsonLogView>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Msg::Take(tx))
            .await
            .map_err(|_| anyhow!("the grouping task is gone"))?;
        rx.await.map_err(|_| anyhow!("the grouping task is gone"))
    }

    /// Closes every open group and waits until each, and any group waiting
    /// behind one, is through the DAG: the end of input.
    pub async fn flush(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Msg::Flush(tx))
            .await
            .map_err(|_| anyhow!("the grouping task is gone"))?;
        rx.await.map_err(|_| anyhow!("the grouping task is gone"))
    }
}

/// Starts the grouping task for plugin `node`: closed groups go to `out`,
/// history to `store`.
pub fn spawn(
    node: Arc<str>,
    cfg: GroupConfig,
    out: Arc<dyn Dispatch>,
    store: Arc<dyn StateStore>,
) -> (Grouper, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(1024);
    let (done_tx, done_rx) = mpsc::unbounded_channel();
    let held = Arc::new(AtomicUsize::new(0));
    let task = Task {
        node,
        cfg,
        out,
        store,
        keys: HashMap::new(),
        held: Arc::clone(&held),
        done_tx,
        flushing: Vec::new(),
        down: false,
        probed: Instant::now(),
    };
    let grouper = Grouper {
        node: Arc::clone(&task.node),
        tx,
        held,
    };
    (grouper, tokio::spawn(task.run(rx, done_rx)))
}

/// A group still taking records.
struct Open {
    records: Vec<JsonLogView>,
    /// When its first record joined: `max_age` counts from here.
    opened: Instant,
    /// When its latest record joined: `expire_after` counts from here.
    last: Instant,
    /// Tells a watcher the group is open, for as long as it is.
    mark: crate::underway::Mark,
}

#[derive(Default)]
struct Key {
    open: Option<Open>,
    /// Closed groups waiting for the one out to be through.
    waiting: VecDeque<Vec<JsonLogView>>,
    /// A group of this key is on its way through the DAG.
    out: bool,
    /// How many times running a group of this key has failed: none once
    /// one is through.
    tries: usize,
}

struct Task {
    node: Arc<str>,
    cfg: GroupConfig,
    out: Arc<dyn Dispatch>,
    store: Arc<dyn StateStore>,
    keys: HashMap<Arc<str>, Key>,
    /// The records in every key's `open` and `waiting`.
    held: Arc<AtomicUsize>,
    /// Where a group's walk reports it is through, with the group's records.
    done_tx: mpsc::UnboundedSender<(Arc<str>, Vec<JsonLogView>, Outcome)>,
    flushing: Vec<oneshot::Sender<()>>,
    /// A group failed and none has been through since: what the groups go
    /// on to (a model, the lake) is taken to be down. Groups stay open,
    /// gathering, and one is sent each `probe_every` to try it.
    down: bool,
    /// When a group last failed or was sent to try.
    probed: Instant,
}

impl Task {
    async fn run(
        mut self,
        mut rx: mpsc::Receiver<Msg>,
        mut done_rx: mpsc::UnboundedReceiver<(Arc<str>, Vec<JsonLogView>, Outcome)>,
    ) {
        let mut every = self.cfg.expire_after.min(Duration::from_secs(1));
        if let Some(age) = self.cfg.max_age {
            every = every.min(age);
        }
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(Msg::Records(records)) => {
                        for r in records {
                            self.add(r).await;
                        }
                    }
                    Some(Msg::Close) => self.close_open().await,
                    Some(Msg::Take(answer)) => {
                        let _ = answer.send(self.take());
                    }
                    Some(Msg::Flush(answer)) => {
                        self.close_open().await;
                        self.flushing.push(answer);
                        self.answer_if_idle();
                    }
                    None => break,
                },
                Some((key, records, outcome)) = done_rx.recv() => self.done(key, records, outcome).await,
                _ = tick.tick() => self.expire().await,
            }
        }
    }

    /// The record's key: its `group_by` values as text.
    fn key_of(&self, r: &JsonLogView) -> Arc<str> {
        let parts: Vec<String> = self
            .cfg
            .group_by
            .iter()
            .map(|path| {
                r.lookup(path)
                    .and_then(JsonLogView::to_scalar)
                    .map(record::scalar_text)
                    .unwrap_or_default()
            })
            .collect();
        Arc::from(parts.join("\u{1f}"))
    }

    async fn add(&mut self, r: JsonLogView) {
        let key = self.key_of(&r);
        let k = self.keys.entry(Arc::clone(&key)).or_default();
        let now = Instant::now();
        let open = match &mut k.open {
            Some(open) => {
                open.mark.more();
                open
            }
            none => {
                let first = serde_json::from_str(&r.to_json()).unwrap_or_default();
                let mark =
                    crate::underway::mark(crate::underway::Stage::Grouping, &self.node, &first);
                none.insert(Open {
                    records: Vec::new(),
                    opened: now,
                    last: now,
                    mark,
                })
            }
        };
        open.records.push(r);
        open.last = now;
        self.held.fetch_add(1, Ordering::Relaxed);
        // while down a full group stays open with the rest
        if !self.down
            && self
                .cfg
                .max_events
                .is_some_and(|max| open.records.len() >= max)
        {
            self.close(key).await;
        }
    }

    /// Closes each group quiet for `expire_after`, or open for `max_age`.
    /// While down, only the oldest of them, and only each `probe_every`:
    /// the rest stay open until one is through.
    async fn expire(&mut self) {
        let cfg = &self.cfg;
        let mut due: Vec<(Instant, Arc<str>)> = self
            .keys
            .iter()
            .filter_map(|(key, k)| {
                let o = k.open.as_ref()?;
                let full = cfg.max_events.is_some_and(|max| o.records.len() >= max);
                (full
                    || o.last.elapsed() >= cfg.expire_after
                    || cfg.max_age.is_some_and(|age| o.opened.elapsed() >= age))
                .then(|| (o.opened, Arc::clone(key)))
            })
            .collect();
        if self.down {
            if due.is_empty() || self.probed.elapsed() < cfg.probe_every {
                return;
            }
            due.sort();
            due.truncate(1);
            self.probed = Instant::now();
        }
        let due = due.into_iter().map(|(_, key)| key);
        for key in due.collect::<Vec<_>>() {
            self.close(key).await;
        }
    }

    /// Every record held, in an open group or a waiting one, each key's in
    /// the order they joined; none is held after.
    fn take(&mut self) -> Vec<JsonLogView> {
        let mut records = Vec::new();
        for k in self.keys.values_mut() {
            for group in k.waiting.drain(..) {
                records.extend(group);
            }
            if let Some(open) = k.open.take() {
                records.extend(open.records);
            }
        }
        self.keys.retain(|_, k| k.out);
        self.held.fetch_sub(records.len(), Ordering::Relaxed);
        records
    }

    async fn close_open(&mut self) {
        let open: Vec<Arc<str>> = self
            .keys
            .iter()
            .filter(|(_, k)| k.open.is_some())
            .map(|(key, _)| Arc::clone(key))
            .collect();
        for key in open {
            self.close(key).await;
        }
    }

    async fn close(&mut self, key: Arc<str>) {
        let Some(k) = self.keys.get_mut(&key) else {
            return;
        };
        let Some(Open { records, .. }) = k.open.take() else {
            return;
        };
        if k.out {
            k.waiting.push_back(records);
        } else {
            self.send(key, records).await;
        }
    }

    async fn send(&mut self, key: Arc<str>, records: Vec<JsonLogView>) {
        self.held.fetch_sub(records.len(), Ordering::Relaxed);
        let mut all = self.history(&key).await;
        let context = all.len();
        all.extend(records.iter().cloned());
        let done = Arc::new(Through {
            tx: self.done_tx.clone(),
            group: Mutex::new(Some((Arc::clone(&key), records))),
            spent: std::sync::atomic::AtomicBool::new(false),
        });
        let group = Group {
            node: NodeRef::Plugin {
                name: Arc::clone(&self.node),
            },
            records: all,
            context,
            done,
            saved: false,
            tries: self.keys.get(&key).map_or(0, |k| k.tries),
        };
        // Out from here: the group's ack, fired or dropped, frees the key.
        if let Some(k) = self.keys.get_mut(&key) {
            k.out = true;
        }
        if let Err(e) = self.out.dispatch(group).await {
            tracing::warn!(plugin = %self.node, error = %e, "a group could not reach its workers; dropped");
        }
    }

    /// Records back in `key`'s open group, ahead of what it holds: a group
    /// that failed, with the closed groups that waited behind it, to go
    /// again as one with whatever joins them.
    fn reopen(&mut self, key: &Arc<str>, mut records: Vec<JsonLogView>) {
        let k = self.keys.entry(Arc::clone(key)).or_default();
        self.held.fetch_add(records.len(), Ordering::Relaxed);
        for waiting in k.waiting.drain(..) {
            records.extend(waiting);
        }
        if let Some(open) = k.open.take() {
            records.extend(open.records);
        }
        let Some(first) = records.first() else {
            return;
        };
        let first = serde_json::from_str(&first.to_json()).unwrap_or_default();
        let mark = crate::underway::mark(crate::underway::Stage::Grouping, &self.node, &first);
        for _ in 1..records.len() {
            mark.more();
        }
        let now = Instant::now();
        k.open = Some(Open {
            records,
            opened: now,
            last: now,
            mark,
        });
    }

    /// A group of `key` is through the DAG, or failed and comes back, or
    /// was dropped on the way (no records then, and nothing to remember).
    async fn done(&mut self, key: Arc<str>, records: Vec<JsonLogView>, outcome: Outcome) {
        match outcome {
            // what it went on to answers
            Outcome::Through => self.down = false,
            Outcome::Spent | Outcome::Failed => {
                self.down = true;
                self.probed = Instant::now();
            }
            Outcome::Dropped => {}
        }
        if let Some(k) = self.keys.get_mut(&key) {
            k.out = false;
            match outcome {
                Outcome::Failed => k.tries += 1,
                Outcome::Through | Outcome::Spent => k.tries = 0,
                Outcome::Dropped => {}
            }
        }
        if matches!(outcome, Outcome::Failed) {
            self.reopen(&key, records);
            self.answer_if_idle();
            return;
        }
        if !records.is_empty() {
            self.remember(&key, &records).await;
        }
        // while down the groups that waited behind it wait on, open
        if self.down && self.keys.get(&key).is_some_and(|k| !k.waiting.is_empty()) {
            self.reopen(&key, Vec::new());
        }
        let next = match self.keys.get_mut(&key) {
            Some(k) => k.waiting.pop_front(),
            None => None,
        };
        match next {
            Some(records) => self.send(Arc::clone(&key), records).await,
            None => {
                if self
                    .keys
                    .get(&key)
                    .is_some_and(|k| k.open.is_none() && !k.out)
                {
                    self.keys.remove(&key);
                }
            }
        }
        self.answer_if_idle();
    }

    fn answer_if_idle(&mut self) {
        if self.flushing.is_empty() || !self.keys.is_empty() {
            return;
        }
        for answer in self.flushing.drain(..) {
            let _ = answer.send(());
        }
    }

    fn history_key(&self, key: &str) -> String {
        format!("{}:{key}", self.node)
    }

    /// The key's history, each record marked `"_context": true`.
    async fn history(&self, key: &str) -> Vec<JsonLogView> {
        if self.cfg.history == 0 {
            return Vec::new();
        }
        let kept = match self.store.get(GROUPS_NS, &self.history_key(key)).await {
            Ok(Some(StateValue::Json(Value::Array(kept)))) => kept,
            Ok(_) => return Vec::new(),
            Err(e) => {
                tracing::warn!(plugin = %self.node, error = %e, "reading a group's history");
                return Vec::new();
            }
        };
        kept.into_iter()
            .filter_map(|mut v| {
                v.as_object_mut()?
                    .insert("_context".into(), Value::Bool(true));
                let bytes = serde_json::to_vec(&v).ok()?;
                JsonLogView::from_bytes(bytes.as_slice().into()).ok()
            })
            .collect()
    }

    /// The key's latest `history` records, the group's added: only this task
    /// writes them, so the read and the write need no transaction.
    async fn remember(&self, key: &str, records: &[JsonLogView]) {
        let n = self.cfg.history;
        if n == 0 {
            return;
        }
        let hk = self.history_key(key);
        let mut kept = match self.store.get(GROUPS_NS, &hk).await {
            Ok(Some(StateValue::Json(Value::Array(kept)))) => kept,
            _ => Vec::new(),
        };
        kept.extend(
            records
                .iter()
                .filter_map(|r| serde_json::from_str::<Value>(&r.to_json()).ok()),
        );
        if kept.len() > n {
            kept.drain(..kept.len() - n);
        }
        if let Err(e) = self
            .store
            .set(
                GROUPS_NS,
                &hk,
                &StateValue::Json(Value::Array(kept)),
                Some(0),
            )
            .await
        {
            tracing::warn!(plugin = %self.node, error = %e, "keeping a group's history");
        }
    }
}

/// A group's ack: once it is through the DAG, its key may send the next.
/// Dropped without firing (its walk was stopped by a signal, or failed),
/// it frees the key all the same, remembering nothing.
struct Through {
    tx: mpsc::UnboundedSender<(Arc<str>, Vec<JsonLogView>, Outcome)>,
    group: Mutex<Option<(Arc<str>, Vec<JsonLogView>)>>,
    /// The group goes on with its last try's failure.
    spent: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl Ack for Through {
    async fn ack(&self) -> Result<()> {
        if let Some((key, records)) = self.group.lock().take() {
            let outcome = match self.spent.load(Ordering::Relaxed) {
                true => Outcome::Spent,
                false => Outcome::Through,
            };
            let _ = self.tx.send((key, records, outcome));
        }
        Ok(())
    }

    fn regroups(&self) -> bool {
        true
    }

    async fn failed(&self, again: bool) {
        if !again {
            self.spent.store(true, Ordering::Relaxed);
        } else if let Some((key, records)) = self.group.lock().take() {
            let _ = self.tx.send((key, records, Outcome::Failed));
        }
    }
}

impl Drop for Through {
    fn drop(&mut self) {
        if let Some((key, _)) = self.group.get_mut().take() {
            let _ = self.tx.send((key, Vec::new(), Outcome::Dropped));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::lru::LruStore;
    use tangent_shared::runtime::StateConfig;

    /// Each group handed over: its records, and its ack until it is fired
    /// or dropped.
    type Handed = Vec<(Vec<Value>, Option<Arc<dyn Ack>>)>;

    /// Records the groups it is handed; acks them when told to.
    #[derive(Default)]
    struct Out {
        groups: Mutex<Handed>,
        /// How many times each had failed before, as it was handed over.
        tries: Mutex<Vec<usize>>,
    }

    #[async_trait]
    impl Dispatch for Out {
        async fn dispatch(&self, g: Group) -> Result<()> {
            let records = g
                .records
                .iter()
                .map(|r| serde_json::from_str(&r.to_json()).unwrap())
                .collect();
            self.tries.lock().push(g.tries);
            self.groups.lock().push((records, Some(g.done)));
            Ok(())
        }
    }

    impl Out {
        fn ids(&self) -> Vec<Vec<i64>> {
            self.groups
                .lock()
                .iter()
                .map(|(rs, _)| rs.iter().map(|r| r["id"].as_i64().unwrap()).collect())
                .collect()
        }
        async fn ack(&self, i: usize) {
            let done = self.groups.lock()[i].1.take().expect("not fired yet");
            done.ack().await.unwrap();
        }
        /// As a walk a node failed: the records go back, or with their
        /// tries spent go on, and the ack fires.
        async fn fail(&self, i: usize, again: bool) {
            let done = self.groups.lock()[i].1.take().expect("not fired yet");
            assert!(done.regroups());
            done.failed(again).await;
            if !again {
                done.ack().await.unwrap();
            }
        }
        /// Waits until `n` groups have been handed over.
        async fn handed(&self, n: usize) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while self.groups.lock().len() < n {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("a group is handed over");
        }
        /// As a walk a signal stopped: the ack goes, unfired.
        fn drop_ack(&self, i: usize) {
            self.groups.lock()[i].1.take();
        }
    }

    fn rec(actor: &str, id: i64) -> JsonLogView {
        let line = format!("{{\"actor\":\"{actor}\",\"id\":{id}}}");
        JsonLogView::from_bytes(line.as_str().into()).unwrap()
    }

    fn start(max: Option<usize>, expire_ms: u64, history: usize) -> (Grouper, Arc<Out>) {
        start_with(GroupConfig {
            group_by: vec!["actor".into()],
            max_events: Some(max.unwrap_or(1000)),
            expire_after: Duration::from_millis(expire_ms),
            max_age: None,
            history,
            probe_every: Duration::from_millis(60),
        })
    }

    fn start_with(cfg: GroupConfig) -> (Grouper, Arc<Out>) {
        let out = Arc::new(Out::default());
        let store: Arc<dyn StateStore> = Arc::new(LruStore::new(StateConfig::default()).unwrap());
        let (g, _task) = spawn(
            Arc::from("p"),
            cfg,
            Arc::clone(&out) as Arc<dyn Dispatch>,
            store,
        );
        (g, out)
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    /// A group that failed goes back to its key's group and goes again with
    /// what joined meanwhile. Until one is through the others stay open,
    /// and one at a time is sent to try.
    #[tokio::test]
    async fn a_failed_group_goes_again_with_what_joined_it_and_the_rest_wait() {
        let (g, out) = start_with(GroupConfig {
            group_by: vec!["actor".into()],
            max_events: None,
            expire_after: Duration::from_millis(30),
            max_age: None,
            history: 0,
            probe_every: Duration::from_millis(400),
        });
        g.add(vec![rec("a", 1), rec("a", 2)]).await.unwrap();
        out.handed(1).await;
        assert_eq!(out.ids(), [vec![1, 2]]);
        // more of a's arrive while its group is out, which then fails
        g.add(vec![rec("a", 3)]).await.unwrap();
        settle().await;
        out.fail(0, true).await;
        // b's begins after a's is back: the older of the two tries first
        settle().await;
        g.add(vec![rec("b", 5)]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(
            out.ids().len(),
            1,
            "quiet long enough to close, and held: it is down"
        );
        assert_eq!(g.held(), 4);
        // the oldest goes to try: a's, the failed records first
        out.handed(2).await;
        assert_eq!(out.ids()[1], [1, 2, 3]);
        assert_eq!(*out.tries.lock(), [0, 1], "and says it has failed once");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(out.ids().len(), 2, "b's waits for it");
        // it is through: the rest go
        out.ack(1).await;
        out.handed(3).await;
        assert_eq!(out.ids()[2], [5]);
        out.ack(2).await;
        settle().await;
        assert_eq!(g.held(), 0);
    }

    /// A group whose tries are spent goes on, and its key starts over; what
    /// it went on to is still taken to be down.
    #[tokio::test]
    async fn a_group_whose_tries_are_spent_goes_on_and_the_rest_still_wait() {
        let (g, out) = start_with(GroupConfig {
            group_by: vec!["actor".into()],
            max_events: None,
            expire_after: Duration::from_millis(30),
            max_age: None,
            history: 0,
            probe_every: Duration::from_millis(400),
        });
        g.add(vec![rec("a", 1)]).await.unwrap();
        out.handed(1).await;
        out.fail(0, false).await;
        g.add(vec![rec("b", 2)]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(out.ids(), [vec![1]], "b's is held");
        out.handed(2).await;
        assert_eq!(out.ids()[1], [2]);
        assert_eq!(*out.tries.lock(), [0, 0]);
    }

    /// A group closes at `max_events`, per key.
    #[tokio::test]
    async fn a_group_closes_when_full() {
        let (g, out) = start(Some(2), 60_000, 0);
        g.add(vec![rec("a", 1), rec("b", 2), rec("a", 3)])
            .await
            .unwrap();
        settle().await;
        assert_eq!(out.ids(), [vec![1, 3]], "b's one record waits");
    }

    /// A stop takes what is held, open or waiting behind a group out, and
    /// nothing of it goes to the plugin after.
    #[tokio::test]
    async fn a_stop_takes_the_groups_not_yet_out() {
        let (g, out) = start(Some(2), 60_000, 0);
        // a's first group goes out and its second waits behind it; b's is open
        g.add(vec![
            rec("a", 1),
            rec("a", 2),
            rec("a", 3),
            rec("a", 4),
            rec("b", 5),
        ])
        .await
        .unwrap();
        settle().await;
        assert_eq!(out.ids(), [vec![1, 2]]);
        assert_eq!(g.held(), 3);

        let mut taken: Vec<i64> = g
            .take()
            .await
            .unwrap()
            .iter()
            .map(|r| {
                r.lookup("id")
                    .and_then(JsonLogView::to_scalar)
                    .map(record::scalar_text)
            })
            .map(|id| id.unwrap().parse().unwrap())
            .collect();
        taken.sort_unstable();
        assert_eq!(taken, [3, 4, 5]);
        assert_eq!(g.held(), 0);

        out.ack(0).await;
        settle().await;
        assert_eq!(out.ids(), [vec![1, 2]], "nothing waited behind it any more");
    }

    /// A group closes once nothing has joined it for `expire_after_ms`.
    #[tokio::test]
    async fn a_quiet_group_closes() {
        let (g, out) = start(None, 50, 0);
        g.add(vec![rec("a", 1)]).await.unwrap();
        settle().await;
        assert!(out.ids().is_empty(), "not yet");
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(out.ids(), [vec![1]]);
    }

    /// A group closes `max_age_ms` after it opened, though its key never goes
    /// quiet.
    #[tokio::test]
    async fn a_busy_group_closes_at_max_age() {
        let (g, out) = start_with(GroupConfig {
            group_by: vec!["actor".into()],
            max_events: None,
            expire_after: Duration::from_secs(60),
            max_age: Some(Duration::from_millis(50)),
            history: 0,
            probe_every: Duration::from_millis(60),
        });
        for id in 1..=20 {
            g.add(vec![rec("a", id)]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let ids = out.ids();
        assert_eq!(ids.len(), 1, "the next waits for the first to be through");
        assert!(
            ids[0].len() < 20,
            "closed while records kept joining: {ids:?}"
        );
    }

    /// A key's next group waits until the last is through.
    #[tokio::test]
    async fn one_group_per_key_is_out() {
        let (g, out) = start(Some(1), 60_000, 0);
        g.add(vec![rec("a", 1), rec("a", 2), rec("b", 3)])
            .await
            .unwrap();
        settle().await;
        assert_eq!(out.ids(), [vec![1], vec![3]], "a's second waits");
        out.ack(0).await;
        settle().await;
        assert_eq!(out.ids(), [vec![1], vec![3], vec![2]]);
    }

    /// A key's history goes ahead of its next group, marked as context, and
    /// holds only the latest `history` records.
    #[tokio::test]
    async fn history_comes_back_as_context() {
        let (g, out) = start(Some(2), 60_000, 3);
        g.add(vec![rec("a", 1), rec("a", 2)]).await.unwrap();
        settle().await;
        out.ack(0).await;
        g.add(vec![rec("a", 3), rec("a", 4)]).await.unwrap();
        settle().await;
        out.ack(1).await;
        g.add(vec![rec("a", 5), rec("a", 6)]).await.unwrap();
        settle().await;
        assert_eq!(
            out.ids(),
            [vec![1, 2], vec![1, 2, 3, 4], vec![2, 3, 4, 5, 6]]
        );
        let groups = out.groups.lock();
        let last = &groups[2].0;
        assert!(last[..3].iter().all(|r| r["_context"] == true), "{last:?}");
        assert!(last[3..].iter().all(|r| r.get("_context").is_none()));
    }

    /// The records in groups not yet out are counted until they go: those
    /// waiting behind a key's group out, and those in a group still open.
    #[tokio::test]
    async fn the_records_held_in_groups_are_counted() {
        let (g, out) = start(Some(2), 60_000, 0);
        g.add((1..=6).map(|id| rec("a", id)).collect())
            .await
            .unwrap();
        g.add(vec![rec("b", 7), rec("b", 8)]).await.unwrap();
        settle().await;
        assert_eq!(out.ids(), [vec![1, 2], vec![7, 8]]);
        assert_eq!(g.held(), 4, "a's 3 to 6; b's group is out, not held");
        out.ack(0).await;
        settle().await;
        assert_eq!(g.held(), 2);
        out.ack(2).await;
        settle().await;
        assert_eq!(out.ids().len(), 4);
        assert_eq!(g.held(), 0);
        g.add(vec![rec("c", 9)]).await.unwrap();
        settle().await;
        assert_eq!(
            g.held(),
            1,
            "c's group is open: one more record would close it"
        );
    }

    /// Open groups close when asked to, though none is full, quiet or old,
    /// and the caller does not wait for them to be through.
    #[tokio::test]
    async fn open_groups_close_when_asked() {
        let (g, out) = start(None, 60_000, 0);
        g.add(vec![rec("a", 1), rec("a", 2), rec("b", 3)])
            .await
            .unwrap();
        settle().await;
        assert!(out.ids().is_empty());
        assert_eq!(g.held(), 3);
        g.close_open().await.unwrap();
        settle().await;
        let mut ids = out.ids();
        ids.sort();
        assert_eq!(ids, [vec![1, 2], vec![3]]);
        assert_eq!(g.held(), 0);
    }

    /// A group whose walk ended without firing its ack (a signal, a failed
    /// worker) frees its key: the next goes, and a flush can answer.
    #[tokio::test]
    async fn a_group_dropped_unfired_frees_its_key() {
        let (g, out) = start(Some(1), 60_000, 2);
        g.add(vec![rec("a", 1), rec("a", 2)]).await.unwrap();
        settle().await;
        assert_eq!(out.ids(), [vec![1]], "a's second waits");
        out.drop_ack(0);
        settle().await;
        assert_eq!(
            out.ids(),
            [vec![1], vec![2]],
            "no history from a dropped group"
        );
        let flushed = {
            let g = g.clone();
            tokio::spawn(async move { g.flush().await })
        };
        out.ack(1).await;
        flushed.await.unwrap().unwrap();
    }

    /// A flush closes every open group and answers once each is through.
    #[tokio::test]
    async fn a_flush_closes_everything_and_waits() {
        let (g, out) = start(None, 60_000, 0);
        g.add(vec![rec("a", 1), rec("b", 2)]).await.unwrap();
        let flushed = {
            let g = g.clone();
            tokio::spawn(async move { g.flush().await })
        };
        settle().await;
        assert_eq!(out.ids().len(), 2);
        assert!(!flushed.is_finished(), "waits for the groups to be through");
        out.ack(0).await;
        out.ack(1).await;
        flushed.await.unwrap().unwrap();
    }
}
