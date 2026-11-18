use std::sync::Arc;

/// A node as the runtime routes between them: its kind and its name. A
/// config names a node by its name alone, in another's `inputs`; the kind is
/// that of the map defining it, `sources`, `plugins`, `inference` or `sinks`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeRef {
    Source {
        name: Arc<str>,
    },
    Plugin {
        name: Arc<str>,
    },
    /// An inference node: a model reads each record (see `inference`).
    Inference {
        name: Arc<str>,
    },
    Sink {
        name: Arc<str>,
    },
}

/// A node and the nodes that take its records: what their `inputs` say,
/// turned round ([`crate::Config::edges`]). A name is one node: no source,
/// plugin, inference node and sink share one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub from: Arc<str>,
    pub to: Vec<Arc<str>>,
}
