use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::dag::{Edge, NodeRef};
use crate::sinks::common::{Encoding, SinkConfig, SinkKind};
use crate::sources::common::SourceConfig;

pub mod cache;
pub mod dag;
pub mod enrichment;
pub mod include;
pub mod inference;
pub mod models;
pub mod packs;
pub mod plugins;
pub mod runtime;
pub mod sinks;
pub mod sources;
pub mod wasm_engine;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub runtime: runtime::RuntimeConfig,

    #[serde(default)]
    pub sources: std::collections::BTreeMap<Arc<str>, SourceConfig>,

    #[serde(default)]
    pub sinks: std::collections::BTreeMap<Arc<str>, SinkConfig>,

    #[serde(default)]
    pub plugins: std::collections::BTreeMap<Arc<str>, plugins::PluginConfig>,

    /// The models, each a server and the model it serves: what an inference
    /// node names as its `model`. They are no nodes: no record goes to one
    /// but through a node that names it.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub models: std::collections::BTreeMap<Arc<str>, models::ModelConfig>,

    /// Inference nodes, each with its own prompt and the model it names,
    /// named in another node's `inputs` as any node is.
    #[serde(default)]
    pub inference: std::collections::BTreeMap<Arc<str>, inference::InferenceConfig>,

    /// Reference data loaded once per process and shared by every plugin,
    /// each looked up by its name.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub enrichment_tables: std::collections::BTreeMap<Arc<str>, enrichment::TableConfig>,
}

/// A node that takes records: its kind, its name and its `inputs`.
struct Reader<'a> {
    kind: &'static str,
    name: &'a Arc<str>,
    inputs: &'a [Arc<str>],
}

/// A config and the files it was read from.
pub struct Loaded {
    pub config: Config,
    /// Every file merged, each after the files it includes; the one named
    /// last.
    pub files: Vec<PathBuf>,
}

impl Config {
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        Ok(Self::load(path)?.config)
    }

    /// The config at `path`, with what it includes (see [`include`]). A file
    /// without `include:` is read as it always was, but that a top-level key
    /// tangent does not know is an error (one starting `x-` aside).
    pub fn load(path: &Path) -> Result<Loaded> {
        let read = include::read(path)?;
        if !read.map.contains_key("include") {
            let mut config: Config = serde_yaml::from_str(&read.text)
                .with_context(|| format!("parsing YAML {}", path.display()))?;
            config.models.values_mut().for_each(|m| m.default_url());
            config
                .check_names()
                .with_context(|| format!("loading {}", path.display()))?;
            return Ok(Loaded {
                config,
                files: vec![path.to_path_buf()],
            });
        }

        let merged = include::merge(path, read)?;
        let mut config: Config =
            serde_path_to_error::deserialize(serde_yaml::Deserializer::from_str(&merged.text))
                .map_err(|e| merged.explain(e))
                .with_context(|| format!("loading {}", path.display()))?;
        config.models.values_mut().for_each(|m| m.default_url());
        config
            .check_names()
            .with_context(|| format!("loading {}", path.display()))?;
        Ok(Loaded {
            config,
            files: merged.files,
        })
    }

    pub const fn batch_age_ms(&self) -> Duration {
        Duration::from_millis(self.runtime.batch_age)
    }

    pub const fn batch_size_kb(&self) -> usize {
        self.runtime.batch_size << 10
    }

    /// The node a name names: whichever of `sources`, `plugins`, `inference`
    /// and `sinks` defines it (they share no name: [`Self::check_names`]).
    pub fn node(&self, name: &str) -> Option<NodeRef> {
        if let Some((n, _)) = self.sources.get_key_value(name) {
            return Some(NodeRef::Source {
                name: Arc::clone(n),
            });
        }
        if let Some((n, _)) = self.plugins.get_key_value(name) {
            return Some(NodeRef::Plugin {
                name: Arc::clone(n),
            });
        }
        if let Some((n, _)) = self.inference.get_key_value(name) {
            return Some(NodeRef::Inference {
                name: Arc::clone(n),
            });
        }
        self.sinks.get_key_value(name).map(|(n, _)| NodeRef::Sink {
            name: Arc::clone(n),
        })
    }

    /// A name is one node, so that `inputs` can name a node without its
    /// kind: no source, plugin, inference node and sink share one. And it is
    /// letters, digits, `_` and `-`: a plugin's names its `.cwasm` file in
    /// plugins_path, and an inference node's is the field its reply goes in,
    /// which a `.` would split: `judge.v2.flag` is judge/v2/flag.
    pub fn check_names(&self) -> Result<()> {
        let mut bad: Vec<String> = Vec::new();
        let mut kinds: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
        let maps: [(&str, Vec<&Arc<str>>); 4] = [
            ("source", self.sources.keys().collect()),
            ("plugin", self.plugins.keys().collect()),
            ("inference node", self.inference.keys().collect()),
            ("sink", self.sinks.keys().collect()),
        ];
        for (kind, names) in maps {
            for n in names {
                if !is_name(n) {
                    bad.push(format!("{kind} `{n}`"));
                }
                kinds.entry(n).or_default().push(kind);
            }
        }
        if !bad.is_empty() {
            anyhow::bail!(
                "a name is letters, digits, `_` and `-` only; rename:\n  - {}",
                bad.join("\n  - ")
            );
        }
        let shared: Vec<String> = kinds
            .iter()
            .filter(|(_, k)| k.len() > 1)
            .map(|(n, k)| format!("`{n}` is a {}", k.join(" and a ")))
            .collect();
        if !shared.is_empty() {
            anyhow::bail!(
                "a name is one node, so `inputs` can name it; rename one of each:\n  - {}",
                shared.join("\n  - ")
            );
        }
        Ok(())
    }

    /// The nodes that take records: the plugins, the inference nodes, then
    /// the sinks, each by name.
    fn readers(&self) -> Vec<Reader<'_>> {
        let plugins = self.plugins.iter().map(|(name, p)| Reader {
            kind: "plugin",
            name,
            inputs: &p.inputs,
        });
        let inference = self.inference.iter().map(|(name, i)| Reader {
            kind: "inference node",
            name,
            inputs: &i.inputs,
        });
        let sinks = self.sinks.iter().map(|(name, s)| Reader {
            kind: "sink",
            name,
            inputs: &s.common.inputs,
        });
        plugins.chain(inference).chain(sinks).collect()
    }

    /// The edges the nodes' `inputs` make, turned round for the router: each
    /// node that is an input, by name, with the nodes that take its records
    /// (plugins, inference nodes, then sinks, each by name), each once
    /// however often it is listed.
    pub fn edges(&self) -> Vec<Edge> {
        let mut outs: BTreeMap<&Arc<str>, Vec<Arc<str>>> = BTreeMap::new();
        for reader in self.readers() {
            for input in reader.inputs {
                let to = outs.entry(input).or_default();
                if !to.contains(reader.name) {
                    to.push(Arc::clone(reader.name));
                }
            }
        }
        outs.into_iter()
            .map(|(from, to)| Edge {
                from: Arc::clone(from),
                to,
            })
            .collect()
    }

    pub fn validate(&self) -> Result<()> {
        self.check_names()?;
        let mut missing: Vec<String> = Vec::new();
        let mut cannot: Vec<String> = Vec::new();
        for Reader { kind, name, inputs } in self.readers() {
            for input in inputs {
                match self.node(input) {
                    None => {
                        missing.push(format!("{kind} `{name}`: input `{input}` does not exist"))
                    }
                    Some(NodeRef::Sink { .. }) => cannot.push(format!(
                        "{kind} `{name}`: input `{input}` is a sink, which sends nothing on"
                    )),
                    Some(_) => {}
                }
            }
        }
        if !missing.is_empty() {
            anyhow::bail!("inputs that name no node:\n  - {}", missing.join("\n  - "));
        }
        cannot.extend(self.cycles());
        if !cannot.is_empty() {
            anyhow::bail!("inputs that cannot be:\n  - {}", cannot.join("\n  - "));
        }

        // an inference node's `model` is an entry under `models`
        for (name, node) in &self.inference {
            if !self.models.contains_key(&node.model) {
                anyhow::bail!(
                    "inference node {name}: model names `{}`, which is no entry under `models`",
                    node.model
                );
            }
        }

        // a plugin's `models` are inference nodes
        for (name, plugin) in &self.plugins {
            for model in &plugin.models {
                if !self.inference.contains_key(model) {
                    anyhow::bail!(
                        "plugin {name}: models names `{model}`, which is no inference node"
                    );
                }
            }
        }

        // a file sink appends each write's encoding to one file, which only
        // NDJSON survives: a Parquet, Avro or JSON file after another is not one
        for (name, sink) in &self.sinks {
            if let SinkKind::File(_) = &sink.kind {
                if !matches!(sink.common.encoding, Encoding::NDJSON) {
                    anyhow::bail!(
                        "sink '{name}': a file sink appends to one file, which only NDJSON \
                         survives; write {} with a rolling_file sink",
                        sink.common.encoding.extension()
                    );
                }
            }
        }

        // a plugin's `tables` are sinks whose records a statement can read
        for (name, plugin) in &self.plugins {
            self.tables_of(name, plugin)?;
        }

        Ok(())
    }

    /// The `tables` of plugin `name` for its `lake.query`: the name its
    /// statements use for each, and where the sink it names keeps its
    /// records (`SinkConfig::table`).
    pub fn tables_of(
        &self,
        name: &str,
        plugin: &plugins::PluginConfig,
    ) -> Result<BTreeMap<String, PathBuf>> {
        let mut tables = BTreeMap::new();
        for (table, sink) in &plugin.tables {
            if !is_table_name(table) {
                anyhow::bail!(
                    "plugin {name}: table `{table}`: a statement names a table with letters, \
                     digits and _, and no digit first"
                );
            }
            let Some(kept) = self.sinks.get(sink.as_str()) else {
                anyhow::bail!("plugin {name}: table `{table}` names `{sink}`, which is no sink");
            };
            let at = kept.table().map_err(|why| {
                anyhow::anyhow!("plugin {name}: table `{table}` is sink `{sink}`: {why}")
            })?;
            tables.insert(table.clone(), at);
        }
        Ok(tables)
    }

    /// What loads and runs but likely is not meant, for the caller to print
    /// (this crate does not log): a plugin, inference node or sink with no
    /// inputs never runs, and a source that is no node's input is read and
    /// dropped, its records acked and a polling source's cursor moved past
    /// them. A plugin that is no node's input is fine: it may only write
    /// state. And a model no inference node names is never asked.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        let edges = self.edges();
        for name in self.sources.keys() {
            if !edges.iter().any(|e| e.from == *name) {
                warnings.push(format!(
                    "source {name}: it is no node's input; its records are read and dropped"
                ));
            }
        }
        // an inference node a plugin calls runs without an input
        let called = |name: &Arc<str>| self.plugins.values().any(|p| p.models.contains(name));
        for Reader { kind, name, inputs } in self.readers() {
            if kind == "inference node" && called(name) {
                continue;
            }
            if inputs.is_empty() {
                warnings.push(format!("{kind} {name}: it has no inputs; it never runs"));
            }
        }
        for name in self.models.keys() {
            if !self.inference.values().any(|node| node.model == *name) {
                warnings.push(format!(
                    "model {name}: no inference node names it; it is never asked"
                ));
            }
        }
        warnings
    }

    /// Cycles among the plugins and inference nodes, each as `a -> b -> a`:
    /// one at least wherever the inputs go round. A walk sends a node's
    /// records on to every node that takes them until a sink, so a record on
    /// a cycle goes round it for good, through a model each time round. No
    /// source or sink is on one: a source has no inputs and a sink is none.
    fn cycles(&self) -> Vec<String> {
        let inner = |n: &str| {
            matches!(
                self.node(n),
                Some(NodeRef::Plugin { .. } | NodeRef::Inference { .. })
            )
        };
        let edges = self.edges();
        let mut outs: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for e in edges.iter().filter(|e| inner(&e.from)) {
            outs.entry(&e.from)
                .or_default()
                .extend(e.to.iter().map(|t| &**t).filter(|t| inner(t)));
        }
        let mut done: HashSet<&str> = HashSet::new();
        let mut cycles = Vec::new();
        for node in outs.keys() {
            visit(node, &outs, &mut Vec::new(), &mut done, &mut cycles);
        }
        cycles
    }
}

/// Whether `name` can name a node: letters, digits, `_` and `-`, one at
/// least ([`Config::check_names`] says why).
pub fn is_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Whether a statement can name a table or a view `name`: letters, digits
/// and `_`, one at least, and no digit first.
pub fn is_table_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

/// A depth-first walk from `node`, `path` the nodes it came through: an
/// edge back to one of them closes a cycle. A node `done` was walked from
/// already.
fn visit<'a>(
    node: &'a str,
    outs: &BTreeMap<&'a str, Vec<&'a str>>,
    path: &mut Vec<&'a str>,
    done: &mut HashSet<&'a str>,
    cycles: &mut Vec<String>,
) {
    if done.contains(node) {
        return;
    }
    if let Some(at) = path.iter().position(|p| *p == node) {
        let mut cycle = path[at..].to_vec();
        cycle.push(node);
        cycles.push(format!("a cycle: {}", cycle.join(" -> ")));
        return;
    }
    path.push(node);
    for to in outs.get(node).into_iter().flatten() {
        visit(to, outs, path, done, cycles);
    }
    path.pop();
    done.insert(node);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(yaml: &str) -> Config {
        serde_yaml::from_str(yaml).unwrap()
    }

    const LINES: &str = "sources:\n  lines: { type: tcp, bind_address: \"127.0.0.1:9\" }\n";

    /// The model the tests' inference nodes name.
    const MODEL: &str = "models:\n  m: { type: openai, model: m }\n";

    /// An input names its node, found in whichever map defines it.
    #[test]
    fn a_name_is_its_node() {
        let cfg = config(&format!(
            "{LINES}sinks:\n  out: {{ type: blackhole, inputs: [lines] }}\n"
        ));
        assert_eq!(
            cfg.node("lines"),
            Some(NodeRef::Source {
                name: "lines".into()
            })
        );
        assert_eq!(cfg.node("out"), Some(NodeRef::Sink { name: "out".into() }));
        assert_eq!(cfg.node("nope"), None);
        cfg.validate().unwrap();
    }

    /// Two kinds sharing a name would make an input's name two nodes: an
    /// error naming both.
    #[test]
    fn two_kinds_may_not_share_a_name() {
        let cfg = config(
            "sources:\n  out: { type: tcp, bind_address: \"127.0.0.1:9\" }\n\
             sinks:\n  out: { type: blackhole, inputs: [out] }\n",
        );
        let e = format!("{:#}", cfg.validate().unwrap_err());
        assert!(e.contains("`out` is a source and a sink"), "{e}");
    }

    /// A plugin's name is its `.cwasm` file's, and an inference node's the
    /// field its reply goes in: `../x` would name a file outside
    /// plugins_path, and `judge.v2.flag` is judge/v2/flag. An error naming
    /// each name that is not letters, digits, `_` and `-`.
    #[test]
    fn a_name_is_letters_digits_underscores_and_dashes() {
        let cfg = config(&format!(
            "{LINES}{MODEL}plugins:\n  ../x: {{ module_type: rust, inputs: [lines] }}\n  \
             ok_name-2: {{ module_type: rust, inputs: [lines] }}\n\
             inference:\n  judge.v2: {{ model: m, prompt_file: p.txt, inputs: [lines] }}\n\
             sinks:\n  out: {{ type: blackhole, inputs: [lines] }}\n"
        ));
        let e = format!("{:#}", cfg.validate().unwrap_err());
        assert!(e.contains("plugin `../x`"), "{e}");
        assert!(e.contains("inference node `judge.v2`"), "{e}");
        assert!(!e.contains("ok_name-2"), "{e}");
    }

    /// An input is a node that sends its records on: one there is, and not
    /// a sink. (A source takes nothing in: it has no `inputs` to say so.)
    #[test]
    fn an_input_is_a_node_that_sends() {
        let after = |inputs: &str| {
            let cfg = config(&format!(
                "{LINES}sinks:\n  out: {{ type: blackhole, inputs: [lines] }}\n  \
                 after: {{ type: blackhole, inputs: [{inputs}] }}\n"
            ));
            format!("{:#}", cfg.validate().unwrap_err())
        };
        let e = after("out");
        assert!(
            e.contains("sink `after`: input `out` is a sink, which sends nothing on"),
            "{e}"
        );
        let e = after("lines, nope");
        assert!(
            e.contains("sink `after`: input `nope` does not exist"),
            "{e}"
        );
    }

    /// An s3 sink may name its objects' prefix; without one they go to the
    /// bucket's root.
    #[test]
    fn an_s3_sink_takes_a_key_prefix() {
        let s3 = |extra: &str| match serde_yaml::from_str::<SinkConfig>(&format!(
            "type: s3\nbucket_name: logs\n{extra}"
        ))
        .unwrap()
        .kind
        {
            SinkKind::S3(c) => c.key_prefix,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            s3("key_prefix: cloudtrail/%Y/%m/%d\n").as_deref(),
            Some("cloudtrail/%Y/%m/%d")
        );
        assert_eq!(s3(""), None);
    }

    /// A walk sends a node's records on to every node that takes them until
    /// a sink: one on a cycle goes round it for good, through a model each
    /// time. An error naming the cycle, through an ungrouped plugin, a
    /// grouped one or an inference node; two nodes with one input are no
    /// cycle.
    #[test]
    fn the_inputs_make_no_cycle() {
        // each node's inputs, besides the source's lines for a, g and first
        let validate = |a: &str, g: &str, first: &str, second: &str, out: &str| {
            config(&format!(
                "{LINES}{MODEL}plugins:\n  a: {{ module_type: rust, inputs: [lines{a}] }}\n  \
                 g: {{ module_type: rust, group_by: [actor], inputs: [lines{g}] }}\n\
                 inference:\n  first: {{ model: m, prompt_file: p.txt, inputs: [lines{first}] }}\n  \
                 second: {{ model: m, prompt_file: p.txt, inputs: [{second}] }}\n\
                 sinks:\n  out: {{ type: blackhole, inputs: [{out}] }}\n"
            ))
            .validate()
        };
        let cycle = |a: &str, g: &str, first: &str, second: &str, out: &str| {
            format!("{:#}", validate(a, g, first, second, out).unwrap_err())
        };

        let e = cycle(", a", "", "", "", "a");
        assert!(e.contains("a cycle: a -> a"), "{e}");
        let e = cycle("", "", ", second", "first", "second");
        assert!(e.contains("a cycle: first -> second -> first"), "{e}");
        let e = cycle("", ", first", ", g", "", "first");
        assert!(e.contains("a cycle: first -> g -> first"), "{e}");

        validate("", "", ", a", "a, first", "second").unwrap();
    }

    /// A node with no inputs never runs, and a source that is no node's
    /// input is read and dropped: each loads, with a warning naming it. A
    /// plugin that is no node's input is fine: it may only write state.
    #[test]
    fn a_node_with_no_inputs_is_a_warning() {
        let cfg = config(&format!(
            "{LINES}  idle: {{ type: tcp, bind_address: \"127.0.0.1:9\" }}\n\
             {MODEL}plugins:\n  builder: {{ module_type: rust, inputs: [lines] }}\n  \
             stray: {{ module_type: rust }}\n\
             inference:\n  lonely: {{ model: m, prompt_file: p.txt }}\n\
             sinks:\n  out: {{ type: blackhole, inputs: [lines] }}\n  never: {{ type: blackhole }}\n"
        ));
        cfg.validate().unwrap();
        assert_eq!(
            cfg.warnings(),
            [
                "source idle: it is no node's input; its records are read and dropped",
                "plugin stray: it has no inputs; it never runs",
                "inference node lonely: it has no inputs; it never runs",
                "sink never: it has no inputs; it never runs",
            ]
        );
    }

    /// The edges are the inputs turned round: each node with the nodes that
    /// take its records, each once.
    #[test]
    fn the_edges_are_the_inputs_turned_round() {
        let cfg = config(&format!(
            "{LINES}plugins:\n  tidy: {{ module_type: rust, inputs: [lines, lines] }}\n\
             sinks:\n  kept: {{ type: blackhole, inputs: [lines, tidy] }}\n  \
             out: {{ type: blackhole, inputs: [tidy] }}\n"
        ));
        let edges: Vec<(String, Vec<String>)> = cfg
            .edges()
            .into_iter()
            .map(|e| {
                (
                    e.from.to_string(),
                    e.to.iter().map(|t| t.to_string()).collect(),
                )
            })
            .collect();
        assert_eq!(
            edges,
            [
                (
                    "lines".to_string(),
                    vec!["tidy".to_string(), "kept".to_string()]
                ),
                (
                    "tidy".to_string(),
                    vec!["kept".to_string(), "out".to_string()]
                ),
            ]
        );
    }

    /// An inference node a plugin holds a conversation with (`models`) runs
    /// without an input, so it draws no warning; a name that is no node is an
    /// error.
    #[test]
    fn a_plugin_s_models_are_inference_nodes_and_need_no_input() {
        let with = |models: &str| {
            config(&format!(
                "{LINES}{MODEL}plugins:\n  agent: {{ module_type: rust, models: [{models}], inputs: [lines] }}\n\
                 inference:\n  reviewer: {{ model: m, prompt_file: p.txt }}\n\
                 sinks:\n  out: {{ type: blackhole, inputs: [agent] }}\n"
            ))
        };
        let cfg = with("reviewer");
        cfg.validate().unwrap();
        assert_eq!(cfg.warnings(), [] as [&str; 0]);
        let e = with("revewer").validate().unwrap_err().to_string();
        assert_eq!(
            e,
            "plugin agent: models names `revewer`, which is no inference node"
        );
    }

    /// An inference node's `model` is an entry under `models`, by name; a
    /// name that is no entry is an error.
    #[test]
    fn an_inference_node_s_model_is_an_entry_under_models() {
        let with = |model: &str| {
            config(&format!(
                "{LINES}{MODEL}inference:\n  judge: {{ model: {model}, prompt_file: p.txt, inputs: [lines] }}\n\
                 sinks:\n  out: {{ type: blackhole, inputs: [judge] }}\n"
            ))
        };
        with("m").validate().unwrap();
        let e = with("n").validate().unwrap_err().to_string();
        assert_eq!(
            e,
            "inference node judge: model names `n`, which is no entry under `models`"
        );
    }

    /// A model no inference node names is never asked: it loads, with a
    /// warning naming it.
    #[test]
    fn a_model_no_node_names_is_a_warning() {
        let cfg = config(&format!(
            "{LINES}{MODEL}  spare: {{ type: anthropic, model: s }}\n\
             inference:\n  judge: {{ model: m, prompt_file: p.txt, inputs: [lines] }}\n\
             sinks:\n  out: {{ type: blackhole, inputs: [judge] }}\n"
        ));
        cfg.validate().unwrap();
        assert_eq!(
            cfg.warnings(),
            ["model spare: no inference node names it; it is never asked"]
        );
    }

    #[test]
    fn a_file_sink_takes_ndjson_only() {
        let file = |encoding: &str| -> Config {
            serde_yaml::from_str(&format!(
                "sources:\n  lines: {{ type: tcp, bind_address: \"127.0.0.1:9\" }}\n\
                 sinks:\n  out: {{ type: file, path: /tmp/out, encoding: {encoding}, inputs: [lines] }}\n"
            ))
            .unwrap()
        };
        assert!(file("{ type: ndjson }").validate().is_ok());
        let parquet = "{ type: parquet, schema: { n: int } }";
        for enc in [parquet, "{ type: json }"] {
            let e = file(enc).validate().unwrap_err();
            assert!(e.to_string().contains("rolling_file"), "{enc}: {e}");
        }
    }

    /// A plugin's table is a sink's records, read as that sink keeps them:
    /// the plugin names the sink, and a sink a statement cannot read is
    /// refused with why.
    #[test]
    fn a_plugin_s_tables_are_sinks_a_statement_can_read() {
        let named = |name: &str, table: &str| {
            config(&format!(
                "{LINES}plugins:\n  agent: {{ module_type: rust, tables: {{ {name}: {table} }}, inputs: [lines] }}\n\
                 sinks:\n  \
                 lake: {{ type: rolling_file, path: lake/logs/%Y/%m/%d, wal_path: lake/wal, encoding: {{ type: parquet, schema: {{ n: int }} }}, inputs: [agent] }}\n  \
                 lines_kept: {{ type: rolling_file, path: kept, wal_path: kept-wal, inputs: [agent] }}\n  \
                 bucket: {{ type: s3, bucket_name: b, encoding: {{ type: parquet, schema: {{ n: int }} }}, inputs: [agent] }}\n  \
                 dated: {{ type: rolling_file, path: \"%Y/%m\", wal_path: dated-wal, encoding: {{ type: parquet, schema: {{ n: int }} }} }}\n"
            ))
        };
        let with = |table: &str| named("records", table);
        let cfg = with("lake");
        cfg.validate().unwrap();
        assert_eq!(
            cfg.tables_of("agent", &cfg.plugins["agent"]).unwrap(),
            BTreeMap::from([("records".to_string(), PathBuf::from("lake/logs"))])
        );

        let refused = |table: &str| with(table).validate().unwrap_err().to_string();
        assert_eq!(
            refused("lakes"),
            "plugin agent: table `records` names `lakes`, which is no sink"
        );
        assert_eq!(
            refused("dated"),
            "plugin agent: table `records` is sink `dated`: its path \"%Y/%m\" starts with a \
             strftime specifier, so its files have no directory of their own to read"
        );
        assert_eq!(
            named("the-records", "lake")
                .validate()
                .unwrap_err()
                .to_string(),
            "plugin agent: table `the-records`: a statement names a table with letters, digits \
             and _, and no digit first"
        );
        assert_eq!(
            refused("lines_kept"),
            "plugin agent: table `records` is sink `lines_kept`: it writes ndjson, \
             and of a rolling_file sink's files only Parquet is read"
        );
        assert_eq!(
            refused("bucket"),
            "plugin agent: table `records` is sink `bucket`: the records of a sink of type s3 are \
             not read yet, only a rolling_file sink's Parquet"
        );
    }
}
