//! `tangent init mac`: the pipeline that watches this Mac, whole, in
//! tangent.yaml, with what the two models are told and what each known
//! program is expected to do beside it (judge.md, judge.schema.json,
//! review.md, profiles.yaml). It is packs/macos, packs/judge and
//! examples/macos written out as one file.
//!
//! There is nothing to choose but who judges. By default it is a model on
//! this Mac, Inkling 2 Mini on a server tangent starts, and nothing the
//! sensor reads leaves the machine. `--hosted` is Claude Haiku 5.5 as the
//! judge and Claude Sonnet 5.5 as the reviewer, through Anthropic's API:
//! each session's summary is sent there, and a review sends the records it
//! queries and the files it reads.

use std::path::Path;

use anyhow::{bail, Context, Result};
use tangent_shared::packs;

use crate::init::{self, Provider, Server, INKLING};
use crate::{fetch, local};

/// tangent.yaml with the two models' settings left out:
/// `{{name}}` where each goes.
const CONFIG: &str = include_str!("init-mac.yaml");

/// The files written beside tangent.yaml, as packs/macos has them: the
/// file's name, and its path under packs/.
const BESIDE: &[(&str, &str)] = &[
    ("judge.md", "macos/judge.md"),
    ("judge.schema.json", "macos/judge.schema.json"),
    ("review.md", "macos/review.md"),
    ("profiles.yaml", "macos/profiles.yaml"),
];

/// What a model brings to the config.
struct Models {
    /// Who judges, who reviews, and who serves them, as the file says it.
    label: &'static str,
    /// What is under `models`.
    entries: String,
    /// The entries the judge and the reviewer name.
    names: (&'static str, &'static str),
    /// What the judge is asked with, under `inference.judge`.
    judge: &'static str,
    /// The judge's `batch_bytes`, and what the file says of it.
    batch: &'static str,
    /// What the reviewer is asked with, under `inference.reviewer`.
    reviewer: &'static str,
    /// Where the records go to be judged, as the file and init say it.
    records: &'static str,
    needs: &'static [(&'static str, &'static str)],
}

/// The pipeline that watches this Mac, for one choice of who judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mac {
    server: Server,
    /// Whether the file is tangent's own, which `tangent watch` writes
    /// again at each start, and not one init leaves to be edited.
    watched: bool,
}

impl Mac {
    /// Judged on this Mac by Inkling, or with `hosted` through Anthropic's
    /// API.
    pub fn new(hosted: bool) -> Self {
        let server = match hosted {
            true => Server::Hosted(Provider::Anthropic),
            false => Server::Ollama,
        };
        Self {
            server,
            watched: false,
        }
    }

    /// This pipeline for `tangent watch`, which keeps the file itself.
    pub fn watched(mut self) -> Self {
        self.watched = true;
        self
    }

    pub fn server(&self) -> Server {
        self.server
    }

    fn brought(&self) -> Models {
        match self.server {
            Server::Ollama => Models {
                label: "Inkling 2 Mini judges and reviews on this Mac, on a server tangent starts (Ollama)",
                entries: init::placed(&format!("  inkling:\n{INKLING}"), &init::cache()),
                names: ("inkling", "inkling"),
                judge: r#"    max_tokens: 1200             # an answer: what the session did, why it is marked, and its account so far
    temperature: 0.7
    extra:
      top_p: 0.95
      reasoning_effort: none       # no thinking: the reply is the answer
"#,
                batch: "32000           # a request past this is split: what the model reads well at once",
                reviewer: "",
                records: "stay on this Mac: the model that judges them runs here",
                needs: &[],
            },
            _ => Models {
                label: "Claude Haiku 5.5 judges, Claude Sonnet 5.5 reviews (Anthropic's API)",
                entries: r#"  judge:
    type: anthropic
    api_key: "${ANTHROPIC_API_KEY}"   # a key from console.anthropic.com
    model: claude-haiku-5-5
    timeout_ms: 90000
    retries: 6
    concurrency: 16              # the one worker sends a request at a time
  reviewer:
    type: anthropic
    api_key: "${ANTHROPIC_API_KEY}"
    model: claude-sonnet-5-5
    fallback: claude-sonnet-5    # asked what Sonnet 5.5 declines, as it does some reviews of an attack
    timeout_ms: 120000           # two minutes a try,
    retries: 2                   # three tries, then the review is an error and the alert stands
    concurrency: 1
"#
                .to_string(),
                names: ("judge", "reviewer"),
                judge: r#"    max_tokens: 4000             # a session's verdict, and the thinking before it
    extra:
      thinking: { type: adaptive }   # it thinks before each verdict, briefly
      output_config: { effort: low }
"#,
                batch: "48000           # a request past this is split: a few sessions' summaries",
                reviewer: r#"    extra:
      thinking: { type: adaptive }   # it thinks before each query and its report
      output_config: { effort: medium }
"#,
                records: "are sent to Anthropic's API to be judged: each session's summary, with its command lines, its paths and what you asked Claude Code. A review sends the records it queries and the files it reads",
                needs: &[("ANTHROPIC_API_KEY", "a key from console.anthropic.com")],
            },
        }
    }

    /// Who judges, who reviews, and who serves them.
    pub fn models(&self) -> String {
        self.brought().label.to_string()
    }

    /// Where the records go to be judged.
    pub fn records(&self) -> String {
        self.brought().records.to_string()
    }

    /// The variables the config reads: the models', and none for a model
    /// that runs here.
    pub fn needs(&self) -> Vec<(&'static str, &'static str)> {
        self.brought().needs.to_vec()
    }

    /// The file's first lines: what it watches, who judges, how to run it
    /// and where the answers go.
    fn header(&self) -> String {
        let mut header = String::from(match self.watched {
            false => "# tangent.yaml, written by `tangent init mac`.\n#\n",
            true => {
                "# tangent.yaml, written by `tangent watch mac` each time it starts: an edit\n\
                 # here is lost. `tangent init mac` writes one to keep.\n#\n"
            }
        });
        header.push_str(
            "#   watches  this Mac: what each program runs, opens and connects to, and what you ask Claude Code\n",
        );
        header.push_str(&format!("#   models   {}\n", self.models()));
        // the file's lines are short: the first sentence says where they go
        let records = self.records();
        let first = records.split(". ").next().unwrap_or(&records);
        header.push_str(&format!("#   records  {first}\n"));
        if !self.watched {
            header.push_str("#\n#   tangent watch --config tangent.yaml\n");
        }
        header.push_str(
            "#\n# What the judge marked is in alerts.ndjson, each alert with its review in\n\
             # reviews.ndjson (those are the ones to read), and every verdict in\n\
             # verdicts.ndjson.\n#",
        );
        header
    }

    /// tangent.yaml for this choice.
    pub fn config(&self) -> String {
        let models = self.brought();
        let (judge, reviewer) = models.names;
        [
            ("{{header}}", self.header()),
            ("{{models}}", models.entries.trim_end().to_string()),
            (
                "{{judge_entry}}",
                format!("{judge:<22}# its model, under `models`"),
            ),
            ("{{reviewer_entry}}", reviewer.to_string()),
            ("{{batch_bytes}}", models.batch.to_string()),
            ("{{judge}}", models.judge.trim_end().to_string()),
            ("{{reviewer}}", models.reviewer.trim_end().to_string()),
        ]
        .into_iter()
        .fold(CONFIG.to_string(), |config, (place, part)| {
            // a part with nothing in it takes no line of its own
            match part.is_empty() {
                true => config.replace(&format!("{place}\n"), "").replace(place, ""),
                false => config.replace(place, &part),
            }
        })
    }

    /// Every file init writes, by name, with its text.
    pub fn files(&self) -> Vec<(&'static str, String)> {
        let mut files = vec![("tangent.yaml", self.config())];
        for (name, pack_file) in BESIDE {
            let (_, text) = packs::FILES
                .iter()
                .find(|(f, _)| f == pack_file)
                .expect("the macos pack's files are built in");
            files.push((name, (*text).to_string()));
        }
        files
    }
}

/// Whether this machine is one the pipeline can watch, with these models:
/// a Mac, and for Inkling one with Apple Silicon and the memory for it. It
/// is asked before anything is written or downloaded, and where Inkling is
/// not started it says the command that has Claude judge instead: where
/// the records go is the person's to say, so it is not done for them.
pub fn runs_here(mac: &Mac) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("this watches a Mac, with macOS's Endpoint Security, and this machine is not one");
    }
    if mac.server == Server::Ollama {
        if let Some(why) = init::no_inkling() {
            bail!(
                "{why}.\n\n\
                 Claude can judge this Mac instead, through Anthropic's API:\n  \
                 tangent {} mac --hosted\n\
                 It reads ANTHROPIC_API_KEY, a key from console.anthropic.com. Each session's summary is sent there, with its command lines, its paths and what you asked Claude Code.",
                if mac.watched { "watch" } else { "init" }
            );
        }
    }
    Ok(())
}

/// What only the person at the Mac can do, as lines to print.
pub const BY_HAND: &str = "It asks for your password once: sudo starts the sensor and macOS's tcpdump as root.\n\
The terminal it runs in needs Full Disk Access (System Settings, Privacy & Security), and a restart after the grant.";

/// `tangent init mac` in `dir`: the files, and the plugins the config
/// names and the sensor, fetched and checked. A fetch that fails takes the
/// files with it, so what is left loads or is nothing.
pub async fn run(dir: &Path, hosted: bool) -> Result<()> {
    let mac = Mac::new(hosted);
    runs_here(&mac)?;
    let written = init::write(dir, &mac.files())?;
    let config = dir.join("tangent.yaml");
    if let Err(e) = fetch::missing(&config.canonicalize().unwrap_or(config)).await {
        init::remove(&written);
        return Err(e.context("a plugin or the sensor could not be fetched, so nothing is written"));
    }

    // The model and what serves it, when it is to run here and is not here.
    let mut fetched = Ok(());
    if mac.server == Server::Ollama {
        let root = local::root()?;
        let missing = local::missing(&root);
        if !missing.nothing() && init::ask_to_fetch(&missing, &root) {
            fetched = local::fetch(&root).await;
        }
    }

    let wrote: Vec<String> = written
        .iter()
        .filter_map(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .collect();
    println!("\nWrote {}.", wrote.join(", "));
    println!("\nYour records {}.", mac.records());
    let needs = mac.needs();
    if !needs.is_empty() {
        println!("\nIt reads these from the environment:");
    }
    let width = needs.iter().map(|(var, _)| var.len()).max().unwrap_or(0);
    for (var, what) in needs {
        let set = std::env::var(var).is_ok_and(|v| !v.trim().is_empty());
        let state = if set { "" } else { " (not set)" };
        println!("  {var:width$}  {what}{state}");
    }
    let local = init::local_needs(mac.server);
    if !local.is_empty() {
        println!("\n{}", local.join("\n"));
    }
    println!("\nThen:\n  tangent watch --config tangent.yaml\n\n{BY_HAND}");
    fetched.context(
        "the config is written, and the model is not all here: `tangent model fetch` goes on where this stopped",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::tests::{settings, shape};
    use tangent_shared::Config;

    /// The files for this choice, in a directory of their own, and the
    /// config as it loads.
    fn written(mac: Mac) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        init::write(dir.path(), &mac.files()).unwrap();
        let cfg = Config::load(&dir.path().join("tangent.yaml"))
            .unwrap_or_else(|e| panic!("{mac:?}: {e:#}"))
            .config;
        cfg.validate().unwrap_or_else(|e| panic!("{mac:?}: {e:#}"));
        (dir, cfg)
    }

    const BOTH: [bool; 2] = [false, true];

    /// With either model, kept or watched: the config loads, passes what
    /// `tangent watch` checks, warns of nothing in its wiring, leaves no place
    /// unfilled, and says where the records go.
    #[test]
    fn the_pipeline_loads_with_either_model() {
        for hosted in BOTH {
            for mac in [Mac::new(hosted), Mac::new(hosted).watched()] {
                let (_dir, cfg) = written(mac);
                assert_eq!(cfg.warnings(), Vec::<String>::new(), "{mac:?}");
                let config = mac.config();
                assert!(!config.contains("{{"), "{mac:?}:\n{config}");
                assert!(!config.contains("\n\n\n"), "{mac:?}: a part left a gap");
                assert_eq!(cfg.runtime.workers, 1, "a process's events stay in order");
                assert_eq!(cfg.inference.len(), 2, "{mac:?}");
                let first = mac.records();
                let first = first.split(". ").next().unwrap();
                assert!(
                    config.contains(&format!("#   records  {first}\n")),
                    "{mac:?}"
                );
                assert_eq!(
                    config.contains("written by `tangent watch mac`"),
                    mac.watched,
                    "{mac:?}"
                );
                assert_eq!(config.contains("tangent watch --config"), !mac.watched);
            }
        }
    }

    /// Judged here, both nodes name the one entry tangent starts, and no
    /// record leaves; hosted, each has its own and a key is needed.
    #[test]
    fn who_judges_is_inkling_here_or_claude_hosted() {
        let (_dir, here) = written(Mac::new(false));
        assert_eq!(here.models.len(), 1);
        assert!(here.models["inkling"].serve.is_some());
        assert_eq!(here.models["inkling"].concurrency, 1);
        assert_eq!(&*here.inference["judge"].model, "inkling");
        assert_eq!(&*here.inference["reviewer"].model, "inkling");
        assert!(Mac::new(false).records().starts_with("stay on this Mac"));
        assert!(Mac::new(false).needs().is_empty());

        let (_dir, hosted) = written(Mac::new(true));
        assert_eq!(hosted.models.len(), 2);
        assert!(hosted.models.values().all(|m| m.serve.is_none()));
        assert_eq!(hosted.models["judge"].model, "claude-haiku-5-5");
        assert_eq!(hosted.models["reviewer"].model, "claude-sonnet-5-5");
        assert!(Mac::new(true).records().contains("sent to Anthropic's API"));
        assert_eq!(
            Mac::new(true).needs(),
            [("ANTHROPIC_API_KEY", "a key from console.anthropic.com")]
        );
    }

    /// The file is what the packs say: the config it writes loads to the
    /// same settings as one that includes packs/macos's four files, wired as
    /// examples/macos wires them. Only the models differ, which the packs
    /// take from Bedrock and a local server, and what the judge is asked
    /// with, which is the model's.
    #[test]
    fn the_config_is_what_the_packs_say() {
        let (_dir, ours) = written(Mac::new(true));
        let theirs = r#"include: [pack:macos, pack:macos/judge, pack:macos/lake, pack:judge/hosted, pack:macos/review]
sources:
  mac: { type: macos }
plugins:
  macos: { inputs: [mac] }
  macos_sessions: { inputs: [macos] }
  macos_verdicts: { inputs: [judge] }
  macos_review: { inputs: [macos_verdicts] }
inference:
  judge: { inputs: [macos_sessions] }
sinks:
  lake: { inputs: [macos] }
  alerts: { inputs: [flagged, macos_verdicts] }
  reviews: { inputs: [macos_review], type: file, path: reviews.ndjson, compression: { type: none } }
enrichment_tables:
  geo: { type: mmdb, path: data/GeoLite2-Country.mmdb }
  asn: { type: mmdb, path: data/GeoLite2-ASN.mmdb }
  networks: { type: cidr, path: data/networks.csv }
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tangent.yaml");
        std::fs::write(&path, theirs).unwrap();
        let theirs = Config::load(&path).unwrap().config;
        theirs.validate().unwrap();

        let (mut ours, mut theirs) = (shape(&ours), shape(&theirs));
        for value in [&mut ours, &mut theirs] {
            let value = value.as_mapping_mut().unwrap();
            // who serves the models, and what the judge is asked with
            value.remove("models");
            let judge = value["inference"]["judge"].as_mapping_mut().unwrap();
            judge.remove("max_tokens");
            judge.remove("extra");
            // where a file is, which is not what it holds
            value.remove("enrichment_tables");
            let plugins = value["plugins"].as_mapping_mut().unwrap();
            // the judge pack's history of each actor, which nothing here feeds
            plugins.remove("baseline_builder");
            plugins.remove("baseline_renderer");
            for plugin in plugins.values_mut() {
                let plugin = plugin.as_mapping_mut().unwrap();
                plugin.remove("path");
                plugin.remove("tests");
            }
        }
        let (mut written, mut included) = (Vec::new(), Vec::new());
        settings(&ours, "", &mut written);
        settings(&theirs, "", &mut included);
        let only = |a: &[String], b: &[String]| -> Vec<String> {
            a.iter().filter(|line| !b.contains(line)).cloned().collect()
        };
        assert_eq!(
            (only(&written, &included), only(&included, &written)),
            (Vec::new(), Vec::new()),
            "settings only init writes, and only the packs have"
        );
        assert!(written.len() > 150, "{} settings", written.len());
    }

    /// The files beside the config are the pack's own.
    #[test]
    fn the_briefs_and_the_profiles_are_the_packs() {
        let files = Mac::new(false).files();
        let names: Vec<&str> = files.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "tangent.yaml",
                "judge.md",
                "judge.schema.json",
                "review.md",
                "profiles.yaml"
            ]
        );
        assert!(files.iter().all(|(_, text)| !text.is_empty()));
    }
}
