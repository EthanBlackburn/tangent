//! `tangent init mac`: the pipeline that watches this Mac, whole, in
//! tangent.yaml, with what the two models are told and what each known
//! program is expected to do beside it (judge.md, judge.schema.json,
//! review.md, profiles.yaml). It is packs/macos, packs/judge and
//! examples/macos written out as one file.
//!
//! There is nothing to choose but who judges. By default it is a model on
//! this Mac, Inkling 2 Mini on a server tangent starts, and nothing the
//! sensor reads leaves the machine. `--provider` names who serves a hosted
//! pair instead, the one `tangent init cloud` writes for that provider:
//! each session's summary is sent there, and a review sends the records it
//! queries and the files it reads. Claude Haiku 5.5 as the judge and Claude
//! Sonnet 5.5 as the reviewer are the pair measured on the recorded Mac
//! attacks; the others' settings here are not measured on them.

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
    label: String,
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
    records: String,
    needs: &'static [(&'static str, &'static str)],
}

/// How hard a hosted judge and reviewer may be asked, after where each is
/// served.
const JUDGE_LIMITS: &str = "    timeout_ms: 90000
    retries: 6
    concurrency: 16              # the one worker sends a request at a time
";
const REVIEWER_LIMITS: &str = "    timeout_ms: 120000           # two minutes a try,
    retries: 2                   # three tries, then the review is an error and the alert stands
    concurrency: 1
";

/// What a provider's judge and reviewer are asked with on a Mac, under
/// `inference.judge` and `inference.reviewer`, and whether the pair was
/// measured on the recorded Mac attacks. A verdict here is a session's,
/// with its account so far, where a cloud judge's is a record's: so the
/// room for an answer is the Mac's, and how each model thinks is as its
/// provider's cloud pair has it.
fn asks(provider: Provider) -> (&'static str, &'static str, bool) {
    match provider {
        Provider::Anthropic | Provider::Bedrock => (
            r#"    max_tokens: 4000             # a session's verdict, and the thinking before it
    extra:
      thinking: { type: adaptive }   # it thinks before each verdict, briefly
      output_config: { effort: low }
"#,
            r#"    extra:
      thinking: { type: adaptive }   # it thinks before each query and its report
      output_config: { effort: medium }
"#,
            true,
        ),
        Provider::Openai => (
            r#"    max_tokens: 4000             # a session's verdict, and the thinking before it
    extra:
      reasoning: { effort: low }   # it thinks before each verdict, briefly
"#,
            r#"    extra:
      reasoning: { effort: low }   # it thinks before each query and its report, briefly
"#,
            false,
        ),
        Provider::Openrouter => (
            r#"    max_tokens: 1200             # an answer: what the session did, why it is marked, and its account so far
    temperature: 0.7             # with top_p, the sampling it was measured with on cloud records
    extra:
      top_p: 0.95
      reasoning: { enabled: false }            # no thinking: the reply is the answer
      provider: { require_parameters: true }   # only hosts that hold the reply to its schema
"#,
            r#"    extra:
      reasoning: { effort: low }   # it thinks before each query and its report, briefly
"#,
            false,
        ),
    }
}

/// The pipeline that watches this Mac, for one choice of who judges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mac {
    server: Server,
    /// The model that judges and the one that reviews, each by the name
    /// its provider takes. Without them, the provider's two as measured.
    named: Option<(String, String)>,
    /// Whether the file is tangent's own, which `tangent watch` writes
    /// again at each start, and not one init leaves to be edited.
    watched: bool,
}

impl Mac {
    /// Judged on this Mac by Inkling, or by the pair `provider` serves.
    pub fn new(provider: Option<Provider>) -> Self {
        let server = match provider {
            Some(provider) => Server::Hosted(provider),
            None => Server::Ollama,
        };
        Self {
            server,
            named: None,
            watched: false,
        }
    }

    /// This pipeline with the provider's models named, as `--model` names
    /// them: the judge's, then the reviewer's. A provider's pair is what was
    /// measured, and one of the two may be a model an account is not served.
    /// Inkling is the one model that runs here, and takes no other name.
    pub fn naming(mut self, models: Option<(String, String)>) -> Result<Self> {
        if models.is_some() && !matches!(self.server, Server::Hosted(_)) {
            bail!("--model names a provider's models, and goes with --provider");
        }
        self.named = models;
        Ok(self)
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
            Server::Hosted(provider) => {
                let pair = self.server.pair();
                let (judge, reviewer, measured) = asks(provider);
                let (label, judge_model, reviewer_model) = match &self.named {
                    Some((judges, reviews)) => (
                        format!(
                            "{judges} judges, {reviews} reviews ({}): not the pair measured on the recorded Mac attacks",
                            pair.host
                        ),
                        init::named(pair.judge_model, judges) + "\n",
                        init::named(pair.reviewer_model, reviews) + "\n",
                    ),
                    None => (
                        match measured {
                            true => pair.label.to_string(),
                            false => {
                                format!("{}: not measured on the recorded Mac attacks", pair.label)
                            }
                        },
                        pair.judge_model.to_string(),
                        pair.reviewer_model.to_string(),
                    ),
                };
                Models {
                    label,
                    entries: format!(
                        "  judge:\n{judge_model}{JUDGE_LIMITS}  reviewer:\n{reviewer_model}{REVIEWER_LIMITS}"
                    ),
                    names: ("judge", "reviewer"),
                    judge,
                    batch: "48000           # a request past this is split: a few sessions' summaries",
                    reviewer,
                    records: format!(
                        "are sent to {} to be judged: each session's summary, with its command lines, its paths and what you asked Claude Code. A review sends the records it queries and the files it reads",
                        pair.host
                    ),
                    needs: pair.needs,
                }
            }
            // a Mac has no server of its own to name: Inkling, which tangent starts
            Server::Ollama | Server::Yours => Models {
                label: "Inkling 2 Mini judges and reviews on this Mac, on a server tangent starts (Ollama)".to_string(),
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
                records: "stay on this Mac: the model that judges them runs here".to_string(),
                needs: &[],
            },
        }
    }

    /// Who judges, who reviews, and who serves them.
    pub fn models(&self) -> String {
        self.brought().label
    }

    /// Where the records go to be judged.
    pub fn records(&self) -> String {
        self.brought().records
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

/// Who judges, in a few words, for where there is room for few: the menu
/// bar and `tangent status`. Who serves the models, and the models.
pub fn brief(provider: Option<Provider>) -> (&'static str, &'static str) {
    match provider {
        None => ("This Mac", "Inkling 2 Mini"),
        Some(Provider::Anthropic) => ("Anthropic", "Claude Haiku 5.5 + Sonnet 5.5"),
        Some(Provider::Bedrock) => ("Bedrock", "Claude Haiku 5.5 + Sonnet 5.5"),
        Some(Provider::Openrouter) => ("OpenRouter", "DeepSeek V4 Flash"),
        Some(Provider::Openai) => ("OpenAI", "GPT-6 Luna + GPT-6.1 Terra"),
    }
}

/// [`brief`] with the models `--model` named in place of the pair's, each
/// without what says where it is served (`us.anthropic.`).
pub fn brief_of(provider: Option<Provider>, named: Option<&(String, String)>) -> (&'static str, String) {
    let (who, pair) = brief(provider);
    let short = |id: &str| {
        let parts: Vec<&str> = id.splitn(3, '.').collect();
        let word = |p: &str| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphabetic());
        match parts[..] {
            [region, vendor, model] if word(region) && word(vendor) => model.to_string(),
            _ => id.to_string(),
        }
    };
    match named {
        Some((judge, reviewer)) if judge == reviewer => (who, short(judge)),
        Some((judge, reviewer)) => (who, format!("{} + {}", short(judge), short(reviewer))),
        None => (who, pair.to_string()),
    }
}

/// Whether this machine is one the pipeline can watch, with these models:
/// a Mac, and for Inkling one with Apple Silicon and the memory for it. It
/// is asked before anything is written or downloaded. Where Inkling is not
/// started it gives the command for each provider, and says which has its
/// key in the environment already: where the records go is the person's to
/// say, so none is picked for them.
pub fn runs_here(mac: &Mac) -> Result<()> {
    let verb = if mac.watched { "watch" } else { "init" };
    runs_here_as(mac, &format!("tangent {verb} mac"))
}

/// [`runs_here`] for a command of another name, which is the one each
/// provider's line gives: `tangent up` is not told to run `tangent watch
/// mac`, which would watch in its terminal.
pub fn runs_here_as(mac: &Mac, command: &str) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("this watches a Mac, with macOS's Endpoint Security, and this machine is not one");
    }
    if mac.server == Server::Ollama {
        if let Some(why) = init::no_inkling() {
            bail!("{}", pick(&why, command, init::set));
        }
    }
    Ok(())
}

/// What is said where Inkling is not started, for `why`: each provider's
/// command, what is sent to the one picked, and which pair was measured.
fn pick(why: &str, command: &str, set: impl Fn(&str) -> bool) -> String {
    let ways = init::providers(command, set);
    format!(
        "{why}.\nPick a hosted provider to watch this Mac:\n\n{}\n\n\
         Each session's summary is sent to the one you pick, with its command lines, its paths and what you asked Claude Code.\n\
         Measured on the recorded Mac attacks: Claude Haiku 5.5 and Sonnet 5.5 (anthropic, bedrock). Not yet: openai's and openrouter's models.",
        init::table(&ways)
    )
}

/// What only the person at the Mac can do, as lines to print.
pub const BY_HAND: &str = "It asks for your password once: sudo starts the sensor and macOS's tcpdump as root.\n\
The terminal it runs in needs Full Disk Access (System Settings, Privacy & Security), and a restart after the grant.";

/// `tangent init mac` in `dir`: the files, and the plugins the config
/// names and the sensor, fetched and checked. A fetch that fails takes the
/// files with it, so what is left loads or is nothing.
pub async fn run(
    dir: &Path,
    provider: Option<Provider>,
    models: Option<(String, String)>,
) -> Result<()> {
    let mac = Mac::new(provider).naming(models)?;
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
    println!("\n{}.", mac.models());
    println!("Your records {}.", mac.records());
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
    fn written(mac: &Mac) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        init::write(dir.path(), &mac.files()).unwrap();
        let cfg = Config::load(&dir.path().join("tangent.yaml"))
            .unwrap_or_else(|e| panic!("{mac:?}: {e:#}"))
            .config;
        cfg.validate().unwrap_or_else(|e| panic!("{mac:?}: {e:#}"));
        (dir, cfg)
    }

    /// Who can judge a Mac: Inkling here, and each provider's pair.
    const ALL: [Option<Provider>; 5] = [
        None,
        Some(Provider::Anthropic),
        Some(Provider::Bedrock),
        Some(Provider::Openrouter),
        Some(Provider::Openai),
    ];

    /// With each of them, kept or watched: the config loads, passes what
    /// `tangent watch` checks, warns of nothing in its wiring, leaves no place
    /// unfilled, and says where the records go.
    #[test]
    fn the_pipeline_loads_whoever_judges() {
        for provider in ALL {
            for mac in [Mac::new(provider), Mac::new(provider).watched()] {
                let (_dir, cfg) = written(&mac);
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
    /// record leaves; with a provider, each has its own, served where that
    /// provider's cloud pair is and asked with the room a session's verdict
    /// takes, and the file says which pair was not measured on a Mac.
    #[test]
    fn who_judges_is_inkling_here_or_a_provider_s_pair() {
        let (_dir, here) = written(&Mac::new(None));
        assert_eq!(here.models.len(), 1);
        assert!(here.models["inkling"].serve.is_some());
        assert_eq!(here.models["inkling"].concurrency, 1);
        assert_eq!(&*here.inference["judge"].model, "inkling");
        assert_eq!(&*here.inference["reviewer"].model, "inkling");
        assert!(Mac::new(None).records().starts_with("stay on this Mac"));
        assert!(Mac::new(None).needs().is_empty());

        let claude = Mac::new(Some(Provider::Anthropic));
        let (_dir, hosted) = written(&claude);
        assert_eq!(hosted.models.len(), 2);
        assert!(hosted.models.values().all(|m| m.serve.is_none()));
        assert_eq!(hosted.models["judge"].model, "claude-haiku-5-5");
        assert_eq!(hosted.models["reviewer"].model, "claude-sonnet-5-5");
        assert!(claude.records().contains("sent to Anthropic's API"));
        assert_eq!(
            claude.needs(),
            [("ANTHROPIC_API_KEY", "a key from console.anthropic.com")]
        );

        for (provider, judge, reviewer, host, measured) in [
            (
                Provider::Anthropic,
                "claude-haiku-5-5",
                "claude-sonnet-5-5",
                "Anthropic's API",
                true,
            ),
            (
                Provider::Bedrock,
                "us.anthropic.claude-haiku-5-5",
                "us.anthropic.claude-sonnet-5-5",
                "Amazon Bedrock",
                true,
            ),
            (
                Provider::Openai,
                "gpt-6-luna",
                "gpt-6.1-terra",
                "OpenAI's API",
                false,
            ),
            (
                Provider::Openrouter,
                "deepseek/deepseek-v4-flash-0731",
                "deepseek/deepseek-v4-flash-0731",
                "OpenRouter",
                false,
            ),
        ] {
            let mac = Mac::new(Some(provider));
            let (_dir, cfg) = written(&mac);
            assert_eq!(cfg.models["judge"].model, judge);
            assert_eq!(cfg.models["reviewer"].model, reviewer);
            assert_eq!(cfg.models["judge"].concurrency, 16, "{provider:?}");
            assert!(
                cfg.inference["judge"].max_tokens >= 1200,
                "{provider:?}: a session's verdict is longer than a record's"
            );
            assert!(
                mac.records().contains(&format!("sent to {host} ")),
                "{provider:?}"
            );
            assert_eq!(
                mac.models()
                    .contains("not measured on the recorded Mac attacks"),
                !measured,
                "{provider:?}"
            );
        }
    }

    /// Where Inkling is not started, each provider's command is given for
    /// the command that was run, with the one whose key is set first, what
    /// is sent, and which pair was measured.
    #[test]
    fn the_models_named_take_the_pair_s_place_and_inkling_takes_no_name() {
        let named = Some(("us.anthropic.claude-haiku-5-5".to_string(), "us.anthropic.claude-sonnet-5".to_string()));
        let mac = Mac::new(Some(Provider::Bedrock)).naming(named.clone()).unwrap();
        let (_dir, cfg) = written(&mac);
        assert_eq!(cfg.models["judge"].model, "us.anthropic.claude-haiku-5-5");
        assert_eq!(cfg.models["reviewer"].model, "us.anthropic.claude-sonnet-5");
        assert!(mac.models().contains("us.anthropic.claude-sonnet-5 reviews"), "{}", mac.models());
        assert_eq!(
            brief_of(Some(Provider::Bedrock), named.as_ref()),
            ("Bedrock", "claude-haiku-5-5 + claude-sonnet-5".to_string())
        );
        let one = ("gpt-6.1-terra".to_string(), "gpt-6.1-terra".to_string());
        assert_eq!(brief_of(Some(Provider::Openai), Some(&one)).1, "gpt-6.1-terra");
        assert_eq!(brief_of(Some(Provider::Openai), None).1, "GPT-6 Luna + GPT-6.1 Terra");
        assert!(Mac::new(None).naming(named).is_err());
    }

    #[test]
    fn a_mac_too_small_for_inkling_is_given_each_provider_s_command() {
        let why = "this Mac has 16 GB of memory, and Inkling 2 Mini needs 32";
        let said = pick(why, "tangent watch mac", |var| var == "AWS_PROFILE");
        assert!(
            said.starts_with(
                "this Mac has 16 GB of memory, and Inkling 2 Mini needs 32.\n\
                 Pick a hosted provider to watch this Mac:\n\n\
                 \x20 tangent watch mac --provider bedrock      (AWS_PROFILE is set)\n\
                 \x20 tangent watch mac --provider anthropic    (needs ANTHROPIC_API_KEY)\n"
            ),
            "{said}"
        );
        assert!(said.contains("Each session's summary is sent to the one you pick"));
        assert!(said.contains("Measured on the recorded Mac attacks"));
        assert!(pick(why, "tangent init mac", |_| false).contains("  tangent init mac --provider anthropic "));
        assert!(pick(why, "tangent up", |_| false).contains("  tangent up --provider bedrock "));
    }

    /// The file is what the packs say: the config it writes loads to the
    /// same settings as one that includes packs/macos's four files, wired as
    /// examples/macos wires them. Only the models differ, which the packs
    /// take from Bedrock and a local server, and what the judge is asked
    /// with, which is the model's.
    #[test]
    fn the_config_is_what_the_packs_say() {
        let (_dir, ours) = written(&Mac::new(Some(Provider::Anthropic)));
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
        let files = Mac::new(None).files();
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
