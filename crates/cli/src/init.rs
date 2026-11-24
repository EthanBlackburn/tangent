//! `tangent init`: writes the whole pipeline to tangent.yaml, with what the
//! two models are told beside it (judge.md, judge.schema.json, review.md).
//! Nothing is left in a file tangent keeps: every node, its settings and its
//! `inputs` are in the file written, to read and to edit.
//!
//! This is `tangent init cloud`; `tangent init mac`, the Mac it runs on, is
//! [`crate::mac`], and shares what is not a cloud's.
//!
//! It asks nothing. What is watched is its subcommand: `cloud` is your
//! cloud and SaaS audit logs, which `--sources` names, and without it the
//! pipeline is written with no source yet. The models are hosted unless
//! `--local`: the two measured on Anthropic's API or, with `--provider` and
//! `--model`, the provider's by name (one name judges and reviews, and two,
//! with a comma, are the judge's and then the reviewer's). `--local` is a
//! model on this machine, Inkling 2 Mini on a server tangent starts or, with
//! `--model`, a server of your own. Hosted, every record is sent to the
//! provider, so the file and init's last lines say where the records go.
//! docs/config.md says how to change either in the file by hand. The plugins
//! the config names are fetched, and the attestation of each build checked,
//! before a file is written: init leaves a pipeline that loads, or nothing.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tangent_shared::packs;

use crate::{fetch, local};

/// tangent.yaml with its sources, their plugins and rows, and the two
/// models' settings left out: `{{name}}` where each goes.
const CONFIG: &str = include_str!("init.yaml");

/// Where a pack's compiled plugin comes from: this repository's release, as
/// built by the workflow that attests it.
pub const PREBUILT: &str =
    "{ repo: EthanBlackburn/tangent, workflow: .github/workflows/attest-packs.yml }";

/// The command that reads a source's past, and the one that reads sources
/// as they are written.
const REPLAY: &str = "tangent replay --config tangent.yaml --from 1d";
const RUN: &str = "tangent watch --config tangent.yaml";

/// Where the directions for changing a written config by hand are.
const DIRECTIONS: &str = "https://github.com/EthanBlackburn/tangent/blob/main/docs/config.md";

/// What the judge and the reviewer are told, written beside tangent.yaml as
/// the judge pack has them: the file's name, and its path under packs/.
const BRIEFS: &[(&str, &str)] = &[
    ("judge.md", "judge/judge.md"),
    ("judge.schema.json", "judge/judge.schema.json"),
    ("review.md", "judge/review.md"),
];

/// A source to watch, by its pack's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Source {
    /// AWS: CloudTrail
    Cloudtrail,
    /// GitHub: an organization's audit log
    Github,
    /// Okta: the System Log
    Okta,
    /// Google Workspace: login, token, Drive and admin activity
    #[value(name = "google_workspace")]
    GoogleWorkspace,
    /// Supabase: a project's Auth log
    Supabase,
}

/// A variable a config reads, and what it holds.
type Needs = &'static [(&'static str, &'static str)];

/// What a source brings to the config.
struct Pack {
    /// The pack, and its plugin: what `--sources` takes.
    name: &'static str,
    /// What it reads, in words.
    label: &'static str,
    /// The source node's name.
    source: &'static str,
    /// The source node, under `sources`.
    node: &'static str,
    /// Its rows under the judge's `encoding.sources`: one for each value of
    /// `source` its records carry.
    rows: &'static str,
    needs: Needs,
}

impl Pack {
    /// Whose logs they are: the label, up to its colon.
    fn provider(&self) -> &'static str {
        self.label.split(':').next().unwrap_or(self.label)
    }
}

impl Source {
    fn pack(self) -> Pack {
        match self {
            Source::Cloudtrail => Pack {
                name: "cloudtrail",
                label: "AWS: CloudTrail",
                source: "aws_audit",
                node: r#"  aws_audit:                     # AWS: CloudTrail
    type: cloudtrail
    profile: "${AWS_PROFILE:-default}"   # the AWS profile (~/.aws/config) that reads CloudTrail; EDIT to name another
    region: us-east-1            # for looking up its credentials; replay reads every region
    queue_url: ${CLOUDTRAIL_QUEUE_URL}   # for `tangent watch`: the SQS queue the trail's bucket notifies; replay needs none
"#,
                rows: r#"        cloudtrail:
          principal: [_norm.actor, userIdentity.arn]
          time: [eventTime, ts]
          keep: [eventName, requestParameters, responseElements, errorCode, errorMessage, userIdentity.mfaAuthenticated, additionalEventData.MFAUsed, _facts.root, _facts.world_open]
"#,
                needs: &[(
                    "AWS_PROFILE",
                    "the AWS profile that reads CloudTrail; `default` when unset",
                )],
            },
            Source::Github => Pack {
                name: "github",
                label: "GitHub: an organization's audit log",
                source: "github_audit",
                node: r#"  github_audit:                  # GitHub: the organization's audit log
    type: github_audit
    org: ${GITHUB_ORG}           # the organization's login
    token: ${GITHUB_TOKEN}       # a token with read:audit_log
"#,
                rows: r#"        github_audit:
          principal: [_norm.actor, actor]
          time: ["@timestamp", created_at, ts]
          keep: [action, repo, visibility, permission, programmatic_access_type, token_scopes, operation_type]
"#,
                needs: &[
                    ("GITHUB_ORG", "the organization's login"),
                    ("GITHUB_TOKEN", "a token with read:audit_log"),
                ],
            },
            Source::Okta => Pack {
                name: "okta",
                label: "Okta: the System Log",
                source: "okta_audit",
                node: r#"  okta_audit:                    # Okta: the System Log
    type: okta
    org_url: ${OKTA_ORG_URL}     # https://acme.okta.com
    token: ${OKTA_API_TOKEN}
"#,
                rows: r#"        okta:
          principal: [_norm.actor, actor.alternateId]
          time: [published, ts]
          keep: [eventType, outcome, target, authenticationContext.credentialType, securityContext.isProxy, debugData.threatSuspected]
"#,
                needs: &[
                    ("OKTA_ORG_URL", "the org's address, https://acme.okta.com"),
                    ("OKTA_API_TOKEN", "an API token"),
                ],
            },
            Source::GoogleWorkspace => Pack {
                name: "google_workspace",
                label: "Google Workspace: login, token, Drive and admin activity",
                source: "workspace_audit",
                node: r#"  workspace_audit:               # Google Workspace: login, token, Drive and admin activity
    type: google_workspace
    credentials_file: ${GOOGLE_APPLICATION_CREDENTIALS}   # a service account's key file, with domain-wide delegation
    subject: ${GOOGLE_ADMIN_EMAIL}                         # the admin it acts as
"#,
                rows: r#"        google_workspace:
          principal: [_norm.actor, actor.email]
          time: [id.time, ts]
          keep: [events]
"#,
                needs: &[
                    (
                        "GOOGLE_APPLICATION_CREDENTIALS",
                        "a service account's key file, with domain-wide delegation",
                    ),
                    (
                        "GOOGLE_ADMIN_EMAIL",
                        "the admin the service account acts as",
                    ),
                ],
            },
            Source::Supabase => Pack {
                name: "supabase",
                label: "Supabase: a project's Auth log",
                source: "supabase_auth",
                node: r#"  supabase_auth:                 # Supabase: a project's Auth log
    type: supabase
    project_ref: ${SUPABASE_PROJECT_REF}   # Project Settings, General
    token: ${SUPABASE_ACCESS_TOKEN}        # Account, Access Tokens
"#,
                rows: r#"        supabase:
          principal: [_norm.actor, auth_event.actor_username]
          time: [ts]
          keep: [log, auth_event.action, auth_event.traits.provider, auth_audit_event.action, path, status, error]
"#,
                needs: &[
                    ("SUPABASE_PROJECT_REF", "the project's reference"),
                    (
                        "SUPABASE_ACCESS_TOKEN",
                        "an access token that can read its logs",
                    ),
                ],
            },
        }
    }

    /// The pack's plugin, under `plugins`: it takes the source.
    fn plugin(self) -> String {
        let pack = self.pack();
        format!(
            "  {}:\n    inputs: [{}]\n    module_type: rust\n    prebuilt: {PREBUILT}\n",
            pack.name, pack.source
        )
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.pack().label)
    }
}

/// Who serves hosted models: what `--provider` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Provider {
    /// Claude Haiku 5.5 judges and Claude Sonnet 5.5 reviews, through Anthropic's API, with ANTHROPIC_API_KEY
    Anthropic,
    /// The same pair on Amazon Bedrock, with an AWS profile
    Bedrock,
    /// DeepSeek V4 Flash, open weights, judges and reviews, through OpenRouter, with OPENROUTER_API_KEY
    Openrouter,
    /// GPT-6 Luna judges and GPT-6.1 Terra reviews, through OpenAI's API, with OPENAI_API_KEY
    Openai,
}

/// Who serves the models. Each brings the settings its models were measured
/// with: a model that judges and one that reviews what it flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Server {
    /// A provider, which is sent every record.
    Hosted(Provider),
    /// A server of your own on this machine, at http://localhost:8080/v1,
    /// with the model you name: `--local` with `--model`.
    Yours,
    /// MTPLX on this Mac, which tangent starts, with Inkling 2 Mini:
    /// `--local`.
    Mtplx,
}

impl Server {
    /// Every pair init writes, the providers' first.
    #[cfg(test)]
    const ALL: [Server; 6] = [
        Server::Hosted(Provider::Anthropic),
        Server::Hosted(Provider::Bedrock),
        Server::Hosted(Provider::Openrouter),
        Server::Hosted(Provider::Openai),
        Server::Yours,
        Server::Mtplx,
    ];
}

/// What a pair brings to the config.
struct Pair {
    /// Who judges, who reviews, and who serves them, as the file says it.
    label: &'static str,
    /// Who serves them, as the file says it of a model named with `--model`.
    host: &'static str,
    /// The one entry under `models` that both nodes name, when the pair is
    /// one model on one server; none when the judge and the reviewer have an
    /// entry each, `judge` and `reviewer`.
    entry: Option<&'static str>,
    /// The judge's model, under `models.judge`: where it is served. With
    /// `entry`, the whole of that entry: its limits and its server too.
    judge_model: &'static str,
    /// What the judge is asked with, under `inference.judge`.
    judge: &'static str,
    /// The reviewer's model, under `models.reviewer`.
    reviewer_model: &'static str,
    /// What the reviewer is asked with, under `inference.reviewer`.
    reviewer: &'static str,
    /// The judge's `batch_bytes`, and what the file says of it.
    batch: &'static str,
    needs: Needs,
}

/// What the judge's and the reviewer's own entries hold after where each is
/// served: how hard each may be asked.
const JUDGE_LIMITS: &str = "    timeout_ms: 90000
    concurrency: 4               # requests at once
";
const REVIEWER_LIMITS: &str =
    "    timeout_ms: 120000           # reviews go one at a time: two minutes a try,
    retries: 2                   # three tries, then the review is an error and the alerts stand
    concurrency: 1
";

/// Inkling 2 Mini's entry under `models`, whole: where MTPLX serves it, how
/// hard it may be asked, and how tangent starts it. One model on one
/// server, which answers a request at a time: the settings are the ones
/// measured with MTPLX 2.13 on an M4 Max with 36 GB, where the model leaves
/// about 3.5 GB spare.
pub const INKLING: &str = r#"    type: openai                 # MTPLX serves the OpenAI API
    url: http://127.0.0.1:8000/v1
    model: mtplx                 # it answers with the model it loaded
    timeout_ms: 600000           # ten minutes a request: a long prompt, or a review that thinks
    retries: 2
    concurrency: 1               # one request at a time, the judge's and the reviewer's together
    # `tangent watch` starts this server, waits until it answers and stops it
    # after; one already answering at `url` is used and left running.
    serve:
      # MTPLX and the model, where `tangent model fetch` keeps them
      command: ["{{mtplx}}", serve, --model, "{{inkling}}", --host, 127.0.0.1, --port, "8000", --ssd-session-cache, "off", --no-stats-footer, --prefill-chunk-tokens, "256"]
      env:
        HF_HUB_OFFLINE: "1"                        # the model is read from this Mac, and never fetched here
        MTPLX_SESSION_BANK_MAX_BYTES: 3G           # what it keeps of prompts it has read, so the judge's brief is read once
        MTPLX_SYSTEM_MEMORY_SHED_FLOOR_BYTES: 2G   # it drops that only below 2 GB of free memory
        MTPLX_GDN_BOUNDARY_TAIL_BACKOFF: "768"     # a restore point inside the brief, for the next record
"#;

/// The judge's `batch_bytes` where a request may be large.
const BATCH: &str = "96000           # a request past this is split; an actor's forty records fit";

impl Server {
    fn pair(self) -> Pair {
        match self {
            Server::Hosted(Provider::Anthropic) => Pair {
                label: "Claude Haiku 5.5 judges, Claude Sonnet 5.5 reviews (Anthropic's API)",
                host: "Anthropic's API",
                entry: None,
                judge_model: r#"    type: anthropic
    api_key: "${ANTHROPIC_API_KEY}"   # a key from console.anthropic.com
    model: claude-haiku-5-5
"#,
                judge: r#"    max_tokens: 400              # per record
    extra: { thinking: { type: disabled } }   # no thinking: the reply is the answer
"#,
                reviewer_model: r#"    type: anthropic
    api_key: "${ANTHROPIC_API_KEY}"
    model: claude-sonnet-5-5
"#,
                reviewer: r#"    extra:
      thinking: { type: adaptive }   # it thinks before each query and its report, briefly
      output_config: { effort: low }
"#,
                batch: BATCH,
                needs: &[("ANTHROPIC_API_KEY", "a key from console.anthropic.com")],
            },
            Server::Hosted(Provider::Bedrock) => Pair {
                label: "Claude Haiku 5.5 judges, Claude Sonnet 5.5 reviews (Amazon Bedrock)",
                host: "Amazon Bedrock",
                entry: None,
                judge_model: r#"    type: bedrock
    model: us.anthropic.claude-haiku-5-5
    aws: { profile: "${AWS_PROFILE:-default}", region: us-west-2 }   # a US region: Bedrock serves this model there
"#,
                judge: r#"    max_tokens: 400              # per record
    extra: { thinking: { type: disabled } }   # no thinking: the reply is the answer
"#,
                reviewer_model: r#"    type: bedrock
    model: us.anthropic.claude-sonnet-5-5
    aws: { profile: "${AWS_PROFILE:-default}", region: us-west-2 }
"#,
                reviewer: r#"    extra:
      thinking: { type: adaptive }   # it thinks before each query and its report, briefly
      output_config: { effort: low }
"#,
                batch: BATCH,
                needs: &[(
                    "AWS_PROFILE",
                    "the AWS profile that calls Bedrock, with access to both models in the US regions; `default` when unset",
                )],
            },
            Server::Hosted(Provider::Openrouter) => Pair {
                label: "DeepSeek V4 Flash, open weights, judges and reviews (OpenRouter)",
                host: "OpenRouter",
                entry: None,
                judge_model: r#"    type: openai                 # an OpenAI-compatible server
    url: https://openrouter.ai/api/v1
    api_key: "${OPENROUTER_API_KEY}"   # a key from openrouter.ai/keys
    model: deepseek/deepseek-v4-flash-0731
"#,
                judge: r#"    max_tokens: 200              # per record
    temperature: 0.7             # with top_p, the sampling it was measured with
    extra:
      top_p: 0.95
      reasoning: { enabled: false }            # no thinking: the reply is the answer
      provider: { require_parameters: true }   # only hosts that hold the reply to its schema
"#,
                reviewer_model: r#"    type: openai                 # an OpenAI-compatible server
    url: https://openrouter.ai/api/v1
    api_key: "${OPENROUTER_API_KEY}"
    model: deepseek/deepseek-v4-flash-0731
"#,
                reviewer: r#"    extra:
      reasoning: { effort: low }   # it thinks before each query and its report, briefly
"#,
                batch: BATCH,
                needs: &[("OPENROUTER_API_KEY", "a key from openrouter.ai/keys")],
            },
            Server::Hosted(Provider::Openai) => Pair {
                label: "GPT-6 Luna judges, GPT-6.1 Terra reviews (OpenAI's API)",
                host: "OpenAI's API",
                entry: None,
                judge_model: r#"    type: responses              # OpenAI's Responses API
    api_key: "${OPENAI_API_KEY}"   # a key from platform.openai.com
    model: gpt-6-luna
"#,
                judge: r#"    max_tokens: 400              # per record, its thinking included
    extra:
      reasoning: { effort: low }   # little thinking: the reply is the answer
"#,
                reviewer_model: r#"    type: responses
    api_key: "${OPENAI_API_KEY}"
    model: gpt-6.1-terra
"#,
                reviewer: r#"    extra:
      reasoning: { effort: low }   # it thinks before each query and its report, briefly
"#,
                batch: BATCH,
                needs: &[("OPENAI_API_KEY", "a key from platform.openai.com")],
            },
            Server::Yours => Pair {
                label: "A model on this machine judges and reviews (llama-server, mlx_lm.server, Ollama, vLLM)",
                host: "a server on this machine",
                entry: None,
                judge_model: r#"    type: openai                 # an OpenAI-compatible server
    url: http://localhost:8080/v1   # llama-server, mlx_lm.server or vLLM; Ollama is http://localhost:11434/v1
    model: glm-4.7-flash         # EDIT to the name your server gives its model
"#,
                judge: r#"    max_tokens: 200              # per record
    temperature: 0.7
    extra:
      top_p: 0.95
      chat_template_kwargs: { enable_thinking: false }   # no thinking: the reply is the answer
"#,
                reviewer_model: r#"    type: openai                 # an OpenAI-compatible server
    url: http://localhost:8080/v1
    model: glm-4.7-flash         # EDIT, as the judge's
"#,
                reviewer: r#""#,
                batch: BATCH,
                needs: &[],
            },
            Server::Mtplx => Pair {
                label: "Inkling 2 Mini judges and reviews on this Mac, on a server tangent starts (MTPLX)",
                host: "this Mac",
                entry: Some("inkling"),
                judge_model: INKLING,
                judge: r#"    max_tokens: 500              # per record
    temperature: 0.7
    extra:
      top_p: 0.95
      chat_template_kwargs: { enable_thinking: false }   # no thinking: the reply is the answer
"#,
                reviewer_model: r#""#,
                reviewer: r#""#,
                batch: "32000           # a request past this is split: what the model reads well at once",
                needs: &[],
            },
        }
    }
}

/// What a config is written for: the sources, in the order `Source` lists
/// them and each once, who serves the models, and the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choices {
    watch: Vec<Source>,
    server: Server,
    /// The model that judges and the one that reviews, each by the name
    /// its provider takes. Without them, the provider's two as measured.
    models: Option<(String, String)>,
    /// Whether the file is tangent's own, which `tangent watch` writes again
    /// at each start, and not one init leaves to be edited.
    watched: bool,
}

/// What `--model` names: one model, which judges and reviews, or the
/// judge's and then the reviewer's, with a comma.
pub fn models(flag: &str) -> Result<(String, String)> {
    let names: Vec<&str> = flag.split(',').map(str::trim).collect();
    match names[..] {
        [both] if !both.is_empty() => Ok((both.to_string(), both.to_string())),
        [judge, reviewer] if !judge.is_empty() && !reviewer.is_empty() => {
            Ok((judge.to_string(), reviewer.to_string()))
        }
        _ => bail!(
            "--model takes one model's name, or the judge's and then the reviewer's with a comma, and `{flag}` is neither"
        ),
    }
}

/// `block` with its `model` line naming `model`.
fn named(block: &str, model: &str) -> String {
    let name = serde_json::Value::from(model).to_string();
    let lines: Vec<String> = block
        .lines()
        .map(|line| match line.split_once("model:") {
            Some((indent, _)) if indent.trim().is_empty() => format!("{indent}model: {name}"),
            _ => line.to_string(),
        })
        .collect();
    lines.join("\n")
}

impl Choices {
    pub fn new(mut watch: Vec<Source>, server: Server, models: Option<(String, String)>) -> Self {
        watch.sort();
        watch.dedup();
        Self {
            watch,
            server,
            models,
            watched: false,
        }
    }

    /// These choices for `tangent watch`, which keeps the file itself.
    pub fn watched(mut self) -> Self {
        self.watched = true;
        self
    }

    pub fn watch(&self) -> &[Source] {
        &self.watch
    }

    /// Who judges, who reviews, and who serves them, as the file says it.
    pub fn models(&self) -> String {
        let pair = self.server.pair();
        match &self.models {
            Some((judge, reviewer)) if judge == reviewer => {
                format!("{judge} judges and reviews ({})", pair.host)
            }
            Some((judge, reviewer)) => {
                format!("{judge} judges, {reviewer} reviews ({})", pair.host)
            }
            None => pair.label.to_string(),
        }
    }

    /// Where the records go to be judged, as the file and init say it: a
    /// hosted model is sent every one.
    pub fn records(&self) -> String {
        match self.server {
            Server::Yours | Server::Mtplx => {
                "stay on this machine: the model that judges them runs here".to_string()
            }
            hosted => format!(
                "are sent to {}, every one, to be judged",
                hosted.pair().host
            ),
        }
    }

    /// What is under `models`, with each model named: the judge's entry and
    /// the reviewer's, or the one entry both name.
    fn served(&self) -> String {
        let pair = self.server.pair();
        let (judge, reviewer) = match &self.models {
            Some((judge, reviewer)) => (
                named(pair.judge_model, judge) + "\n",
                named(pair.reviewer_model, reviewer) + "\n",
            ),
            None => (
                pair.judge_model.to_string(),
                pair.reviewer_model.to_string(),
            ),
        };
        match pair.entry {
            Some(entry) => placed(&format!("  {entry}:\n{judge}"), &cache()),
            None => {
                format!("  judge:\n{judge}{JUDGE_LIMITS}  reviewer:\n{reviewer}{REVIEWER_LIMITS}")
            }
        }
    }

    /// The entries under `models` the judge and the reviewer name.
    fn entries(&self) -> (&'static str, &'static str) {
        match self.server.pair().entry {
            Some(entry) => (entry, entry),
            None => ("judge", "reviewer"),
        }
    }

    fn replays(&self) -> bool {
        self.watch.contains(&Source::Cloudtrail)
    }

    /// Whether a source is read as it happens with what init asks for:
    /// every one but CloudTrail, which needs a queue as well.
    fn runs(&self) -> bool {
        self.watch.iter().any(|w| *w != Source::Cloudtrail)
    }

    /// The commands that read the sources, and what each reads, as lines
    /// to print.
    fn commands(&self) -> Vec<String> {
        let mut commands = Vec::new();
        if self.replays() {
            commands.push(format!("{REPLAY}   # the last day of CloudTrail"));
        }
        if self.runs() {
            let live: Vec<&str> = self
                .watch
                .iter()
                .filter(|w| **w != Source::Cloudtrail)
                .map(|w| w.pack().provider())
                .collect();
            // in a column with replay's, when both are there
            let width = if self.replays() { REPLAY.len() } else { 0 };
            commands.push(format!(
                "{RUN:width$}   # {}, from an hour back and as it happens",
                live.join(", ")
            ));
        }
        commands
    }

    /// The variables the config reads, each once, the models' first.
    pub fn needs(&self) -> Vec<(&'static str, &'static str)> {
        let mut needs: Vec<(&'static str, &'static str)> = Vec::new();
        let packs = self.watch.iter().flat_map(|w| w.pack().needs);
        for need in self.server.pair().needs.iter().chain(packs) {
            if !needs.iter().any(|(var, _)| var == &need.0) {
                needs.push(*need);
            }
        }
        needs
    }

    /// The file's first lines: what it watches, who judges, how to run it
    /// and where the answers go.
    fn header(&self) -> String {
        let mut header = String::from(match self.watched {
            false => "# tangent.yaml, written by `tangent init`.\n#\n",
            true => {
                "# tangent.yaml, written by `tangent watch cloud` each time it starts: an edit\n\
                 # here is lost. `tangent init cloud` with the same flags writes one to keep.\n#\n"
            }
        });
        if self.watch.is_empty() {
            header.push_str("#   watches  nothing yet\n");
        }
        for (i, w) in self.watch.iter().enumerate() {
            let lead = if i == 0 { "watches" } else { "" };
            header.push_str(&format!("#   {lead:7}  {}\n", w.pack().label));
        }
        header.push_str(&format!("#   models   {}\n", self.models()));
        header.push_str(&format!("#   records  {}\n", self.records()));
        // the commands that run a file of your own; `watch cloud` is its own
        let commands = match self.watched {
            false => self.commands(),
            true => Vec::new(),
        };
        for (i, command) in commands.iter().enumerate() {
            let gap = if i == 0 { "#\n" } else { "" };
            header.push_str(&format!("{gap}#   {command}\n"));
        }
        header.push_str(
            "#\n# What the judge flagged is in alerts.ndjson, each alert with its review in\n\
             # reviews.ndjson (those are the ones to read), and every verdict in\n\
             # verdicts.ndjson.\n#\n",
        );
        match self.watched {
            false => header.push_str(&format!(
                "# To watch something else, or have other models judge it, edit this file as\n\
                 # {DIRECTIONS} says.\n#"
            )),
            true => header.push_str(
                "# To watch something else, or have other models judge it, give\n\
                 # `tangent watch cloud` other flags.\n#",
            ),
        }
        header
    }

    /// tangent.yaml for these choices.
    pub fn config(&self) -> String {
        let packs: Vec<Pack> = self.watch.iter().map(|w| w.pack()).collect();
        let join = |part: fn(&Pack) -> &'static str| packs.iter().map(part).collect::<String>();
        let flow: Vec<String> = packs
            .iter()
            .map(|p| format!("{} -> {}", p.source, p.name))
            .collect();
        let inputs: Vec<&str> = packs.iter().map(|p| p.name).collect();
        let plugins: String = self.watch.iter().map(|w| w.plugin()).collect();
        let pair = self.server.pair();
        let (judge_entry, reviewer_entry) = self.entries();
        // Each part ends its last line, and so does the line it stands on.
        // With no source yet, a part says so where its nodes would be.
        let block = |text: &str, none: &str| match text.trim_end() {
            "" => none.to_string(),
            text => text.to_string(),
        };
        [
            ("{{header}}", self.header()),
            ("{{flow}}", block(&flow.join("\n#   "), "(no source yet)")),
            ("{{sources}}", block(&join(|p| p.node), "  {}   # none yet")),
            ("{{packs}}", block(&plugins, "  # (none yet)")),
            ("{{inputs}}", inputs.join(", ")),
            ("{{models}}", block(&self.served(), "")),
            (
                "{{judge_entry}}",
                format!("{judge_entry:<22}# its model, under `models`"),
            ),
            ("{{reviewer_entry}}", reviewer_entry.to_string()),
            ("{{batch_bytes}}", pair.batch.to_string()),
            ("{{judge}}", block(pair.judge, "")),
            (
                "{{rows}}",
                block(&join(|p| p.rows), "        {}   # none yet"),
            ),
            ("{{reviewer}}", block(pair.reviewer, "")),
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

    /// Every file init writes, by name, with its text: tangent.yaml, and
    /// what the two models are told.
    pub fn files(&self) -> Vec<(&'static str, String)> {
        let mut files = vec![("tangent.yaml", self.config())];
        for (name, pack_file) in BRIEFS {
            let (_, text) = packs::FILES
                .iter()
                .find(|(f, _)| f == pack_file)
                .expect("the judge pack's briefs are built in");
            files.push((name, (*text).to_string()));
        }
        files
    }

    /// Writes the files to `dir`, unless one of them is there: each is
    /// created only if missing, so a file already there is never written
    /// over, and a write that fails removes what this call wrote, which is
    /// its alone. The paths written.
    pub fn write(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        write(dir, &self.files())
    }
}

/// Writes `files` to `dir`, unless one of them is there: each is created
/// only if missing, so a file already there is never written over, and a
/// write that fails removes what this call wrote, which is its alone. The
/// paths written.
pub fn write(dir: &Path, files: &[(&'static str, String)]) -> Result<Vec<PathBuf>> {
    if let Some((name, _)) = files.iter().find(|(name, _)| dir.join(name).exists()) {
        bail!(
            "{name} is already here; init leaves it as it is, and writes nothing (run tangent init in another directory)"
        );
    }
    let mut written = Vec::new();
    for (name, text) in files {
        let path = dir.join(name);
        let created = OpenOptions::new().write(true).create_new(true).open(&path);
        let result = match created {
            Ok(mut file) => {
                written.push(path.clone());
                file.write_all(text.as_bytes())
                    .with_context(|| format!("writing {}", path.display()))
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(anyhow::anyhow!(
                "{name} is already here; init leaves it as it is"
            )),
            Err(e) => Err(e).with_context(|| format!("creating {}", path.display())),
        };
        if let Err(e) = result {
            remove(&written);
            return Err(e);
        }
    }
    Ok(written)
}

/// Writes `files` to `dir`, over the ones there: for a directory that is
/// tangent's own, where each start writes what its flags say.
pub fn place(dir: &Path, files: &[(&'static str, String)]) -> Result<()> {
    for (name, text) in files {
        let path = dir.join(name);
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

pub fn remove(paths: &[PathBuf]) {
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

/// Every value of a flag, as it is written, joined by `sep`.
pub fn names<T: clap::ValueEnum>(sep: &str) -> String {
    let names: Vec<String> = T::value_variants()
        .iter()
        .filter_map(|v| v.to_possible_value())
        .map(|v| v.get_name().to_string())
        .collect();
    names.join(sep)
}

/// `tangent init` in `dir`: the files for what the flags name, and the
/// plugins the config names, fetched and checked. A fetch that fails takes
/// the files with it, so what is left loads or is nothing.
/// The memory under which tangent does not start Inkling, in GiB.
const INKLING_MEMORY: u64 = 32;

/// The pair `tangent init cloud`'s flags name, and the models named with
/// it: hosted unless `--local`. Hosted is Anthropic's pair, or `--provider`
/// with `--model`; `--local` is Inkling on a server tangent starts, or with
/// `--model` a server of your own.
pub fn served(
    local: bool,
    provider: Option<Provider>,
    model: Option<&str>,
) -> Result<(Server, Option<(String, String)>)> {
    let named = model.map(models).transpose()?;
    match (local, provider) {
        (true, _) if named.is_some() => Ok((Server::Yours, named)),
        (true, _) => Ok((Server::Mtplx, None)),
        (false, None) if named.is_some() => bail!(
            "--model names a hosted model with --provider, or with --local a model server of your own"
        ),
        (false, provider) => Ok((Server::Hosted(provider.unwrap_or(Provider::Anthropic)), named)),
    }
}

/// The cache directory as a config names it, so the file holds no one's
/// home: `${XDG_CACHE_HOME}` where that is set to a path tangent would use,
/// else `${HOME}/.cache`.
pub fn cache() -> String {
    let xdg = std::env::var_os("XDG_CACHE_HOME").is_some_and(|p| Path::new(&p).is_absolute());
    if xdg {
        "${XDG_CACHE_HOME}"
    } else {
        "${HOME}/.cache"
    }
    .to_string()
}

/// `text` with MTPLX's program and the model's directory under `cache` in
/// their places.
pub fn placed(text: &str, cache: &str) -> String {
    let (mtplx, inkling) = local::paths(cache);
    text.replace("{{mtplx}}", &mtplx)
        .replace("{{inkling}}", &inkling)
}

/// Asks, at a terminal, whether to download what `missing` lists now. No
/// terminal is no.
pub fn ask_to_fetch(missing: &local::Missing, root: &Path) -> bool {
    use std::io::IsTerminal as _;
    println!(
        "\nInkling 2 Mini runs on MTPLX, and {}: {} to download, into {}.",
        match (missing.engine, missing.model > 0) {
            (true, true) => "neither is on this Mac yet",
            (true, false) => "MTPLX is not on this Mac yet",
            _ => "the model is not all on this Mac yet",
        },
        local::size(missing.bytes()),
        root.display()
    );
    if !std::io::stdin().is_terminal() {
        return false;
    }
    print!("Download now? [y/N] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).ok();
    matches!(answer.trim(), "y" | "Y" | "yes")
}

/// This machine's memory in GiB, where it says: a Mac's `hw.memsize`.
fn memory_gib() -> Option<u64> {
    let out = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()?;
    let bytes: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    Some(bytes >> 30)
}

/// What a model on this machine needs that the file cannot hold, as lines
/// to print after it is written.
pub fn local_needs(server: Server) -> Vec<String> {
    match server {
        Server::Yours => vec!["Start your model's server first.".to_string()],
        Server::Mtplx => {
            let mut lines = vec![
                "`tangent watch` starts the model, waits until it answers and stops it after."
                    .to_string(),
            ];
            if let Ok(root) = local::root() {
                let missing = local::missing(&root);
                if !missing.nothing() {
                    lines.push(format!(
                        "It is not all on this Mac yet: `tangent model fetch` downloads it ({}), and goes on where a fetch was stopped.",
                        local::size(missing.bytes())
                    ));
                }
            }
            lines
        }
        _ => Vec::new(),
    }
}

/// Why tangent does not start Inkling on this machine, where it does not:
/// MTPLX runs on Apple Silicon Macs only, and the model does not fit in
/// less than [`INKLING_MEMORY`].
pub fn no_inkling() -> Option<String> {
    unfit(memory_gib())
}

/// [`no_inkling`] for a machine with `memory` GiB, or one that does not say.
fn unfit(memory: Option<u64>) -> Option<String> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Some("tangent starts Inkling 2 Mini on Apple Silicon Macs only".to_string());
    }
    let memory = memory.filter(|gib| *gib < INKLING_MEMORY)?;
    Some(format!(
        "this Mac has {memory} GB of memory, and Inkling 2 Mini takes about 20 GB to itself: under {INKLING_MEMORY} GB it is slow or does not load, so tangent does not start it"
    ))
}

/// Whether this machine can serve the models as `server` would. It is
/// asked before anything is written or downloaded.
pub fn runs_here(server: Server) -> Result<()> {
    if server == Server::Mtplx {
        if let Some(why) = no_inkling() {
            bail!(
                "{why}. `--local --model <name>` is a model server of your own, and without --local the models are served for you"
            );
        }
    }
    Ok(())
}

pub async fn run(
    dir: &Path,
    watch: Vec<Source>,
    server: Server,
    models: Option<(String, String)>,
) -> Result<()> {
    runs_here(server)?;
    let choices = Choices::new(watch, server, models);
    let written = choices.write(dir)?;
    let config = dir.join("tangent.yaml");
    if let Err(e) = fetch::missing(&config.canonicalize().unwrap_or(config)).await {
        remove(&written);
        return Err(
            e.context("a plugin the config names could not be fetched, so nothing is written")
        );
    }

    // The model and what serves it, when it is to run here and is not here.
    let mut fetched = Ok(());
    if choices.server == Server::Mtplx {
        let root = local::root()?;
        let missing = local::missing(&root);
        if !missing.nothing() && ask_to_fetch(&missing, &root) {
            fetched = local::fetch(&root).await;
        }
    }

    let wrote: Vec<String> = written
        .iter()
        .filter_map(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .collect();
    println!("\nWrote {}.", wrote.join(", "));
    println!("\nYour records {}.", choices.records());
    let needs = choices.needs();
    if !needs.is_empty() {
        println!("\nIt reads these from the environment:");
        let width = needs.iter().map(|(var, _)| var.len()).max().unwrap_or(0);
        for (var, what) in needs {
            let set = std::env::var(var).is_ok_and(|v| !v.trim().is_empty());
            let state = if set { "" } else { " (not set)" };
            println!("  {var:width$}  {what}{state}");
        }
    }
    let local = local_needs(choices.server);
    if !local.is_empty() {
        println!("\n{}", local.join("\n"));
    }
    if choices.watch.is_empty() {
        println!(
            "\nIt watches nothing yet. In an empty directory, `tangent init cloud` with `--sources` and one or more of {} writes it with them in; {DIRECTIONS} says how to add one to this file.",
            names::<Source>(", ")
        );
        return fetched.context("the config is written, and the model is not all here: `tangent model fetch` goes on where this stopped");
    }
    println!("\nThen:");
    for command in choices.commands() {
        println!("  {command}");
    }
    if !choices.runs() {
        println!(
            "\n`tangent watch` reads CloudTrail as it is written once tangent.yaml's `queue_url` names the trail's queue."
        );
    }
    fetched.context("the config is written, and the model is not all here: `tangent model fetch` goes on where this stopped")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use clap::ValueEnum as _;
    use serde_yaml::Value;
    use tangent_shared::models::ModelKind;
    use tangent_shared::sources::common::SourceConfig;
    use tangent_shared::Config;

    const EVERY: [Source; 5] = [
        Source::Cloudtrail,
        Source::Github,
        Source::Okta,
        Source::GoogleWorkspace,
        Source::Supabase,
    ];

    /// The files for these choices, in a directory of their own, and the
    /// config as it loads.
    fn written(watch: &[Source], server: Server) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let choices = Choices::new(watch.to_vec(), server, None);
        choices.write(dir.path()).unwrap();
        let cfg = Config::load(&dir.path().join("tangent.yaml"))
            .unwrap_or_else(|e| panic!("{watch:?}, {server:?}: {e:#}"))
            .config;
        cfg.validate()
            .unwrap_or_else(|e| panic!("{watch:?}, {server:?}: {e:#}"));
        (dir, cfg)
    }

    /// Every source alone, and all five together, with every pair: the
    /// config loads, passes what `tangent watch` checks, and warns of nothing
    /// in its wiring.
    #[test]
    fn every_choice_is_a_pipeline_that_loads() {
        let mut sets: Vec<Vec<Source>> = EVERY.iter().map(|w| vec![*w]).collect();
        sets.push(EVERY.to_vec());
        for watch in &sets {
            for server in &Server::ALL {
                let (_dir, cfg) = written(watch, *server);
                assert_eq!(
                    cfg.warnings(),
                    Vec::<String>::new(),
                    "{watch:?}, {server:?}"
                );
                assert_eq!(cfg.sources.len(), watch.len(), "{watch:?}");
                for w in watch {
                    let pack = w.pack();
                    assert!(cfg.sources.contains_key(pack.source), "{watch:?}");
                    assert_eq!(
                        cfg.plugins[pack.name].inputs,
                        [pack.source.into()],
                        "{watch:?}"
                    );
                }
                let names: Vec<std::sync::Arc<str>> =
                    watch.iter().map(|w| w.pack().name.into()).collect();
                assert_eq!(cfg.plugins["baseline_builder"].inputs, names);
                assert_eq!(cfg.plugins["baseline_renderer"].inputs, names);
                assert_eq!(cfg.sinks["lake"].common.inputs, names);
            }
        }
    }

    /// No place is left in a config, whatever the choices.
    #[test]
    fn every_place_in_the_file_is_filled() {
        for server in &Server::ALL {
            let config = Choices::new(EVERY.to_vec(), *server, None).config();
            assert!(!config.contains("{{"), "{server:?}:\n{config}");
            assert!(!config.contains("\n\n\n"), "{server:?}: a part left a gap");
        }
    }

    /// A config as it loads, as YAML to compare: without the paths that say
    /// where a file is rather than what it holds.
    pub(crate) fn shape(cfg: &Config) -> Value {
        let mut value = serde_yaml::to_value(cfg).unwrap();
        for node in value["inference"].as_mapping_mut().unwrap().values_mut() {
            let node = node.as_mapping_mut().unwrap();
            node.remove("prompt_file");
            node.remove("schema_file");
        }
        value
    }

    /// Every setting in `value`, as `a.b.c = value` lines, sorted: two
    /// configs compare whatever order their maps are in, and a difference
    /// is the lines that differ.
    pub(crate) fn settings(value: &Value, at: &str, out: &mut Vec<String>) {
        match value {
            Value::Mapping(map) => {
                for (key, value) in map {
                    let key = key.as_str().unwrap();
                    settings(value, &format!("{at}.{key}"), out);
                }
            }
            other => out.push(format!(
                "{at} = {}",
                serde_yaml::to_string(other).unwrap().trim_end()
            )),
        }
        out.sort();
    }

    /// The config init writes is the judge pack's, node for node and setting
    /// for setting: the same as a config that includes the provider's pack
    /// and each source's, for the two pairs that have a pack. So what the
    /// pack measured is what init writes.
    #[test]
    fn the_config_is_what_the_packs_say() {
        for (server, pack) in [
            (Server::Hosted(Provider::Anthropic), "anthropic"),
            (Server::Hosted(Provider::Openrouter), "openrouter"),
        ] {
            let (_dir, ours) = written(&EVERY, server);

            let choices = Choices::new(EVERY.to_vec(), server, None);
            let packs: Vec<Pack> = EVERY.iter().map(|w| w.pack()).collect();
            let names: Vec<&str> = packs.iter().map(|p| p.name).collect();
            let includes: Vec<String> = names.iter().map(|n| format!("pack:{n}")).collect();
            let sources: String = packs.iter().map(|p| p.node).collect();
            let plugins: String = packs
                .iter()
                .map(|p| format!("  {}: {{ inputs: [{}] }}\n", p.name, p.source))
                .collect();
            let tables = choices
                .config()
                .split_once("enrichment_tables:\n")
                .and_then(|(_, rest)| rest.split_once("\nruntime:"))
                .map(|(tables, _)| tables.to_string())
                .unwrap();
            let theirs = format!(
                "include: [pack:judge/{pack}, {}]\nsources:\n{sources}plugins:\n{plugins}  \
                 baseline_builder: {{ inputs: [{inputs}] }}\n  baseline_renderer: {{ inputs: [{inputs}] }}\n\
                 sinks:\n  lake: {{ inputs: [{inputs}] }}\nenrichment_tables:\n{tables}\n",
                includes.join(", "),
                inputs = names.join(", "),
            );
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("tangent.yaml");
            std::fs::write(&path, theirs).unwrap();
            let theirs = Config::load(&path).unwrap().config;
            theirs.validate().unwrap();

            let (mut ours, mut theirs) = (shape(&ours), shape(&theirs));
            // The pack names Anthropic's address over the local server's it
            // starts from; the file has no address to name over.
            for value in [&mut ours, &mut theirs] {
                if server == Server::Hosted(Provider::Anthropic) {
                    value["models"]["judge"]
                        .as_mapping_mut()
                        .unwrap()
                        .remove("url");
                }
            }
            // The pack has a row for every source any pack reads; the file,
            // for the sources it has.
            let rows = theirs["inference"]["judge"]["encoding"]["sources"]
                .as_mapping_mut()
                .unwrap();
            for unread in ["gha_ci", "runner_egress"] {
                assert!(rows.remove(unread).is_some(), "{unread}");
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
                "{server:?}: settings only init writes, and only the packs have"
            );
            assert!(
                written.len() > 150,
                "{server:?}: {} settings",
                written.len()
            );
        }
    }

    /// What the models are told is written beside the config as the judge
    /// pack has it, and the config names those files.
    #[test]
    fn the_briefs_are_the_judge_packs_beside_the_config() {
        let (dir, cfg) = written(&[Source::Cloudtrail], Server::Hosted(Provider::Anthropic));
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packs");
        for (name, pack_file) in BRIEFS {
            assert_eq!(
                std::fs::read_to_string(dir.path().join(name)).unwrap(),
                std::fs::read_to_string(repo.join(pack_file)).unwrap(),
                "{name}"
            );
        }
        let judge = &cfg.inference["judge"];
        assert_eq!(judge.prompt_file, Path::new("judge.md"));
        assert_eq!(
            judge.schema_file.as_deref(),
            Some(Path::new("judge.schema.json"))
        );
        assert_eq!(
            cfg.inference["reviewer"].prompt_file,
            Path::new("review.md")
        );
    }

    /// Each pair names the models it says it does, where they are served,
    /// and its reviewer is the provider's own. Each node names its model.
    #[test]
    fn every_pair_names_its_models() {
        for server in &Server::ALL {
            let (_dir, cfg) = written(&[Source::Cloudtrail], *server);
            let (judge, reviewer) = (&cfg.inference["judge"], &cfg.inference["reviewer"]);
            let (kind, url, judges, reviews) = match server {
                Server::Hosted(Provider::Anthropic) => (
                    ModelKind::Anthropic,
                    None,
                    "claude-haiku-5-5",
                    "claude-sonnet-5-5",
                ),
                Server::Hosted(Provider::Bedrock) => (
                    ModelKind::Bedrock,
                    None,
                    "us.anthropic.claude-haiku-5-5",
                    "us.anthropic.claude-sonnet-5-5",
                ),
                Server::Hosted(Provider::Openrouter) => (
                    ModelKind::Openai,
                    Some("https://openrouter.ai/api/v1"),
                    "deepseek/deepseek-v4-flash-0731",
                    "deepseek/deepseek-v4-flash-0731",
                ),
                Server::Hosted(Provider::Openai) => {
                    (ModelKind::Responses, None, "gpt-6-luna", "gpt-6.1-terra")
                }
                Server::Yours => (
                    ModelKind::Openai,
                    Some("http://localhost:8080/v1"),
                    "glm-4.7-flash",
                    "glm-4.7-flash",
                ),
                Server::Mtplx => (
                    ModelKind::Openai,
                    Some("http://127.0.0.1:8000/v1"),
                    "mtplx",
                    "mtplx",
                ),
            };
            let models = [judge, reviewer].map(|node| &cfg.models[&node.model]);
            for model in models {
                assert_eq!(model.kind, kind, "{server:?}");
                assert_eq!(model.url.as_deref(), url, "{server:?}");
            }
            assert_eq!(models.map(|model| model.model.as_str()), [judges, reviews]);
            assert!(
                reviewer.inputs.is_empty(),
                "{server:?}: the plugin calls it"
            );
            assert_eq!(reviewer.max_tokens, 8000, "{server:?}");
        }
    }

    /// No hosted model is sent llama.cpp's `chat_template_kwargs`, which it
    /// would refuse; the local model keeps it. Sampling settings are the
    /// local model's and, as its pair was measured, OpenRouter's.
    #[test]
    fn a_hosted_model_is_sent_no_local_settings() {
        for server in &Server::ALL {
            let (_dir, cfg) = written(&[Source::Cloudtrail], *server);
            let judge = &cfg.inference["judge"];
            let local = matches!(server, Server::Yours | Server::Mtplx);
            assert_eq!(
                judge.extra.contains_key("chat_template_kwargs"),
                local,
                "{server:?}"
            );
            let sampled = local || *server == Server::Hosted(Provider::Openrouter);
            assert_eq!(judge.temperature.is_some(), sampled, "{server:?}");
            assert_eq!(judge.extra.contains_key("top_p"), sampled, "{server:?}");
        }
    }

    /// `--local` is one model on a server tangent starts: one entry under
    /// `models`, which the judge and the reviewer both name, asked one
    /// request at a time, with the command that starts it.
    #[test]
    fn inkling_is_one_model_tangent_starts() {
        let (_dir, cfg) = written(&[Source::Github], Server::Mtplx);
        cfg.validate().unwrap();
        assert_eq!(
            cfg.models.keys().map(|k| &**k).collect::<Vec<_>>(),
            ["inkling"]
        );
        for node in ["judge", "reviewer"] {
            assert_eq!(&*cfg.inference[node].model, "inkling", "{node}");
        }
        let model = &cfg.models["inkling"];
        assert_eq!(model.concurrency, 1);
        assert_eq!(model.timeout_ms, 600_000);
        let serve = model.serve.as_ref().expect("tangent starts it");
        // tangent's own MTPLX and the model, under the cache
        let (mtplx, inkling) = local::paths(&cache());
        let expand = |text: &str| {
            let home = std::env::var("HOME").unwrap_or_default();
            let xdg = std::env::var("XDG_CACHE_HOME").unwrap_or_default();
            text.replace("${HOME}", &home)
                .replace("${XDG_CACHE_HOME}", &xdg)
        };
        assert_eq!(serve.command[0], expand(&mtplx));
        assert_eq!(
            serve.command[1..4],
            ["serve".to_string(), "--model".to_string(), expand(&inkling)]
        );
        let port = serve.command.iter().position(|a| a == "--port").unwrap();
        assert!(
            model
                .url
                .as_deref()
                .unwrap()
                .contains(&format!(":{}/", serve.command[port + 1])),
            "the server listens where the model is asked"
        );
        assert_eq!(serve.env["HF_HUB_OFFLINE"], "1");
        assert_eq!(cfg.inference["judge"].batch_bytes, 32_000);
        // every other pair's judge may be sent an actor's forty records at once
        let (_dir, hosted) = written(&[Source::Github], Server::Hosted(Provider::Anthropic));
        assert_eq!(hosted.inference["judge"].batch_bytes, 96_000);
    }

    /// Inkling is not started on a Mac with less memory than it was
    /// measured to need, and the reason says how much the Mac has. A Mac
    /// that does not say its memory is not refused for it.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn inkling_is_not_started_under_its_memory() {
        let why = unfit(Some(16)).expect("16 GB is under what Inkling needs");
        assert!(why.contains("this Mac has 16 GB of memory"), "{why}");
        assert!(unfit(Some(INKLING_MEMORY - 1)).is_some());
        assert_eq!(unfit(Some(INKLING_MEMORY)), None);
        assert_eq!(unfit(Some(64)), None);
        assert_eq!(unfit(None), None);
    }

    /// The models are hosted unless `--local`: Anthropic's pair or a
    /// provider's models by name, and with `--local` Inkling or, with a
    /// model named, a server of your own.
    #[test]
    fn the_flags_say_who_judges() {
        let both = |name: &str| Some((name.to_string(), name.to_string()));
        assert_eq!(
            served(false, None, None).unwrap(),
            (Server::Hosted(Provider::Anthropic), None)
        );
        assert_eq!(
            served(false, Some(Provider::Openai), Some("gpt-6-luna")).unwrap(),
            (Server::Hosted(Provider::Openai), both("gpt-6-luna"))
        );
        assert_eq!(served(true, None, None).unwrap(), (Server::Mtplx, None));
        assert_eq!(
            served(true, None, Some("glm-4.7-flash")).unwrap(),
            (Server::Yours, both("glm-4.7-flash"))
        );
        assert!(served(false, None, Some("gpt-6-luna")).is_err());
    }

    /// The file's head and init's last lines say where the records go: a
    /// hosted model is sent every one, by name, and a model on this machine
    /// none.
    #[test]
    fn the_file_says_where_the_records_go() {
        for server in &Server::ALL {
            let choices = Choices::new(vec![Source::Okta], *server, None);
            let line = format!("#   records  {}\n", choices.records());
            assert!(choices.header().contains(&line), "{server:?}");
            let local = matches!(server, Server::Yours | Server::Mtplx);
            assert_eq!(line.contains("stay on this machine"), local, "{server:?}");
            assert_eq!(
                line.contains(&format!("are sent to {}", server.pair().host)),
                !local,
                "{server:?}"
            );
        }
    }

    /// The shell's AWS_PROFILE, or `default` when it is unset. The tests
    /// read the variable and set nothing: it is the whole process's, and
    /// other tests run beside these.
    fn profile() -> Option<String> {
        std::env::var("AWS_PROFILE")
            .ok()
            .filter(|p| !p.is_empty())
            .or_else(|| Some("default".to_string()))
    }

    /// On Bedrock the source, the judge and the reviewer use one profile,
    /// the shell's, and the models are called in a US region.
    #[test]
    fn on_bedrock_the_models_use_the_sources_profile() {
        let (_dir, cfg) = written(&[Source::Cloudtrail], Server::Hosted(Provider::Bedrock));
        let SourceConfig::Cloudtrail(source) = &cfg.sources["aws_audit"] else {
            panic!("aws_audit is not a cloudtrail source");
        };
        assert_eq!(source.profile, profile());
        for model in ["judge", "reviewer"] {
            let aws = &cfg.models[model].aws;
            assert_eq!(aws.profile, profile(), "{model}");
            assert_eq!(aws.region.as_deref(), Some("us-west-2"), "{model}");
        }
    }

    /// Replay reads only CloudTrail's past, and run reads CloudTrail only
    /// with a queue: the file and init name the command that reads what was
    /// chosen.
    #[test]
    fn the_commands_are_the_ones_that_read_what_is_watched() {
        let commands = |watch: &[Source]| -> Vec<&'static str> {
            let choices = Choices::new(watch.to_vec(), Server::Hosted(Provider::Anthropic), None);
            let config = choices.config();
            let lines = choices.commands();
            for line in &lines {
                assert!(config.contains(line.as_str()), "{watch:?}: {line}");
            }
            let command = |line: &String| {
                if line.starts_with(REPLAY) {
                    REPLAY
                } else {
                    RUN
                }
            };
            lines.iter().map(command).collect()
        };
        assert_eq!(commands(&[Source::Cloudtrail]), [REPLAY]);
        assert_eq!(commands(&[Source::Okta, Source::Github]), [RUN]);
        assert_eq!(commands(&EVERY), [REPLAY, RUN]);
        let all = Choices::new(EVERY.to_vec(), Server::Hosted(Provider::Anthropic), None);
        assert!(
            all.commands()[1].ends_with(
                "# GitHub, Okta, Google Workspace, Supabase, from an hour back and as it happens"
            ),
            "{:?}",
            all.commands()
        );
    }

    /// The sources are written once each, in one order, however the flag
    /// named them.
    #[test]
    fn the_sources_are_each_once() {
        let named = Choices::new(
            vec![Source::Okta, Source::Cloudtrail, Source::Okta],
            Server::Yours,
            None,
        );
        assert_eq!(named.watch, [Source::Cloudtrail, Source::Okta]);
        assert_eq!(
            names::<Source>(","),
            "cloudtrail,github,okta,google_workspace,supabase"
        );
    }

    /// With no source named, the file is the pipeline without one: it loads,
    /// and says where its sources go.
    #[test]
    fn with_no_source_it_is_the_pipeline_without_one() {
        for server in &Server::ALL {
            let dir = tempfile::tempdir().unwrap();
            let choices = Choices::new(Vec::new(), *server, None);
            choices.write(dir.path()).unwrap();
            let config = choices.config();
            assert!(!config.contains("{{"), "{server:?}:\n{config}");
            assert!(!config.contains("\n\n\n"), "{server:?}: a part left a gap");
            assert!(config.contains("#   watches  nothing yet"), "{config}");
            let cfg = Config::load(&dir.path().join("tangent.yaml"))
                .unwrap_or_else(|e| panic!("{server:?}: {e:#}"))
                .config;
            assert!(cfg.sources.is_empty(), "{server:?}");
            assert_eq!(cfg.inference.len(), 2, "{server:?}");
        }
    }

    /// The models named with a provider are the judge's and the reviewer's,
    /// by those names, with the provider's settings around each: one name
    /// is both, and two are the judge's and then the reviewer's.
    #[test]
    fn the_models_named_are_the_judge_and_the_reviewer() {
        let named = [
            (
                Server::Hosted(Provider::Anthropic),
                "claude-sonnet-5-5",
                "judges and reviews",
            ),
            (
                Server::Hosted(Provider::Bedrock),
                "us.anthropic.claude-haiku-5-5",
                "judges and reviews",
            ),
            (
                Server::Hosted(Provider::Openrouter),
                "z-ai/glm-4.7-flash",
                "judges and reviews",
            ),
            (
                Server::Hosted(Provider::Openai),
                "gpt-6-luna, gpt-6.1-terra",
                "gpt-6-luna judges, gpt-6.1-terra reviews",
            ),
            (
                Server::Yours,
                "qwen3.5:122b,glm-4.7-flash",
                "qwen3.5:122b judges, glm-4.7-flash reviews",
            ),
        ];
        for (server, flag, says) in named {
            let (judge, reviewer) = models(flag).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let choices = Choices::new(
                vec![Source::Github],
                server,
                Some((judge.clone(), reviewer.clone())),
            );
            choices.write(dir.path()).unwrap();
            let cfg = Config::load(&dir.path().join("tangent.yaml"))
                .unwrap_or_else(|e| panic!("{server:?}: {e:#}"))
                .config;
            let (_dir, measured) = written(&[Source::Github], server);
            let shape_of =
                |cfg: &Config, node: &str| serde_yaml::to_value(&cfg.inference[node]).unwrap();
            for (node, name) in [("judge", &judge), ("reviewer", &reviewer)] {
                assert_eq!(&cfg.models[node].model, name, "{server:?} {node}");
                let mut as_measured = shape_of(&cfg, node);
                as_measured["model"] = shape_of(&measured, node)["model"].clone();
                assert_eq!(
                    as_measured,
                    shape_of(&measured, node),
                    "{server:?} {node}: only the model differs"
                );
            }
            let header = choices.header();
            assert!(header.contains(says), "{server:?}: {header}");
        }
    }

    /// `--model` is one name or two: anything else is an error that says so.
    #[test]
    fn a_model_flag_is_one_name_or_two() {
        assert_eq!(models("a").unwrap(), ("a".to_string(), "a".to_string()));
        assert_eq!(models("a, b").unwrap(), ("a".to_string(), "b".to_string()));
        for flag in ["", "a,", ",b", "a,b,c"] {
            let err = format!("{:#}", models(flag).unwrap_err());
            assert!(
                err.contains("one model's name, or the judge's"),
                "{flag}: {err}"
            );
        }
    }

    /// docs/config.md holds every part a source or a provider puts in the
    /// file, as init writes it: the directions are for doing by hand what
    /// the flags do.
    #[test]
    fn the_directions_hold_every_part_init_writes() {
        let directions = include_str!("../../../docs/config.md");
        for source in Source::value_variants() {
            let pack = source.pack();
            for part in [pack.node, &source.plugin(), pack.rows] {
                assert!(directions.contains(part.trim_end()), "{source:?}:\n{part}");
            }
            for (var, _) in pack.needs {
                assert!(directions.contains(var), "{source:?}: {var}");
            }
        }
        for server in &Server::ALL {
            let pair = server.pair();
            for part in [
                pair.judge_model,
                pair.reviewer_model,
                pair.judge,
                pair.reviewer,
            ] {
                // as the file has it where the cache is the home's
                let part = placed(part, "${HOME}/.cache");
                assert!(directions.contains(part.trim_end()), "{server:?}:\n{part}");
            }
        }
        assert!(DIRECTIONS.ends_with("docs/config.md"));
    }

    /// `tangent watch` keeps the file itself: it says so, names no command
    /// that runs a file of your own, loads as init's does, and is written
    /// over what was there, where init's is not.
    #[test]
    fn a_watched_file_is_tangents_own() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tangent.yaml");
        for server in &Server::ALL {
            let kept = Choices::new(vec![Source::Okta], *server, None);
            let watched = kept.clone().watched();
            place(dir.path(), &watched.files()).unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                text.contains("written by `tangent watch cloud`"),
                "{server:?}"
            );
            assert!(!text.contains("--config tangent.yaml"), "{server:?}");
            assert!(!text.contains(DIRECTIONS), "{server:?}");
            let cfg = Config::load(&path).unwrap().config;
            cfg.validate()
                .unwrap_or_else(|e| panic!("{server:?}: {e:#}"));
            assert_eq!(cfg.warnings(), Vec::<String>::new(), "{server:?}");
            // but for its first lines, it is the file init writes
            let body = |text: &str| text[text.find("\nsources:").unwrap()..].to_string();
            assert_eq!(body(&text), body(&kept.config()), "{server:?}");
            assert!(kept.write(dir.path()).is_err(), "init writes over nothing");
        }
    }

    /// A variable two parts read is asked for once: on Bedrock, the profile
    /// that reads CloudTrail is the one that calls the models.
    #[test]
    fn a_variable_is_named_once() {
        let choices = Choices::new(
            vec![Source::Cloudtrail],
            Server::Hosted(Provider::Bedrock),
            None,
        );
        let vars: Vec<&str> = choices.needs().into_iter().map(|(var, _)| var).collect();
        assert_eq!(vars, ["AWS_PROFILE"]);
        let choices = Choices::new(
            vec![Source::Github],
            Server::Hosted(Provider::Anthropic),
            None,
        );
        let vars: Vec<&str> = choices.needs().into_iter().map(|(var, _)| var).collect();
        assert_eq!(vars, ["ANTHROPIC_API_KEY", "GITHUB_ORG", "GITHUB_TOKEN"]);
    }

    /// A file of any of the names already there stops init before it writes
    /// one, and every file is left as it was.
    #[test]
    fn refuses_a_file_already_there_and_writes_nothing() {
        let choices = Choices::new(
            vec![Source::Cloudtrail],
            Server::Hosted(Provider::Anthropic),
            None,
        );
        for (taken, _) in choices.files() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(taken), "mine").unwrap();
            let err = format!("{:#}", choices.write(dir.path()).unwrap_err());
            assert!(err.contains(&format!("{taken} is already here")), "{err}");
            let left: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .flatten()
                .map(|e| e.file_name())
                .collect();
            assert_eq!(left, [std::ffi::OsString::from(taken)], "{taken}");
            assert_eq!(
                std::fs::read_to_string(dir.path().join(taken)).unwrap(),
                "mine"
            );
        }
    }
}
