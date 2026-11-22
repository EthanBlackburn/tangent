//! `tangent init`: asks what to watch and which models judge it, and writes
//! the whole pipeline to tangent.yaml, with what the two models are told
//! beside it (judge.md, judge.schema.json, review.md). Nothing is left in a
//! file tangent keeps: every node, its settings and its `inputs` are in the
//! file written, to read and to edit.
//!
//! At a terminal the two questions are menus. Away from one, for a script or
//! an agent, init prints them with every answer's name and reads the answers
//! from stdin, a line each. The plugins the config names are fetched, and
//! the attestation of each build checked, before a file is written: init
//! leaves a pipeline that runs, or nothing.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufRead, ErrorKind, IsTerminal as _, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::ValueEnum as _;
use tangent_shared::packs;

use crate::fetch;

/// tangent.yaml with its sources, their plugins and rows, and the two
/// models' settings left out: `{{name}}` where each goes.
const CONFIG: &str = include_str!("init.yaml");

/// Where a pack's compiled plugin comes from: this repository's release, as
/// built by the workflow that attests it.
const PREBUILT: &str =
    "{ repo: EthanBlackburn/tangent, workflow: .github/workflows/attest-packs.yml }";

/// The command that reads a source's past, and the one that reads sources
/// as they are written.
const REPLAY: &str = "tangent replay --config tangent.yaml --from 1d";
const RUN: &str = "tangent run --config tangent.yaml";

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
    /// The pack, and its plugin: the name the source is answered by.
    name: &'static str,
    /// What the question calls it.
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
    queue_url: ${CLOUDTRAIL_QUEUE_URL}   # for `tangent run`: the SQS queue the trail's bucket notifies; replay needs none
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

/// Who serves the models. Each brings its pair, the model that judges and
/// the one that reviews what it flagged, measured together, with the
/// settings it was measured with.
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
    /// A model on this machine judges and reviews: a server you run at http://localhost:8080/v1 (llama-server, mlx_lm.server, Ollama, vLLM)
    Local,
}

/// What a pair brings to the config.
struct Pair {
    /// Who judges, who reviews, and who serves them, as the file says it.
    label: &'static str,
    /// The same as the question lists it, in a line with `measured`.
    choice: &'static str,
    /// What the pair did over tangent-eval's cloud logs: attacks caught of
    /// 71, and ordinary records still flagged after review, of 5,304.
    measured: &'static str,
    /// The judge's own settings, under `inference.judge`.
    judge: &'static str,
    /// The reviewer's, under `inference.reviewer`.
    reviewer: &'static str,
    needs: Needs,
}

impl Provider {
    fn pair(self) -> Pair {
        match self {
            Provider::Anthropic => Pair {
                label: "Claude Haiku 5.5 judges, Claude Sonnet 5.5 reviews (Anthropic's API)",
                choice: "Claude Haiku 5.5, Sonnet 5.5 reviews (Anthropic)",
                measured: "70 of 71, 40 flagged",
                judge: r#"    backend: anthropic
    api_key: "${ANTHROPIC_API_KEY}"   # a key from console.anthropic.com
    model: claude-haiku-5-5
    max_tokens: 400              # per record
    extra: { thinking: { type: disabled } }   # no thinking: the reply is the answer
"#,
                reviewer: r#"    backend: anthropic
    api_key: "${ANTHROPIC_API_KEY}"
    model: claude-sonnet-5-5
    extra:
      thinking: { type: adaptive }   # it thinks before each query and its report, briefly
      output_config: { effort: low }
"#,
                needs: &[("ANTHROPIC_API_KEY", "a key from console.anthropic.com")],
            },
            Provider::Bedrock => Pair {
                label: "Claude Haiku 5.5 judges, Claude Sonnet 5.5 reviews (Amazon Bedrock)",
                choice: "Claude Haiku 5.5, Sonnet 5.5 reviews (Bedrock)",
                measured: "the same pair",
                judge: r#"    backend: bedrock
    model: us.anthropic.claude-haiku-5-5
    aws: { profile: "${AWS_PROFILE:-default}", region: us-west-2 }   # a US region: Bedrock serves this model there
    max_tokens: 400              # per record
    extra: { thinking: { type: disabled } }   # no thinking: the reply is the answer
"#,
                reviewer: r#"    backend: bedrock
    model: us.anthropic.claude-sonnet-5-5
    aws: { profile: "${AWS_PROFILE:-default}", region: us-west-2 }
    extra:
      thinking: { type: adaptive }   # it thinks before each query and its report, briefly
      output_config: { effort: low }
"#,
                needs: &[(
                    "AWS_PROFILE",
                    "the AWS profile that calls Bedrock, with access to both models in the US regions; `default` when unset",
                )],
            },
            Provider::Openrouter => Pair {
                label: "DeepSeek V4 Flash, open weights, judges and reviews (OpenRouter)",
                choice: "DeepSeek V4 Flash, reviews itself (OpenRouter)",
                measured: "71 of 71, 10 to 13 flagged",
                judge: r#"    url: https://openrouter.ai/api/v1
    api_key: "${OPENROUTER_API_KEY}"   # a key from openrouter.ai/keys
    model: deepseek/deepseek-v4-flash-0731
    max_tokens: 200              # per record
    temperature: 0.7             # with top_p, the sampling it was measured with
    extra:
      top_p: 0.95
      reasoning: { enabled: false }            # no thinking: the reply is the answer
      provider: { require_parameters: true }   # only hosts that hold the reply to its schema
"#,
                reviewer: r#"    url: https://openrouter.ai/api/v1
    api_key: "${OPENROUTER_API_KEY}"
    model: deepseek/deepseek-v4-flash-0731
    extra:
      reasoning: { effort: low }   # it thinks before each query and its report, briefly
"#,
                needs: &[("OPENROUTER_API_KEY", "a key from openrouter.ai/keys")],
            },
            Provider::Openai => Pair {
                label: "GPT-6 Luna judges, GPT-6.1 Terra reviews (OpenAI's API)",
                choice: "GPT-6 Luna, GPT-6.1 Terra reviews (OpenAI)",
                measured: "71 of 71, 20 flagged",
                judge: r#"    backend: responses           # OpenAI's Responses API
    api_key: "${OPENAI_API_KEY}"   # a key from platform.openai.com
    model: gpt-6-luna
    max_tokens: 400              # per record, its thinking included
    extra:
      reasoning: { effort: low }   # little thinking: the reply is the answer
"#,
                reviewer: r#"    backend: responses
    api_key: "${OPENAI_API_KEY}"
    model: gpt-6.1-terra
    extra:
      reasoning: { effort: low }   # it thinks before each query and its report, briefly
"#,
                needs: &[("OPENAI_API_KEY", "a key from platform.openai.com")],
            },
            Provider::Local => Pair {
                label: "A model on this machine judges and reviews (llama-server, mlx_lm.server, Ollama, vLLM)",
                choice: "A model on this machine, reviews itself",
                measured: "not measured",
                judge: r#"    url: http://localhost:8080/v1   # llama-server, mlx_lm.server or vLLM; Ollama is http://localhost:11434/v1
    model: glm-4.7-flash         # EDIT to the name your server gives its model
    max_tokens: 200              # per record
    temperature: 0.7
    extra:
      top_p: 0.95
      chat_template_kwargs: { enable_thinking: false }   # no thinking: the reply is the answer
"#,
                reviewer: r#"    url: http://localhost:8080/v1
    model: glm-4.7-flash         # EDIT, as the judge's
"#,
                needs: &[],
            },
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pair = self.pair();
        write!(f, "{:48}  {}", pair.choice, pair.measured)
    }
}

/// What a config is written for: the sources, in the order `Source` lists
/// them and each once, and the pair of models.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choices {
    watch: Vec<Source>,
    provider: Provider,
}

impl Choices {
    /// `watch` must name a source: a pipeline with none reads nothing.
    pub fn new(mut watch: Vec<Source>, provider: Provider) -> Result<Self> {
        if watch.is_empty() {
            bail!(
                "nothing to watch: name a source, one or more of {}",
                names::<Source>(", ")
            );
        }
        watch.sort();
        watch.dedup();
        Ok(Self { watch, provider })
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
    fn needs(&self) -> Vec<(&'static str, &'static str)> {
        let mut needs: Vec<(&'static str, &'static str)> = Vec::new();
        let packs = self.watch.iter().flat_map(|w| w.pack().needs);
        for need in self.provider.pair().needs.iter().chain(packs) {
            if !needs.iter().any(|(var, _)| var == &need.0) {
                needs.push(*need);
            }
        }
        needs
    }

    /// The file's first lines: what it watches, who judges, how to run it
    /// and where the answers go.
    fn header(&self) -> String {
        let pair = self.provider.pair();
        let mut header = String::from("# tangent.yaml, written by `tangent init`.\n#\n");
        for (i, w) in self.watch.iter().enumerate() {
            let lead = if i == 0 { "watches" } else { "" };
            header.push_str(&format!("#   {lead:7}  {}\n", w.pack().label));
        }
        header.push_str(&format!("#   models   {}\n#\n", pair.label));
        for command in self.commands() {
            header.push_str(&format!("#   {command}\n"));
        }
        header.push_str(
            "#\n# What the judge flagged is in alerts.ndjson, each alert with its review in\n\
             # reviews.ndjson (those are the ones to read), and every verdict in\n\
             # verdicts.ndjson.\n#",
        );
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
        let pair = self.provider.pair();
        // Each part ends its last line, and so does the line it stands on.
        let block = |text: &str| text.trim_end().to_string();
        [
            ("{{header}}", self.header()),
            ("{{flow}}", flow.join("\n#   ")),
            ("{{sources}}", block(&join(|p| p.node))),
            ("{{packs}}", block(&plugins)),
            ("{{inputs}}", inputs.join(", ")),
            ("{{judge}}", block(pair.judge)),
            ("{{rows}}", block(&join(|p| p.rows))),
            ("{{reviewer}}", block(pair.reviewer)),
        ]
        .into_iter()
        .fold(CONFIG.to_string(), |config, (place, part)| {
            config.replace(place, &part)
        })
    }

    /// Every file init writes, by name, with its text: tangent.yaml, and
    /// what the two models are told.
    fn files(&self) -> Vec<(&'static str, String)> {
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
        let files = self.files();
        if let Some((name, _)) = files.iter().find(|(name, _)| dir.join(name).exists()) {
            bail!(
                "{name} is already here; init leaves it as it is, and writes nothing (run tangent init in another directory)"
            );
        }
        let mut written = Vec::new();
        for (name, text) in &files {
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
}

fn remove(paths: &[PathBuf]) {
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

/// The name an answer is given by.
fn name<T: clap::ValueEnum>(value: &T) -> String {
    value
        .to_possible_value()
        .map(|v| v.get_name().to_string())
        .unwrap_or_default()
}

/// Every answer to a question, by name, joined by `sep`.
fn names<T: clap::ValueEnum>(sep: &str) -> String {
    let names: Vec<String> = T::value_variants().iter().map(name).collect();
    names.join(sep)
}

/// The two questions as text, each answer by its name: what init prints
/// away from a terminal, where it can draw no menu.
fn questions() -> String {
    let mut text = String::from(
        "tangent init writes tangent.yaml from two answers. This is not a terminal, so it reads them from stdin, a line each:\n\
         \n  printf 'cloudtrail,github\\nanthropic\\n' | tangent init\n\
         \n1. What do you want to watch? One or more of these names, with commas between:\n\n",
    );
    for source in Source::value_variants() {
        text += &format!("  {:18}{source}\n", name(source));
    }
    text += "\n2. Who serves the models? One of these names. Each brings a model that judges every record and one that reviews what it flagged; in brackets, the attacks the two caught and the ordinary records they flagged, of 5,304, in tangent's evals:\n\n";
    for provider in Provider::value_variants() {
        let pair = provider.pair();
        text += &format!(
            "  {:12}{} [{}]\n",
            name(provider),
            pair.label,
            pair.measured
        );
    }
    text
}

/// The choices away from a terminal: the questions are written to `asked`,
/// and a line of `answers` is read for each.
fn answered(answers: impl BufRead, mut asked: impl Write) -> Result<Choices> {
    let _ = writeln!(asked, "{}", questions());
    let mut lines = answers.lines();
    let mut answer = |question: &str| -> Result<String> {
        match lines
            .next()
            .transpose()
            .context("stdin could not be read")?
        {
            Some(line) if !line.trim().is_empty() => Ok(line.trim().to_string()),
            _ => bail!("{question} has no answer on stdin: answer both, a line each, as above"),
        }
    };
    let watch = answer("question 1, what to watch,")?
        .split(',')
        .map(|name| {
            Source::from_str(name.trim(), true).map_err(|_| {
                anyhow!(
                    "`{}` is not a source: question 1 takes one or more of {}",
                    name.trim(),
                    names::<Source>(", ")
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let provider = answer("question 2, who serves the models,")?;
    let provider = Provider::from_str(&provider, true).map_err(|_| {
        anyhow!(
            "`{provider}` does not serve the models: question 2 takes one of {}",
            names::<Provider>(", ")
        )
    })?;
    Choices::new(watch, provider)
}

/// The choices: at a terminal a menu for each question, and away from one
/// the questions as text and the answers from stdin.
fn choices() -> Result<Choices> {
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        return answered(std::io::stdin().lock(), std::io::stderr());
    }
    let watch = inquire::MultiSelect::new(
        "What do you want to watch?",
        Source::value_variants().to_vec(),
    )
    .with_validator(inquire::min_length!(1, "Pick at least one, with space"))
    .prompt()
    .context("nothing is written")?;
    let provider = inquire::Select::new(
        "Which models judge it, and review what is flagged?",
        Provider::value_variants().to_vec(),
    )
    .with_help_message("attacks caught, and ordinary records flagged of 5,304, in tangent's evals")
    .prompt()
    .context("nothing is written")?;
    Choices::new(watch, provider)
}

/// `tangent init` in `dir`: the choices, the files, and the plugins the
/// config names, fetched and checked. A fetch that fails takes the files
/// with it, so what is left runs or is nothing.
pub async fn run(dir: &Path) -> Result<()> {
    let choices = choices()?;
    let written = choices.write(dir)?;
    let config = dir.join("tangent.yaml");
    if let Err(e) = fetch::missing(&config.canonicalize().unwrap_or(config)).await {
        remove(&written);
        return Err(
            e.context("a plugin the config names could not be fetched, so nothing is written")
        );
    }

    let names: Vec<String> = written
        .iter()
        .filter_map(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .collect();
    println!("\nWrote {}.", names.join(", "));
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
    if choices.provider == Provider::Local {
        println!("\nStart your model's server first; the lines marked EDIT in tangent.yaml name its model.");
    }
    println!("\nThen:");
    for command in choices.commands() {
        println!("  {command}");
    }
    if !choices.runs() {
        println!(
            "\n`tangent run` reads CloudTrail as it is written once tangent.yaml's `queue_url` names the trail's queue."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml::Value;
    use tangent_shared::inference::Backend;
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
    fn written(watch: &[Source], provider: Provider) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let choices = Choices::new(watch.to_vec(), provider).unwrap();
        choices.write(dir.path()).unwrap();
        let cfg = Config::load(&dir.path().join("tangent.yaml"))
            .unwrap_or_else(|e| panic!("{watch:?}, {provider:?}: {e:#}"))
            .config;
        cfg.validate()
            .unwrap_or_else(|e| panic!("{watch:?}, {provider:?}: {e:#}"));
        (dir, cfg)
    }

    /// Every source alone, and all five together, with every pair: the
    /// config loads, passes what `tangent run` checks, and warns of nothing
    /// in its wiring.
    #[test]
    fn every_choice_is_a_pipeline_that_loads() {
        let mut sets: Vec<Vec<Source>> = EVERY.iter().map(|w| vec![*w]).collect();
        sets.push(EVERY.to_vec());
        for watch in &sets {
            for provider in Provider::value_variants() {
                let (_dir, cfg) = written(watch, *provider);
                assert_eq!(
                    cfg.warnings(),
                    Vec::<String>::new(),
                    "{watch:?}, {provider:?}"
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
        for provider in Provider::value_variants() {
            let config = Choices::new(EVERY.to_vec(), *provider).unwrap().config();
            assert!(!config.contains("{{"), "{provider:?}:\n{config}");
            assert!(
                !config.contains("\n\n\n"),
                "{provider:?}: a part left a gap"
            );
        }
    }

    /// A config as it loads, as YAML to compare: without the paths that say
    /// where a file is rather than what it holds.
    fn shape(cfg: &Config) -> Value {
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
    fn settings(value: &Value, at: &str, out: &mut Vec<String>) {
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
        for (provider, pack) in [
            (Provider::Anthropic, "anthropic"),
            (Provider::Openrouter, "openrouter"),
        ] {
            let (_dir, ours) = written(&EVERY, provider);

            let choices = Choices::new(EVERY.to_vec(), provider).unwrap();
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
                if provider == Provider::Anthropic {
                    value["inference"]["judge"]
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
                "{provider:?}: settings only init writes, and only the packs have"
            );
            assert!(
                written.len() > 150,
                "{provider:?}: {} settings",
                written.len()
            );
        }
    }

    /// What the models are told is written beside the config as the judge
    /// pack has it, and the config names those files.
    #[test]
    fn the_briefs_are_the_judge_packs_beside_the_config() {
        let (dir, cfg) = written(&[Source::Cloudtrail], Provider::Anthropic);
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
    /// and its reviewer is the provider's own.
    #[test]
    fn every_pair_names_its_models() {
        for provider in Provider::value_variants() {
            let (_dir, cfg) = written(&[Source::Cloudtrail], *provider);
            let (judge, reviewer) = (&cfg.inference["judge"], &cfg.inference["reviewer"]);
            let (backend, url, judges, reviews) = match provider {
                Provider::Anthropic => (
                    Backend::Anthropic,
                    None,
                    "claude-haiku-5-5",
                    "claude-sonnet-5-5",
                ),
                Provider::Bedrock => (
                    Backend::Bedrock,
                    None,
                    "us.anthropic.claude-haiku-5-5",
                    "us.anthropic.claude-sonnet-5-5",
                ),
                Provider::Openrouter => (
                    Backend::Openai,
                    Some("https://openrouter.ai/api/v1"),
                    "deepseek/deepseek-v4-flash-0731",
                    "deepseek/deepseek-v4-flash-0731",
                ),
                Provider::Openai => (Backend::Responses, None, "gpt-6-luna", "gpt-6.1-terra"),
                Provider::Local => (
                    Backend::Openai,
                    Some("http://localhost:8080/v1"),
                    "glm-4.7-flash",
                    "glm-4.7-flash",
                ),
            };
            for node in [judge, reviewer] {
                assert_eq!(node.backend, backend, "{provider:?}");
                assert_eq!(node.url.as_deref(), url, "{provider:?}");
            }
            assert_eq!(
                (judge.model.as_str(), reviewer.model.as_str()),
                (judges, reviews)
            );
            assert!(
                reviewer.inputs.is_empty(),
                "{provider:?}: the plugin calls it"
            );
            assert_eq!(reviewer.max_tokens, 8000, "{provider:?}");
        }
    }

    /// No hosted model is sent llama.cpp's `chat_template_kwargs`, which it
    /// would refuse; the local model keeps it. Sampling settings are the
    /// local model's and, as its pair was measured, OpenRouter's.
    #[test]
    fn a_hosted_model_is_sent_no_local_settings() {
        for provider in Provider::value_variants() {
            let (_dir, cfg) = written(&[Source::Cloudtrail], *provider);
            let judge = &cfg.inference["judge"];
            let local = *provider == Provider::Local;
            assert_eq!(
                judge.extra.contains_key("chat_template_kwargs"),
                local,
                "{provider:?}"
            );
            let sampled = matches!(provider, Provider::Local | Provider::Openrouter);
            assert_eq!(judge.temperature.is_some(), sampled, "{provider:?}");
            assert_eq!(judge.extra.contains_key("top_p"), sampled, "{provider:?}");
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
        let (_dir, cfg) = written(&[Source::Cloudtrail], Provider::Bedrock);
        let SourceConfig::Cloudtrail(source) = &cfg.sources["aws_audit"] else {
            panic!("aws_audit is not a cloudtrail source");
        };
        assert_eq!(source.profile, profile());
        for node in ["judge", "reviewer"] {
            let aws = &cfg.inference[node].aws;
            assert_eq!(aws.profile, profile(), "{node}");
            assert_eq!(aws.region.as_deref(), Some("us-west-2"), "{node}");
        }
    }

    /// Replay reads only CloudTrail's past, and run reads CloudTrail only
    /// with a queue: the file and init name the command that reads what was
    /// chosen.
    #[test]
    fn the_commands_are_the_ones_that_read_what_is_watched() {
        let commands = |watch: &[Source]| -> Vec<&'static str> {
            let choices = Choices::new(watch.to_vec(), Provider::Anthropic).unwrap();
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
        let all = Choices::new(EVERY.to_vec(), Provider::Anthropic).unwrap();
        assert!(
            all.commands()[1].ends_with(
                "# GitHub, Okta, Google Workspace, Supabase, from an hour back and as it happens"
            ),
            "{:?}",
            all.commands()
        );
    }

    /// The sources are written once each, in one order, however the flag
    /// named them; and a pipeline needs one.
    #[test]
    fn the_sources_are_each_once_and_at_least_one() {
        let named = Choices::new(
            vec![Source::Okta, Source::Cloudtrail, Source::Okta],
            Provider::Local,
        )
        .unwrap();
        assert_eq!(named.watch, [Source::Cloudtrail, Source::Okta]);
        let err = Choices::new(Vec::new(), Provider::Local).unwrap_err();
        assert!(format!("{err:#}").contains("nothing to watch"), "{err:#}");
        assert_eq!(
            names::<Source>(","),
            "cloudtrail,github,okta,google_workspace,supabase"
        );
    }

    /// Away from a terminal the questions are text that names every answer,
    /// and the answers are lines.
    #[test]
    fn away_from_a_terminal_the_answers_are_lines() {
        let mut asked = Vec::new();
        let choices = answered("okta, cloudtrail\nlocal\n".as_bytes(), &mut asked).unwrap();
        assert_eq!(choices.watch, [Source::Cloudtrail, Source::Okta]);
        assert_eq!(choices.provider, Provider::Local);
        let asked = String::from_utf8(asked).unwrap();
        for answer in names::<Source>(",")
            .split(',')
            .chain(names::<Provider>(",").split(','))
        {
            assert!(
                asked.contains(&format!("\n  {answer} ")),
                "{answer}: {asked}"
            );
        }
        assert!(asked.contains("| tangent init"), "{asked}");
    }

    /// An answer left out or misnamed is an error that says which question,
    /// and what it takes.
    #[test]
    fn an_answer_left_out_or_misnamed_says_which() {
        let error = |answers: &str| {
            let err = answered(answers.as_bytes(), std::io::sink()).unwrap_err();
            format!("{err:#}")
        };
        assert!(error("").contains("question 1"), "{}", error(""));
        assert!(error("\nlocal\n").contains("question 1"));
        assert!(error("cloudtrail\n").contains("question 2"));
        let misnamed = error("cloudtrail,splunk\nlocal\n");
        assert!(misnamed.contains("`splunk` is not a source"), "{misnamed}");
        assert!(misnamed.contains("google_workspace"), "{misnamed}");
        let misnamed = error("cloudtrail\nclaude\n");
        assert!(
            misnamed.contains("`claude` does not serve the models"),
            "{misnamed}"
        );
        assert!(misnamed.contains("openrouter"), "{misnamed}");
    }

    /// Each pair's line in the question fits an 80-column terminal, with
    /// the two columns the list's own marker takes.
    #[test]
    fn a_pairs_line_fits_a_terminal() {
        for provider in Provider::value_variants() {
            let line = provider.to_string();
            assert!(line.chars().count() <= 78, "{provider:?}: {line}");
            assert!(provider.pair().choice.len() <= 48, "{provider:?}");
        }
    }

    /// A variable two parts read is asked for once: on Bedrock, the profile
    /// that reads CloudTrail is the one that calls the models.
    #[test]
    fn a_variable_is_named_once() {
        let choices = Choices::new(vec![Source::Cloudtrail], Provider::Bedrock).unwrap();
        let vars: Vec<&str> = choices.needs().into_iter().map(|(var, _)| var).collect();
        assert_eq!(vars, ["AWS_PROFILE"]);
        let choices = Choices::new(vec![Source::Github], Provider::Anthropic).unwrap();
        let vars: Vec<&str> = choices.needs().into_iter().map(|(var, _)| var).collect();
        assert_eq!(vars, ["ANTHROPIC_API_KEY", "GITHUB_ORG", "GITHUB_TOKEN"]);
    }

    /// A file of any of the names already there stops init before it writes
    /// one, and every file is left as it was.
    #[test]
    fn refuses_a_file_already_there_and_writes_nothing() {
        let choices = Choices::new(vec![Source::Cloudtrail], Provider::Anthropic).unwrap();
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
