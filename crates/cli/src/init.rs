//! `tangent init`: a tangent.yaml that replays the AWS account's CloudTrail
//! and has a model judge it, with the packs built in. `--model` says who
//! serves the model.

use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write as _};
use std::path::Path;

/// The config `tangent init` writes for [`Model::Anthropic`]. Another
/// model's is this one with that model's four parts in place of Anthropic's.
const CONFIG: &str = include_str!("init.yaml");

/// Who serves the model that judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Model {
    /// Claude Haiku 5.5 through Anthropic's API, with ANTHROPIC_API_KEY
    Anthropic,
    /// Claude Haiku 5.5 on Amazon Bedrock, with the AWS profile that reads CloudTrail
    Bedrock,
    /// DeepSeek V4 Flash, open weights, through OpenRouter, with OPENROUTER_API_KEY
    Openrouter,
    /// GPT-6 Luna through OpenAI's API, with OPENAI_API_KEY
    Openai,
    /// A local model: a server you run at http://localhost:8080/v1 (llama-server, mlx_lm.server, Ollama, vLLM)
    Local,
}

const HOSTED: &str = "  - pack:judge/hosted          # the judge, for a hosted model, with the enrich-ip and behavior-baseline packs";
const LOCAL: &str = "  - pack:judge                 # the judge, for a local model, with the enrich-ip and behavior-baseline packs";

impl Model {
    /// Who judges, as the file's first lines say it.
    fn judged_by(self) -> &'static str {
        match self {
            Model::Anthropic => "Claude Haiku 5.5 (Anthropic's API)",
            Model::Bedrock => "Claude Haiku 5.5 on Bedrock",
            Model::Openrouter => "DeepSeek V4 Flash (OpenRouter)",
            Model::Openai => "GPT-6 Luna (OpenAI's API)",
            Model::Local => "the local model at localhost:8080",
        }
    }

    /// The variable that holds the model's key, for those that take one.
    fn key(self) -> Option<&'static str> {
        match self {
            Model::Anthropic => Some("ANTHROPIC_API_KEY"),
            Model::Openrouter => Some("OPENROUTER_API_KEY"),
            Model::Openai => Some("OPENAI_API_KEY"),
            Model::Bedrock | Model::Local => None,
        }
    }

    /// The pack the judge comes from: a hosted model's settings, or a local
    /// one's.
    fn include(self) -> &'static str {
        match self {
            Model::Local => LOCAL,
            _ => HOSTED,
        }
    }

    /// The `inference.judge` the config sets over the pack's.
    fn judge(self) -> &'static str {
        match self {
            Model::Anthropic => {
                r#"inference:
  judge:
    backend: anthropic
    url: https://api.anthropic.com
    api_key: "${ANTHROPIC_API_KEY}"                 # a key from console.anthropic.com
    model: claude-haiku-5-5
    max_tokens: 400                                 # per record
    extra: { thinking: { type: disabled } }         # no thinking: the reply is the answer
"#
            }
            Model::Bedrock => {
                r#"inference:
  judge:
    backend: bedrock
    model: us.anthropic.claude-haiku-5-5
    aws: { profile: *profile, region: us-west-2 }   # a US region: Bedrock serves this model there
    max_tokens: 400                                 # per record
    extra: { thinking: { type: disabled } }         # no thinking: the reply is the answer
"#
            }
            Model::Openrouter => {
                r#"inference:
  judge:
    url: https://openrouter.ai/api/v1
    api_key: "${OPENROUTER_API_KEY}"                # a key from openrouter.ai/keys
    model: deepseek/deepseek-v4-flash-0731          # open weights; any model OpenRouter lists
    max_tokens: 400                                 # per record
    extra:
      reasoning: { enabled: false }                 # no thinking: the reply is the answer
      provider: { require_parameters: true }        # only hosts that hold the reply to its schema
"#
            }
            Model::Openai => {
                r#"inference:
  judge:
    url: https://api.openai.com/v1
    api_key: "${OPENAI_API_KEY}"                    # a key from platform.openai.com
    model: gpt-6-luna
    max_tokens: 400                                 # per record
    extra: { reasoning_effort: low }                # little thinking: the reply is the answer
"#
            }
            Model::Local => {
                r#"inference:
  judge:
    url: http://localhost:8080/v1                   # llama-server, mlx_lm.server or vLLM; Ollama is http://localhost:11434/v1
    model: glm-4.7-flash                            # EDIT to the name your server gives its model
"#
            }
        }
    }

    /// What the AWS profile is for, as the comment over it says.
    fn profile(self) -> &'static str {
        match self {
            Model::Bedrock => {
                "# The AWS profile (~/.aws/config) that reads CloudTrail and calls Bedrock:"
            }
            _ => "# The AWS profile (~/.aws/config) that reads CloudTrail:",
        }
    }

    /// The four parts of the config that are a model's own.
    fn parts(self) -> [&'static str; 4] {
        [
            self.judged_by(),
            self.profile(),
            self.include(),
            self.judge(),
        ]
    }

    /// The config for this model.
    pub fn config(self) -> String {
        let mut config = CONFIG.to_string();
        for (anthropic, this) in Model::Anthropic.parts().into_iter().zip(self.parts()) {
            config = config.replacen(anthropic, this, 1);
        }
        config
    }
}

/// Writes `model`'s config to `dir`/tangent.yaml, unless a tangent.yaml is
/// there: the file is created only if missing, in one step, so one already
/// there is never written over. A write that fails removes the part written,
/// which is this call's alone, so a later init is not refused by it.
pub fn run_in(dir: &Path, model: Model) -> Result<()> {
    let path = dir.join("tangent.yaml");
    let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => bail!(
            "tangent.yaml is already here; init leaves it as it is (edit it, or run tangent init in another directory)"
        ),
        Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
    };
    if let Err(e) = file.write_all(model.config().as_bytes()) {
        let _ = std::fs::remove_file(&path);
        return Err(e).with_context(|| format!("writing {}", path.display()));
    }
    println!(
        "Wrote tangent.yaml: CloudTrail, judged by {}. It reads CloudTrail as $AWS_PROFILE, or your default AWS profile when that is unset; to use another, set it on the line marked EDIT.",
        model.judged_by()
    );
    match (model, model.key()) {
        (_, Some(key)) if std::env::var(key).map_or(true, |v| v.trim().is_empty()) => {
            println!("The model's key is read from ${key}, which is not set: export it first.");
        }
        (_, Some(key)) => println!("The model's key is read from ${key}."),
        (Model::Bedrock, None) => println!("The same profile calls Bedrock."),
        (_, None) => println!(
            "Start your model's server first; the line marked EDIT under `inference` names its model."
        ),
    }
    println!("  tangent replay --config tangent.yaml --from 1d");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum as _;
    use tangent_shared::inference::Backend;
    use tangent_shared::sources::common::SourceConfig;

    /// `model`'s config as `tangent init` writes it and as it loads: the
    /// file's text, the source's AWS profile and the judge.
    fn written(
        model: Model,
    ) -> (
        String,
        Option<String>,
        tangent_shared::inference::InferenceConfig,
    ) {
        let dir = tempfile::tempdir().unwrap();
        run_in(dir.path(), model).unwrap();
        loaded(&dir.path().join("tangent.yaml"))
    }

    fn loaded(
        path: &Path,
    ) -> (
        String,
        Option<String>,
        tangent_shared::inference::InferenceConfig,
    ) {
        let cfg = tangent_shared::Config::load(path).unwrap().config;
        cfg.validate().unwrap();
        let SourceConfig::Cloudtrail(source) = &cfg.sources["aws_audit"] else {
            panic!("aws_audit is not a cloudtrail source");
        };
        (
            std::fs::read_to_string(path).unwrap(),
            source.profile.clone(),
            cfg.inference["judge"].clone(),
        )
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

    /// Anthropic's config is init.yaml as it is, and each part another model
    /// replaces is in it once, so every other model's config has all four of
    /// its own.
    #[test]
    fn another_models_config_is_anthropics_with_its_own_four_parts() {
        assert_eq!(Model::Anthropic.config(), CONFIG);
        for part in Model::Anthropic.parts() {
            assert_eq!(CONFIG.matches(part).count(), 1, "{part}");
        }
        for model in Model::value_variants() {
            let config = model.config();
            for part in model.parts() {
                assert_eq!(config.matches(part).count(), 1, "{model:?}: {part}");
            }
        }
    }

    /// Every model's config loads with the packs, reads CloudTrail as the
    /// shell's profile, and names the model it says it does, where that
    /// model is served.
    #[test]
    fn every_models_config_loads_and_names_its_model() {
        for model in Model::value_variants() {
            let (_, source_profile, judge) = written(*model);
            assert_eq!(source_profile, profile(), "{model:?}");
            let (backend, url, name) = match model {
                Model::Anthropic => (
                    Backend::Anthropic,
                    Some("https://api.anthropic.com"),
                    "claude-haiku-5-5",
                ),
                // the pack's address, which Bedrock does not read
                Model::Bedrock => (
                    Backend::Bedrock,
                    Some("http://localhost:8080/v1"),
                    "us.anthropic.claude-haiku-5-5",
                ),
                Model::Openrouter => (
                    Backend::Openai,
                    Some("https://openrouter.ai/api/v1"),
                    "deepseek/deepseek-v4-flash-0731",
                ),
                Model::Openai => (
                    Backend::Openai,
                    Some("https://api.openai.com/v1"),
                    "gpt-6-luna",
                ),
                Model::Local => (
                    Backend::Openai,
                    Some("http://localhost:8080/v1"),
                    "glm-4.7-flash",
                ),
            };
            assert_eq!(judge.backend, backend, "{model:?}");
            assert_eq!(judge.url.as_deref(), url, "{model:?}");
            assert_eq!(judge.model, name, "{model:?}");
        }
    }

    /// A hosted model gets the hosted judge's settings: none of the sampling
    /// a local model is given, which a hosted one may refuse. The local model
    /// keeps them.
    #[test]
    fn a_hosted_model_is_sent_no_sampling_settings() {
        for model in Model::value_variants() {
            let (_, _, judge) = written(*model);
            let local = *model == Model::Local;
            assert_eq!(judge.temperature.is_some(), local, "{model:?}");
            assert_eq!(judge.extra.contains_key("top_p"), local, "{model:?}");
        }
    }

    /// On Bedrock the source and the judge share one profile, and the judge
    /// calls a US region.
    #[test]
    fn on_bedrock_the_judge_uses_the_sources_profile() {
        let (_, source_profile, judge) = written(Model::Bedrock);
        assert_eq!(judge.aws.profile, source_profile);
        assert_eq!(judge.aws.region.as_deref(), Some("us-west-2"));
    }

    /// The profile is a quoted scalar: a name with ` #` or `: ` in it is
    /// the whole name, not a comment's start or a mapping.
    #[test]
    fn a_profile_name_is_taken_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tangent.yaml");
        let config = Model::Bedrock.config();
        let named = config.replace("${AWS_PROFILE:-default}", "team #1: prod");
        assert_ne!(named, config);
        std::fs::write(&path, named).unwrap();
        let want = Some("team #1: prod".to_string());
        let (_, source_profile, judge) = loaded(&path);
        assert_eq!((source_profile, judge.aws.profile), (want.clone(), want));
    }

    #[test]
    fn refuses_a_tangent_yaml_already_there_and_leaves_it_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        run_in(dir.path(), Model::Anthropic).unwrap();
        let path = dir.path().join("tangent.yaml");
        let config = Model::Anthropic.config();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), config);
        let edited = config.replace("${AWS_PROFILE:-default}", "prod");
        assert_ne!(edited, config);
        std::fs::write(&path, &edited).unwrap();

        let err = format!("{:#}", run_in(dir.path(), Model::Bedrock).unwrap_err());
        assert!(err.contains("tangent.yaml is already here"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), edited.as_bytes());
    }
}
