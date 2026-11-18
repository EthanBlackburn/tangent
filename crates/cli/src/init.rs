//! `tangent init`: a tangent.yaml that replays the AWS account's CloudTrail
//! and has a model judge it, with the packs built in. `--model` says who
//! serves the model. Where the judge pack has a provider's pair, a second
//! model reviews what the first flagged.

use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write as _};
use std::path::Path;

/// The config `tangent init` writes for [`Model::Anthropic`]: a judge and a
/// reviewer, from the provider's pack. OpenRouter's is this one with its own
/// parts in place of Anthropic's.
const REVIEWED: &str = include_str!("init.yaml");

/// The config for [`Model::Bedrock`]: a judge alone, its settings in the
/// file. OpenAI's and a local model's are this one with their own parts in
/// place of Bedrock's.
const JUDGED: &str = include_str!("init-judge.yaml");

/// Who serves the model that judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Model {
    /// Claude Haiku 5.5, reviewed by Claude Sonnet 5.5, through Anthropic's API, with ANTHROPIC_API_KEY
    Anthropic,
    /// Claude Haiku 5.5 on Amazon Bedrock, with the AWS profile that reads CloudTrail
    Bedrock,
    /// DeepSeek V4 Flash, open weights, which also reviews, through OpenRouter, with OPENROUTER_API_KEY
    Openrouter,
    /// GPT-6 Luna through OpenAI's API, with OPENAI_API_KEY
    Openai,
    /// A local model: a server you run at http://localhost:8080/v1 (llama-server, mlx_lm.server, Ollama, vLLM)
    Local,
}

const ANTHROPIC: &str = "  - pack:judge/anthropic       # Claude Haiku 5.5 judges, Claude Sonnet 5.5 reviews; the key is $ANTHROPIC_API_KEY, from console.anthropic.com";
const OPENROUTER: &str = "  - pack:judge/openrouter      # DeepSeek V4 Flash judges and reviews; the key is $OPENROUTER_API_KEY, from openrouter.ai/keys";
const HOSTED: &str = "  - pack:judge/hosted          # the judge, for a hosted model, with the enrich-ip and behavior-baseline packs";
const LOCAL: &str = "  - pack:judge                 # the judge, for a local model, with the enrich-ip and behavior-baseline packs";

impl Model {
    /// Who judges, and who reviews, as the file's first lines say it.
    fn judged_by(self) -> &'static str {
        match self {
            Model::Anthropic => "judged by Claude Haiku 5.5, and what it flags reviewed by Claude Sonnet 5.5 (Anthropic's API)",
            Model::Bedrock => "judged by Claude Haiku 5.5 on Bedrock",
            Model::Openrouter => "judged by DeepSeek V4 Flash, and what it flags reviewed by the same model (OpenRouter)",
            Model::Openai => "judged by GPT-6 Luna (OpenAI's API)",
            Model::Local => "judged by the local model at localhost:8080",
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

    /// The pack the judge comes from: the provider's pair, a hosted model's
    /// settings, or a local one's.
    fn include(self) -> &'static str {
        match self {
            Model::Anthropic => ANTHROPIC,
            Model::Openrouter => OPENROUTER,
            Model::Local => LOCAL,
            Model::Bedrock | Model::Openai => HOSTED,
        }
    }

    /// The `inference.judge` the config sets over the pack's, for a model
    /// whose pack does not name it.
    fn judge(self) -> Option<&'static str> {
        Some(match self {
            Model::Anthropic | Model::Openrouter => return None,
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
        })
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

    /// The parts of the config that are a model's own.
    fn parts(self) -> Vec<&'static str> {
        let mut parts = vec![self.judged_by(), self.profile(), self.include()];
        parts.extend(self.judge());
        parts
    }

    /// The model whose config this one's is made from, and that config: a
    /// judge and a reviewer where the provider has a pack of the pair, a
    /// judge alone where it has not.
    fn base(self) -> (Model, &'static str) {
        match self {
            Model::Anthropic | Model::Openrouter => (Model::Anthropic, REVIEWED),
            Model::Bedrock | Model::Openai | Model::Local => (Model::Bedrock, JUDGED),
        }
    }

    /// The config for this model.
    pub fn config(self) -> String {
        let (base, config) = self.base();
        let mut config = config.to_string();
        for (theirs, this) in base.parts().into_iter().zip(self.parts()) {
            config = config.replacen(theirs, this, 1);
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
        "Wrote tangent.yaml: CloudTrail, {}. It reads CloudTrail as $AWS_PROFILE, or your default AWS profile when that is unset; to use another, set it on the line marked EDIT.",
        model.judged_by()
    );
    match (model, model.key()) {
        (_, Some(key)) if std::env::var(key).map_or(true, |v| v.trim().is_empty()) => {
            println!("The key is read from ${key}, which is not set: export it first.");
        }
        (_, Some(key)) => println!("The key is read from ${key}."),
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

    /// Anthropic's config is init.yaml as it is and Bedrock's is
    /// init-judge.yaml, and each part another model replaces is in its base
    /// once, so every other model's config has all of its own.
    #[test]
    fn a_models_config_is_its_base_s_with_its_own_parts() {
        assert_eq!(Model::Anthropic.config(), REVIEWED);
        assert_eq!(Model::Bedrock.config(), JUDGED);
        for model in Model::value_variants() {
            let (base, text) = model.base();
            assert_eq!(base.base().0, base, "{model:?}: its base is a base");
            assert_eq!(base.parts().len(), model.parts().len(), "{model:?}");
            for part in base.parts() {
                assert_eq!(text.matches(part).count(), 1, "{base:?}: {part}");
            }
            let config = model.config();
            for part in model.parts() {
                assert_eq!(config.matches(part).count(), 1, "{model:?}: {part}");
            }
        }
    }

    /// Anthropic's and OpenRouter's configs have the provider's pair: a
    /// reviewer, the lake it reads, which the plugin's records are routed
    /// to, and reviews.ndjson. The others have a judge alone.
    #[test]
    fn a_provider_with_a_pair_gets_its_reviewer() {
        for model in Model::value_variants() {
            let dir = tempfile::tempdir().unwrap();
            run_in(dir.path(), *model).unwrap();
            let cfg = tangent_shared::Config::load(&dir.path().join("tangent.yaml"))
                .unwrap()
                .config;
            cfg.validate().unwrap();
            let reviewed = matches!(model, Model::Anthropic | Model::Openrouter);
            assert_eq!(
                cfg.inference.contains_key("reviewer"),
                reviewed,
                "{model:?}"
            );
            assert_eq!(cfg.sinks.contains_key("reviews"), reviewed, "{model:?}");
            let kept = cfg
                .edges()
                .iter()
                .any(|e| &*e.from == "cloudtrail" && e.to.iter().any(|t| &**t == "lake"));
            assert_eq!(kept, reviewed, "{model:?}");
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

    /// No hosted model is sent llama.cpp's `chat_template_kwargs`, which it
    /// would refuse; the local model keeps it. Sampling settings are the
    /// local model's and, as its pair was measured, OpenRouter's.
    #[test]
    fn a_hosted_model_is_sent_no_local_settings() {
        for model in Model::value_variants() {
            let (_, _, judge) = written(*model);
            let local = *model == Model::Local;
            assert_eq!(
                judge.extra.contains_key("chat_template_kwargs"),
                local,
                "{model:?}"
            );
            let sampled = matches!(model, Model::Local | Model::Openrouter);
            assert_eq!(judge.temperature.is_some(), sampled, "{model:?}");
            assert_eq!(judge.extra.contains_key("top_p"), sampled, "{model:?}");
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
