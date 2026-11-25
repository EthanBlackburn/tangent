//! A model, as an entry under `models` describes it: the client that reaches
//! it, and the limits every node that names it shares.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rig_core::completion::request::CompletionRequest;
use rig_core::completion::{CompletionResponse, FinishReason};
use rig_core::operation::Completion;
use rig_core::providers::anthropic::AnthropicConfig;
use rig_core::providers::openai::{OpenAIConfig, Route};
use rig_core::DynModel;
use secrecy::ExposeSecret;
use tangent_shared::models::{ModelConfig, ModelKind, DEFAULT_URL};
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::stop::Stop;

pub struct Model {
    pub name: Arc<str>,
    pub cfg: ModelConfig,
    client: DynModel<Completion>,
    /// `fallback`, reached as this model is: who is asked what it declines.
    fallback: Option<(Arc<str>, DynModel<Completion>)>,
    /// `concurrency` permits: requests in flight to this model, from every
    /// node that names it.
    sem: Semaphore,
    /// The run's stop: once it is finishing, a request sent is not sent
    /// again, and the nodes send no new one.
    stop: Stop,
}

/// The key of an API that needs one. `${VAR}` unset is the empty string:
/// said when the pipeline is built, not by a 401 on the first request.
fn key<'a>(cfg: &'a ModelConfig, kind: &str, var: &str) -> Result<&'a str> {
    cfg.api_key
        .as_ref()
        .map(|k| k.expose_secret())
        .filter(|k| !k.trim().is_empty())
        .with_context(|| {
            format!("type {kind} needs `api_key`, e.g. \"${{{var}}}\" with that variable set")
        })
}

/// Model `model` where `cfg` points, behind rig's erased handle.
fn client(cfg: &ModelConfig, model: &str) -> Result<DynModel<Completion>> {
    Ok(match cfg.kind {
        ModelKind::Openai => {
            // Local servers accept any key, so none is "none". One that is
            // set and empty is "${OPENAI_API_KEY}" unset: said here, not by
            // a 401 on every record.
            let key = match cfg.api_key.as_ref().map(|k| k.expose_secret()) {
                None => "none",
                Some(k) if k.trim().is_empty() => bail!(
                    "`api_key` is empty: is the variable it names, e.g. \"${{OPENAI_API_KEY}}\", set? \
                     A server that takes no key needs no `api_key`"
                ),
                Some(k) => k,
            };
            OpenAIConfig::new(key)
                .with_base_url(
                    cfg.url
                        .as_deref()
                        .unwrap_or(DEFAULT_URL)
                        .trim_end_matches('/'),
                )
                .with_route(Route::Chat)
                .client()
                .chat(model)
                .erase()
        }
        ModelKind::Responses => {
            let mut provider = OpenAIConfig::new(key(cfg, "responses", "OPENAI_API_KEY")?);
            if let Some(url) = &cfg.url {
                provider = provider.with_base_url(url.trim_end_matches('/'));
            }
            provider.client().responses(model).erase()
        }
        ModelKind::Anthropic => {
            let mut provider = AnthropicConfig::new(key(cfg, "anthropic", "ANTHROPIC_API_KEY")?);
            if let Some(url) = &cfg.url {
                provider = provider.with_base_url(url);
            }
            provider.client().completion(model).erase()
        }
        ModelKind::Bedrock => {
            let mut runtime = rig_bedrock::client::BedrockRuntime::builder();
            if let Some(region) = &cfg.aws.region {
                runtime = runtime.region(region);
            }
            if let Some(profile) = &cfg.aws.profile {
                runtime = runtime.profile_name(profile);
            }
            runtime.build().completion(model).erase()
        }
    })
}

impl Model {
    pub fn new(name: &Arc<str>, cfg: ModelConfig, stop: Stop) -> Result<Self> {
        let client = client(&cfg, &cfg.model)?;
        let fallback = match cfg.fallback.as_deref().map(str::trim) {
            Some("") => {
                bail!("`fallback` is empty: it names the model asked what this one declines")
            }
            Some(id) => Some((Arc::from(id), self::client(&cfg, id)?)),
            None => None,
        };
        let sem = Semaphore::new(cfg.concurrency.max(1));
        tracing::info!(model = %name, kind = ?cfg.kind, id = %cfg.model, "model ready");
        Ok(Self {
            name: Arc::clone(name),
            cfg,
            client,
            fallback,
            sem,
            stop,
        })
    }

    pub fn stop(&self) -> &Stop {
        &self.stop
    }

    /// One of the model's `concurrency` places, held while a request is out.
    pub async fn permit(&self) -> SemaphorePermit<'_> {
        self.sem.acquire().await.expect("semaphore is never closed")
    }

    /// One request's reply: the model's, or its `fallback`'s to a request
    /// the model declined (the reply says it was refused or filtered). The
    /// fallback is asked once, the same request with the same tries, and
    /// what it replies is the reply, a decline of its own included. A run
    /// that is stopping asks no one else.
    pub async fn send(&self, node: &str, request: CompletionRequest) -> Result<CompletionResponse> {
        let reply = self.ask(&self.client, node, &request).await?;
        let declined = reply.finish_reason() == Some(FinishReason::ContentFilter);
        match &self.fallback {
            Some((id, second)) if declined && !self.stop.finishing() => {
                tracing::info!(
                    node, model = %self.name,
                    "{} declined the request, asking {id}", self.cfg.model
                );
                self.ask(second, node, &request).await
            }
            _ => Ok(reply),
        }
    }

    /// `request`'s reply from `client`. A request that got none (nothing
    /// within `timeout_ms`, a dropped connection, a 429, a 5xx) is sent
    /// again, `retries` times, a longer wait before each. One the provider
    /// would refuse the same way again (a key it rejects, a request it
    /// cannot read) is the error at once.
    async fn ask(
        &self,
        client: &DynModel<Completion>,
        node: &str,
        request: &CompletionRequest,
    ) -> Result<CompletionResponse> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let timeout = Duration::from_millis(self.cfg.timeout_ms);
            let (e, again) = match tokio::time::timeout(timeout, client.call(request.clone())).await
            {
                Ok(Ok(reply)) => return Ok(reply),
                Ok(Err(e)) => (anyhow!("{e}"), e.is_retryable()),
                Err(_) => (anyhow!("no reply within {} ms", self.cfg.timeout_ms), true),
            };
            // A run that is stopping waits for the requests it sent, and
            // sends none again.
            if !again || attempt > self.cfg.retries || self.stop.finishing() {
                return Err(e);
            }
            let wait = Duration::from_secs(1 << (attempt - 1).min(6));
            tracing::warn!(
                node, model = %self.name,
                attempt,
                "inference failed, retrying in {wait:?}: {e:#}"
            );
            tokio::time::sleep(wait).await;
        }
    }
}
