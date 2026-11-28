//! A model, as an entry under `models` describes it: the client that reaches
//! it, and the limits every node that names it shares.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use parking_lot::Mutex;
use rig_core::completion::request::CompletionRequest;
use rig_core::completion::{CompletionResponse, FinishReason};
use rig_core::operation::Completion;
use rig_core::providers::anthropic::AnthropicConfig;
use rig_core::providers::openai::{OpenAIConfig, Route};
use rig_core::DynModel;
use secrecy::ExposeSecret;
use tangent_shared::models::{ModelConfig, ModelKind, DEFAULT_URL};
use tokio::sync::oneshot;

use crate::stop::Stop;

pub struct Model {
    pub name: Arc<str>,
    pub cfg: ModelConfig,
    client: DynModel<Completion>,
    /// `fallback`, reached as this model is: who is asked what it declines.
    fallback: Option<(Arc<str>, DynModel<Completion>)>,
    /// `concurrency` places: requests in flight to this model, from every
    /// node that names it.
    places: Arc<Mutex<Places>>,
    /// The run's stop: once it is finishing, a request sent is not sent
    /// again, and the nodes send no new one.
    stop: Stop,
    /// Whether its last request ended [`Unreached`]. What waits for it is
    /// then asked again one request at a time, not all at once.
    down: std::sync::atomic::AtomicBool,
    /// When it was last tried while down ([`Self::probe`]).
    probed: parking_lot::Mutex<Option<std::time::Instant>>,
}

/// A request that got no answer to read, for a reason another time may not
/// have: the model was not reached in any of its tries, or would not serve
/// the key it was asked with.
#[derive(Debug)]
pub struct Unreached(pub String);

impl std::fmt::Display for Unreached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unreached {}

/// Whether a provider's error is a refusal of the key or the account, and
/// not of the request: a 401 or a 403, a key it does not know, a sign-in
/// that has run out, an account with nothing to pay with. The same request
/// is served once that is mended.
pub fn refuses_the_key(error: &str) -> bool {
    let e = error.to_ascii_lowercase();
    [
        "401",
        "403",
        "unauthorized",
        "forbidden",
        "authentication",
        "invalid x-api-key",
        "invalid_api_key",
        "incorrect api key",
        "api key not valid",
        "expiredtoken",
        "token has expired",
        "no credentials",
        "unrecognizedclient",
        "invalidclienttokenid",
        "accessdenied",
        "credit balance is too low",
        "insufficient_quota",
        "payment_instrument",
        // Bedrock's client, of credentials it could not load
        "verify internet connection or aws keys",
    ]
    .iter()
    .any(|needle| e.contains(needle))
}

/// A model's places, and who waits for one. A place that comes free goes to
/// a conversation's turn before the request of a node's records, and within
/// each to whoever has waited longest: the records still to be read do not
/// keep waiting an alert that is being settled, and the conversations end
/// when no record is read, since it is the records that begin them.
struct Places {
    free: usize,
    turns: VecDeque<oneshot::Sender<Place>>,
    requests: VecDeque<oneshot::Sender<Place>>,
}

/// One of a model's places, held while a request is out and given on when
/// dropped.
pub struct Place(Option<Arc<Mutex<Places>>>);

impl Drop for Place {
    fn drop(&mut self) {
        let Some(places) = self.0.take() else { return };
        loop {
            let next = {
                let mut places = places.lock();
                match places
                    .turns
                    .pop_front()
                    .or_else(|| places.requests.pop_front())
                {
                    Some(next) => next,
                    None => {
                        places.free += 1;
                        return;
                    }
                }
            };
            // Given whole, so one whose waiting ended after this gives it
            // on in its turn. One that ended before is not there to take
            // it: the place is still this one's to give.
            match next.send(Place(Some(Arc::clone(&places)))) {
                Ok(()) => return,
                Err(mut unheld) => unheld.0 = None,
            }
        }
    }
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
        let places = Arc::new(Mutex::new(Places {
            free: cfg.concurrency.max(1),
            turns: VecDeque::new(),
            requests: VecDeque::new(),
        }));
        tracing::info!(model = %name, kind = ?cfg.kind, id = %cfg.model, "model ready");
        Ok(Self {
            name: Arc::clone(name),
            cfg,
            client,
            fallback,
            places,
            stop,
            down: std::sync::atomic::AtomicBool::new(false),
            probed: parking_lot::Mutex::new(None),
        })
    }

    /// Whether the last request to it ended [`Unreached`].
    pub fn down(&self) -> bool {
        self.down.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the caller is the one to try a model that is down: true once
    /// in `every`, so an outage of hours is a request each `every` and not
    /// one for each record that waits.
    pub fn probe(&self, every: Duration) -> bool {
        let mut probed = self.probed.lock();
        if probed.is_some_and(|at| at.elapsed() < every) {
            return false;
        }
        *probed = Some(std::time::Instant::now());
        true
    }

    pub fn stop(&self) -> &Stop {
        &self.stop
    }

    /// One of the model's `concurrency` places for the request of a node's
    /// records, held while it is out.
    pub async fn place(&self) -> Place {
        self.wait(|places| &mut places.requests).await
    }

    /// One for a turn of a conversation, which takes the next that comes
    /// free ahead of the records' requests.
    pub async fn turn(&self) -> Place {
        self.wait(|places| &mut places.turns).await
    }

    async fn wait(
        &self,
        line: impl FnOnce(&mut Places) -> &mut VecDeque<oneshot::Sender<Place>>,
    ) -> Place {
        let given = {
            let mut places = self.places.lock();
            if places.free > 0 {
                places.free -= 1;
                return Place(Some(Arc::clone(&self.places)));
            }
            let (give, given) = oneshot::channel();
            line(&mut places).push_back(give);
            given
        };
        given
            .await
            .expect("whoever waits is given a place or is still in line")
    }

    /// One request's reply: the model's, or its `fallback`'s to a request
    /// the model declined (the reply says it was refused or filtered). The
    /// fallback is asked once, the same request with the same tries, and
    /// what it replies is the reply, a decline of its own included. A run
    /// that is stopping asks no one else.
    pub async fn send(&self, node: &str, request: CompletionRequest) -> Result<CompletionResponse> {
        let began = std::time::Instant::now();
        let reply = self.answer(node, request).await;
        if reply.is_ok() {
            crate::INFERENCE_SECONDS
                .with_label_values(&[node])
                .observe(began.elapsed().as_secs_f64());
        }
        reply
    }

    async fn answer(&self, node: &str, request: CompletionRequest) -> Result<CompletionResponse> {
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
                Ok(Ok(reply)) => {
                    self.down.store(false, std::sync::atomic::Ordering::Relaxed);
                    return Ok(reply);
                }
                Ok(Err(e)) => (anyhow!("{e}"), e.is_retryable()),
                Err(_) => (anyhow!("no reply within {} ms", self.cfg.timeout_ms), true),
            };
            // A run that is stopping waits for the requests it sent, and
            // sends none again.
            if !again || attempt > self.cfg.retries || self.stop.finishing() {
                // One that would be answered another time is told apart
                // from one the provider refuses for what it says.
                let said = format!("{e:#}");
                if again || refuses_the_key(&said) {
                    self.down.store(true, std::sync::atomic::Ordering::Relaxed);
                    return Err(anyhow::Error::new(Unreached(said)));
                }
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
