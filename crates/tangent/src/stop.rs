//! What a signal asks of the model calls.
//!
//! A run stops in two steps. At the first signal it is finishing: no request
//! is sent to a model from then on, and the ones already sent are waited
//! for. At the second the requests under way end too. A replay reads a past
//! it can read again, so its first signal is both.

use std::future::Future;

use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct Stop {
    finishing: CancellationToken,
    ending: CancellationToken,
}

impl Stop {
    /// No request is sent from here on; the ones sent finish.
    pub fn finish(&self) {
        self.finishing.cancel();
    }

    /// The requests under way end, and none is sent.
    pub fn end(&self) {
        self.finishing.cancel();
        self.ending.cancel();
    }

    /// Whether a request not yet sent is to stay unsent.
    pub fn finishing(&self) -> bool {
        self.finishing.is_cancelled()
    }

    /// Whether the requests under way were ended.
    pub fn ended(&self) -> bool {
        self.ending.is_cancelled()
    }

    pub async fn until_ended(&self) {
        self.ending.cancelled().await;
    }

    /// `call`'s result, or none if the requests were ended first.
    pub async fn unless_ended<F: Future>(&self, call: F) -> Option<F::Output> {
        self.ending.run_until_cancelled(call).await
    }
}
