//! What a model's tokens cost, as its provider lists them, in USD a million
//! tokens. Read on 2026-11-28 from Anthropic's pricing page, AWS's price list
//! for Bedrock (us-west-2), OpenAI's pricing page and OpenRouter's model
//! list. A model that is not here has no price, and its cost is not counted:
//! a wrong one would be worse than none.

use tangent_shared::models::{ModelConfig, ModelKind};

/// A million tokens of each kind, in USD.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rates {
    pub input: f64,
    pub cache_read: f64,
    pub cache_write: f64,
    pub output: f64,
}

/// A model's rates, and those of a request whose prompt is over `long`
/// tokens where its provider charges such a request more.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Price {
    rates: Rates,
    long: Option<(u64, Rates)>,
}

/// The tokens of one request: `input` is the part of the prompt neither read
/// from a cache nor written to one.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Tokens {
    pub input: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub output: u64,
}

impl Tokens {
    pub fn all(&self) -> u64 {
        self.input + self.cache_read + self.cache_write + self.output
    }
}

const fn rates(input: f64, cache_read: f64, cache_write: f64, output: f64) -> Rates {
    Rates {
        input,
        cache_read,
        cache_write,
        output,
    }
}

/// Anthropic's own prices. A cache is written for five minutes (1.25x).
const CLAUDE: &[(&str, Rates, Option<(u64, Rates)>)] = &[
    (
        "claude-haiku-5-5",
        rates(0.10, 0.01, 0.125, 0.50),
        Some((100_000, rates(0.50, 0.05, 0.625, 2.50))),
    ),
    // before `claude-sonnet-5`, which its name begins with
    ("claude-sonnet-5-5", rates(2.0, 0.10, 2.5, 10.0), None),
    ("claude-sonnet-5", rates(2.0, 0.20, 2.5, 10.0), None),
    ("claude-opus-5-5", rates(4.0, 0.20, 5.0, 20.0), None),
    ("claude-haiku-4-5", rates(1.0, 0.10, 1.25, 5.0), None),
];

/// OpenAI's standard prices: it charges nothing more to write a cache.
const OPENAI: &[(&str, Rates, Option<(u64, Rates)>)] = &[
    (
        "gpt-6-luna",
        rates(0.10, 0.01, 0.10, 0.50),
        Some((272_000, rates(0.20, 0.02, 0.20, 0.75))),
    ),
    (
        "gpt-6.1-terra",
        rates(1.0, 0.05, 1.0, 5.0),
        Some((272_000, rates(2.0, 0.10, 2.0, 7.5))),
    ),
];

/// OpenRouter's, for the model `--provider openrouter` asks.
const OPENROUTER: &[(&str, Rates, Option<(u64, Rates)>)] = &[(
    "deepseek/deepseek-v4-flash-0731",
    rates(0.0456, 0.035, 0.0456, 0.27),
    None,
)];

fn scaled(r: Rates, by: f64) -> Rates {
    rates(r.input * by, r.cache_read * by, r.cache_write * by, r.output * by)
}

fn listed(table: &[(&str, Rates, Option<(u64, Rates)>)], model: &str, by: f64) -> Option<Price> {
    table
        .iter()
        .find(|(name, ..)| model.starts_with(name))
        .map(|(_, r, long)| Price {
            rates: scaled(*r, by),
            long: long.map(|(over, r)| (over, scaled(r, by))),
        })
}

impl Price {
    /// What `cfg`'s model costs, or None when it is not known. A server on
    /// this machine costs nothing.
    pub fn of(cfg: &ModelConfig) -> Option<Self> {
        let model = cfg.model.as_str();
        let host = cfg.url.as_deref().unwrap_or("");
        match cfg.kind {
            ModelKind::Anthropic => listed(CLAUDE, model, 1.0),
            // Bedrock charges Anthropic's prices through a `global.`
            // profile and a tenth more in a region or through a geography's
            // profile (`us.`, `eu.`)
            ModelKind::Bedrock => {
                let (place, name) = model.split_once("anthropic.")?;
                listed(CLAUDE, name, if place == "global." { 1.0 } else { 1.1 })
            }
            ModelKind::Responses => listed(OPENAI, model, 1.0),
            ModelKind::Openai if host.contains("://localhost") || host.contains("://127.0.0.1") => {
                Some(Price {
                    rates: rates(0.0, 0.0, 0.0, 0.0),
                    long: None,
                })
            }
            ModelKind::Openai if host.contains("openrouter.ai") => listed(OPENROUTER, model, 1.0),
            ModelKind::Openai if host.contains("api.openai.com") => listed(OPENAI, model, 1.0),
            ModelKind::Openai => None,
        }
    }

    /// What one request's tokens cost, in USD: at the long prompt's rates
    /// when the whole prompt is over the provider's line.
    pub fn cost(&self, t: &Tokens) -> f64 {
        let prompt = t.input + t.cache_read + t.cache_write;
        let r = match self.long {
            Some((over, long)) if prompt > over => long,
            _ => self.rates,
        };
        (t.input as f64 * r.input
            + t.cache_read as f64 * r.cache_read
            + t.cache_write as f64 * r.cache_write
            + t.output as f64 * r.output)
            / 1e6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(yaml: &str) -> ModelConfig {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn a_model_costs_what_its_provider_lists() {
        let t = Tokens {
            input: 1_000_000,
            cache_read: 1_000_000,
            cache_write: 1_000_000,
            output: 1_000_000,
        };
        // Sonnet 5.5 is not Sonnet 5: its cache reads are half the price
        let direct = Price::of(&cfg("{ type: anthropic, model: claude-sonnet-5-5 }")).unwrap();
        assert!((direct.cost(&t) - 14.60).abs() < 1e-9);
        let five = Price::of(&cfg("{ type: anthropic, model: claude-sonnet-5 }")).unwrap();
        assert!((five.cost(&t) - 14.70).abs() < 1e-9);
        // Bedrock: a geography's profile is a tenth more, the global one is not
        let us = Price::of(&cfg("{ type: bedrock, model: us.anthropic.claude-sonnet-5 }")).unwrap();
        assert!((us.cost(&t) - 14.70 * 1.1).abs() < 1e-9);
        let global =
            Price::of(&cfg("{ type: bedrock, model: global.anthropic.claude-sonnet-5 }")).unwrap();
        assert!((global.cost(&t) - 14.70).abs() < 1e-9);
    }

    #[test]
    fn a_long_prompt_is_charged_as_one() {
        let haiku = Price::of(&cfg("{ type: anthropic, model: claude-haiku-5-5 }")).unwrap();
        let short = Tokens {
            input: 100_000,
            output: 1000,
            ..Tokens::default()
        };
        assert!((haiku.cost(&short) - (0.010 + 0.0005)).abs() < 1e-9);
        // a cache read counts toward the prompt's length
        let long = Tokens {
            input: 1,
            cache_read: 100_000,
            output: 1000,
            ..Tokens::default()
        };
        assert!((haiku.cost(&long) - (0.0000005 + 0.005 + 0.0025)).abs() < 1e-9);
    }

    #[test]
    fn a_model_that_is_not_listed_has_no_price_and_a_local_one_is_free() {
        assert!(Price::of(&cfg("{ type: anthropic, model: claude-next }")).is_none());
        assert!(Price::of(&cfg(
            "{ type: openai, url: 'https://example.com/v1', model: gpt-6-luna }"
        ))
        .is_none());
        let local = Price::of(&cfg(
            "{ type: openai, url: 'http://localhost:8080/v1', model: glm-4.7-flash }",
        ))
        .unwrap();
        assert_eq!(local.cost(&Tokens { input: 9, output: 9, ..Tokens::default() }), 0.0);
        let terra = Price::of(&cfg("{ type: responses, model: gpt-6.1-terra }")).unwrap();
        assert!((terra.cost(&Tokens { output: 1_000_000, ..Tokens::default() }) - 5.0).abs() < 1e-9);
    }
}
