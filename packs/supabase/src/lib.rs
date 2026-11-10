//! A Supabase project's logs, as the `supabase` source reads them: each row
//! into `_norm`, trimmed to what a verdict turns on, its address described
//! from the runtime's tables, and what the company profile says about it in
//! `_facts`. The Auth server's logs are the ones it knows by name; any other
//! log's rows pass with their attributes kept.

wit_bindgen::generate!({
    path: ".tangent/wit",
    world: "processor",
    generate_all,
});

mod trim;

use exports::tangent::logs::mapper::{Guest, Meta, Pred, Selector};
use normkit::{Norm, Stamp};
use serde_json::{Map, Value};
use tangent::logs::enrichment::lookup;
use tangent::logs::log::{Logview, Scalar};

struct Component;

export!(Component);

/// The first of `keys` the row's `log_attributes` holds a value for. The
/// keys are whole, dots and all (`auth_event.action`), and every value is
/// text, as Supabase stores them.
fn attr(m: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    let attrs = normkit::obj(m.get("log_attributes"))?;
    keys.iter().find_map(|k| match attrs.get(*k)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn norm(m: &Map<String, Value>) -> Norm {
    Norm {
        // Who signed in, or was signed up, recovered, changed: the Auth
        // server's own audit event names them. A request it refused names
        // nobody.
        actor: attr(
            m,
            &[
                "auth_event.actor_username",
                "auth_audit_event.actor_username",
                "auth_event.traits.user_email",
            ],
        ),
        // The audit event's action, or for a bare request the path it asked.
        kind: attr(m, &["auth_event.action", "auth_audit_event.action", "path"]),
        ip: attr(m, &["remote_addr"]),
        // The actor is one of your product's users, not one of your people:
        // the profile's members, and where they work from, say nothing of
        // them.
        principal: Some("user"),
        ..Norm::default()
    }
}

impl Guest for Component {
    fn metadata() -> Meta {
        Meta {
            name: "supabase".to_string(),
            version: "0.1.0".to_string(),
        }
    }

    fn probe() -> Vec<Selector> {
        vec![Selector {
            any: Vec::new(),
            all: vec![Pred::In((
                "source".to_string(),
                vec![Scalar::Str("supabase".to_string())],
            ))],
            none: Vec::new(),
        }]
    }

    fn process_logs(input: Vec<Logview>) -> Result<Vec<u8>, String> {
        let kit = factskit::kit(lookup);
        let mut out = Vec::new();
        for lv in input {
            let read = normkit::record(&lv.log())?;
            let n = norm(&read);
            kit.write(&mut out, Stamp::of(&read), trim::supabase(&read), n)?;
        }
        Ok(out)
    }
}
