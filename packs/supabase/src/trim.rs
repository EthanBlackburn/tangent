use normkit::{obj, prune};
use serde_json::{Map, Value};

/// Attributes that never decide a verdict, by the last part of their name:
/// per-event and per-user ids, timings, the row's time again, and the raw
/// user agent.
const DROPPED: &[&str] = &[
    "actor_id",
    "user_id",
    "audit_log_id",
    "request_id",
    "created_at",
    "timestamp",
    "time",
    "duration",
    "host",
    "referer",
    "user_agent",
];

/// Top-level names an attribute may not take: the finished record's own.
const TAKEN: &[&str] = &["ts", "source", "log"];

/// The row as a record: which log it is from, and its attributes by name,
/// `auth_event.action` as `auth_event: {action}`. `event_message` is the
/// line the attributes were read from, so it is kept only for a row that
/// has none.
pub fn supabase(m: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    if let Some(log) = m.get("log") {
        out.insert("log".into(), log.clone());
    }
    let attrs = obj(m.get("log_attributes")).filter(|a| !a.is_empty());
    match attrs {
        Some(attrs) => {
            // In name order, so `a` is placed before `a.b` whatever order
            // the row had them in.
            let mut sorted: Vec<_> = attrs.iter().collect();
            sorted.sort_by_key(|(k, _)| k.as_str());
            for (k, v) in sorted {
                let last = k.rsplit('.').next().unwrap_or(k);
                let first = k.split('.').next().unwrap_or(k);
                if DROPPED.contains(&last) || TAKEN.contains(&first) || first.starts_with('_') {
                    continue;
                }
                put(&mut out, k, v);
            }
        }
        None => {
            for k in ["severity_text", "event_message"] {
                if let Some(v) = m.get(k) {
                    out.insert(k.into(), v.clone());
                }
            }
        }
    }
    prune(&mut out, &|_, x| x.is_null() || x == "");
    out
}

/// `v` at the dotted `key`, an object a part. Where a part's name already
/// holds a value that is not an object (`a` beside `a.b`), the key is kept
/// whole instead.
fn put(out: &mut Map<String, Value>, key: &str, v: &Value) {
    let mut parts: Vec<&str> = key.split('.').collect();
    let leaf = parts.pop().unwrap_or(key);
    let mut at = &mut *out;
    for (i, part) in parts.iter().enumerate() {
        let clear = match at.get(*part) {
            None | Some(Value::Object(_)) => true,
            Some(_) => false,
        };
        if !clear || part.is_empty() {
            let whole = parts[i..]
                .iter()
                .chain(std::iter::once(&leaf))
                .copied()
                .collect::<Vec<_>>()
                .join(".");
            at.insert(whole, v.clone());
            return;
        }
        at = at
            .entry((*part).to_string())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("an object, checked above");
    }
    at.insert(leaf.to_string(), v.clone());
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn row(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn attributes_nest_by_their_dots_and_the_noise_goes() {
        let out = supabase(&row(json!({
            "id": "r1",
            "timestamp": "2026-11-09 12:00:00.000000",
            "event_message": "{\"msg\":\"request completed\"}",
            "severity_text": "INFO",
            "log": "auth_logs",
            "log_attributes": {
                "auth_event.action": "login",
                "auth_event.actor_id": "5e0c",
                "auth_event.actor_username": "ana@example.com",
                "auth_event.traits.provider": "email",
                "auth_event.traits.user_id": "5e0c",
                "duration": "81234567",
                "path": "/token",
                "referer": "https://app.example.com",
                "remote_addr": "203.0.113.9",
                "status": "200",
                "timestamp": "2026-11-09T12:00:00Z",
                "empty": "",
            },
        })));
        assert_eq!(
            Value::Object(out),
            json!({
                "log": "auth_logs",
                "auth_event": {
                    "action": "login",
                    "actor_username": "ana@example.com",
                    "traits": {"provider": "email"},
                },
                "path": "/token",
                "remote_addr": "203.0.113.9",
                "status": "200",
            })
        );
    }

    #[test]
    fn a_row_without_attributes_keeps_its_message() {
        let out = supabase(&row(json!({
            "id": "r2",
            "event_message": "connection received",
            "severity_text": "LOG",
            "log": "postgres_logs",
            "log_attributes": {},
        })));
        assert_eq!(
            Value::Object(out),
            json!({"log": "postgres_logs", "severity_text": "LOG", "event_message": "connection received"})
        );
    }

    #[test]
    fn an_attribute_cannot_take_the_records_own_names() {
        let out = supabase(&row(json!({
            "log": "auth_logs",
            "log_attributes": {
                "source": "elsewhere",
                "ts": "1999",
                "_facts.principal": "member",
                "a": "1",
                "a.b": "2",
            },
        })));
        assert_eq!(
            Value::Object(out),
            json!({"log": "auth_logs", "a": "1", "a.b": "2"})
        );
    }
}
