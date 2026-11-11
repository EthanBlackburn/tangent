//! `macos_verdicts`: the judge's running account of a session, kept for the
//! session's next record, and its flags told once. A session reaches the
//! judge a piece at a time (an agent's turn a few minutes at a time), and a
//! piece alone says little: the read that makes an upload a theft was a
//! piece back. With each verdict the judge writes `so_far`, its summary of
//! the session up to and including that piece; this plugin sits after the
//! judge and keeps it in state, and `macos_sessions` puts it on the
//! session's next summary.
//!
//! It passes on only the verdicts a person has not been told of: a flag, the
//! first in its turn or one more suspicious than the turn's last. The judge
//! is not shown what it flagged before (shown that, it took its own flag for
//! evidence and flagged again), so the same thing in the next piece is
//! flagged again, and here is where the repeat stops. Every verdict is still
//! in the judge's own output.

wit_bindgen::generate!({
    path: ".tangent/wit",
    world: "processor",
    generate_all,
});

use exports::tangent::logs::mapper::{Guest, Meta, Pred, Selector};
use serde_json::{json, Value};
use tangent::logs::log::{Logview, Scalar};
use tangent::logs::state;

struct Component;

export!(Component);

/// For this long after the last verdict: `macos_sessions` keeps a session's
/// prompts as long.
const TTL_MS: u64 = 7_200_000;

/// The state key `macos_sessions` reads: the session's id and entry point,
/// as its summary names them.
pub fn key(rec: &Value) -> String {
    let at = |p: &str| rec.pointer(p).and_then(Value::as_str).unwrap_or("?");
    format!("story:{}:{}", at("/session/id"), at("/session/entry"))
}

/// The session's story with this verdict taken in, and whether a person is
/// to be told of it: the judge's newest summary (the last one stands when a
/// verdict has none), and the turn and suspicion of the last flag told. None
/// when the record holds no verdict.
fn told(story: Value, rec: &Value) -> Option<(Value, bool)> {
    let j = rec.get("judge")?;
    j.get("assessment")?.as_str()?;
    let so_far = j
        .get("so_far")
        .and_then(Value::as_str)
        .filter(|t| !t.trim().is_empty())
        .map(|t| json!(t))
        .unwrap_or_else(|| story["so_far"].clone());
    let mut alerted = story["alerted"].clone();
    let mut tell = false;
    if j.get("flag").and_then(Value::as_bool) == Some(true) {
        // a session with no turns is one long one
        let turn = rec.pointer("/session/turn").cloned().unwrap_or(json!(""));
        let suspicion = j.get("suspicion").and_then(Value::as_i64).unwrap_or(0);
        let repeat = alerted["turn"] == turn
            && alerted["suspicion"]
                .as_i64()
                .is_some_and(|s| suspicion <= s);
        if !repeat {
            tell = true;
            alerted = json!({"turn": turn, "suspicion": suspicion});
        }
    }
    Some((json!({"so_far": so_far, "alerted": alerted}), tell))
}

impl Guest for Component {
    fn metadata() -> Meta {
        Meta {
            name: "macos_verdicts".to_string(),
            version: "0.1.0".to_string(),
        }
    }

    fn probe() -> Vec<Selector> {
        vec![Selector {
            any: Vec::new(),
            all: vec![
                Pred::Eq((
                    "source".to_string(),
                    Scalar::Str("macos_session".to_string()),
                )),
                Pred::Has("judge.assessment".to_string()),
            ],
            none: Vec::new(),
        }]
    }

    fn process_logs(input: Vec<Logview>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for lv in input {
            let line = lv.log();
            if let Ok(rec) = serde_json::from_str::<Value>(&line) {
                let k = key(&rec);
                let story = match state::get(&k) {
                    Ok(Some(Scalar::Str(v))) => serde_json::from_str(&v).unwrap_or(Value::Null),
                    _ => Value::Null,
                };
                if let Some((next, tell)) = told(story, &rec) {
                    if let Ok(v) = serde_json::to_string(&next) {
                        let _ = state::set(&k, &Scalar::Str(v), Some(TTL_MS));
                    }
                    if tell {
                        out.extend(line.into_bytes());
                        out.push(b'\n');
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(judge: Value) -> Value {
        json!({"source": "macos_session",
               "session": {"id": "200", "entry": "/bin/zsh", "from": "t1", "to": "t2"},
               "judge": judge})
    }

    #[test]
    fn the_newest_summary_stands_and_a_flag_is_told_once_a_turn() {
        let piece = |turn: &str, suspicion: i64, flag: bool, so_far: Option<&str>| {
            let mut r = rec(json!({"assessment": "a", "suspicion": suspicion, "flag": flag}));
            r["session"]["turn"] = json!(turn);
            if let Some(t) = so_far {
                r["judge"]["so_far"] = json!(t);
            }
            r
        };
        let first = piece(
            "t1",
            1,
            false,
            Some("The agent scaled a service down, as asked."),
        );
        assert_eq!(key(&first), "story:200:/bin/zsh");
        let (story, tell) = told(Value::Null, &first).unwrap();
        assert!(!tell);
        assert_eq!(
            story["so_far"],
            "The agent scaled a service down, as asked."
        );

        // the turn's first flag is told; the same again is not; a worse one is
        let (story, tell) =
            told(story, &piece("t1", 3, true, Some("Then read the SSH key."))).unwrap();
        assert!(tell);
        assert_eq!(story["so_far"], "Then read the SSH key.");
        let (story, tell) = told(story, &piece("t1", 3, true, None)).unwrap();
        assert!(!tell);
        assert_eq!(
            story["so_far"], "Then read the SSH key.",
            "no summary: the last stands"
        );
        let (story, tell) = told(story, &piece("t1", 6, true, None)).unwrap();
        assert!(tell);
        // the next turn's first flag is told, however mild
        let (story, tell) = told(story, &piece("t2", 3, true, None)).unwrap();
        assert!(tell);
        // a record the judge could not answer says nothing
        assert!(told(story, &rec(json!({"error": "timeout"}))).is_none());
    }
}
