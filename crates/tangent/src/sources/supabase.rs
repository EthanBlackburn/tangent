//! A Supabase project's logs, queried from the Management API.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, DurationRound, NaiveDateTime, SecondsFormat, Utc};
use serde_json::Value;
use tangent_shared::sources::supabase::SupabaseConfig;
use tokio_util::sync::CancellationToken;

use crate::router::Router;
use crate::sources::poll::{idle, opt, parse_time, secret, Poller};
use crate::state::StateStore;

const SOURCE: &str = "supabase";
const LATE_MS: i64 = 5 * 60 * 1000;
/// Rows asked for a query.
const PAGE: usize = 1000;
/// New rows a poll holds; past them, the next poll goes on from the newest.
const CAP: usize = 10_000;

pub async fn run_consumer(
    name: Arc<str>,
    cfg: SupabaseConfig,
    router: Arc<Router>,
    store: Arc<dyn StateStore>,
    shutdown: CancellationToken,
) -> Result<()> {
    let (Some(project), Some(token)) = (opt(&cfg.project_ref), secret(&cfg.token)) else {
        idle(&name, "supabase project_ref or token");
        shutdown.cancelled().await;
        return Ok(());
    };
    // The log's name goes into the query.
    if cfg.log.is_empty()
        || !cfg
            .log
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        bail!(
            "supabase log {:?}: a log's name, such as auth_logs",
            cfg.log
        );
    }
    let poller = Poller::new(
        Arc::clone(&name),
        store,
        router,
        Duration::milliseconds(LATE_MS),
    );
    let client = reqwest::Client::builder()
        .user_agent("tangent")
        .timeout(StdDuration::from_secs(30))
        .build()?;
    let mut ticker = tokio::time::interval(StdDuration::from_secs(cfg.interval_secs.max(10)));
    let mut failing = false;
    tracing::info!(source = %name, project, log = %cfg.log, since = %cfg.since, "supabase source querying the project's logs");

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            _ = ticker.tick() => match poll(&client, &cfg, project, token, &poller).await {
                Ok(n) => {
                    failing = false;
                    if n > 0 {
                        tracing::debug!(source = %name, events = n, "supabase poll");
                    }
                }
                Err(e) if !failing => {
                    failing = true;
                    tracing::warn!(source = %name, "supabase poll failed (retrying each interval): {e:#}");
                }
                Err(e) => tracing::debug!(source = %name, "supabase poll failed: {e:#}"),
            },
        }
    }
    Ok(())
}

/// From the cursor to now, in the windows the API allows (a day at most,
/// rounded to the minute): each window's new rows are emitted oldest first,
/// and the cursor moves after each. A window that comes to `CAP` new rows
/// ends the poll there, and the next goes on from its newest row.
async fn poll(
    client: &reqwest::Client,
    cfg: &SupabaseConfig,
    project: &str,
    token: &str,
    poller: &Poller,
) -> Result<usize> {
    let end = Utc::now();
    let mut n = 0;
    loop {
        let start = poller.start(&cfg.since).await;
        // From the minute `start` is in, so the API's rounding cuts
        // nothing off; the query itself starts at `start`.
        let from = start.duration_trunc(Duration::minutes(1))?;
        let to = end.min(from + Duration::hours(23));
        let (out, capped) = window(client, cfg, project, token, poller, start, from, to).await?;
        let newest = out.iter().map(|(t, _, _)| *t).max();
        n += poller.emit(SOURCE, out).await?;
        if capped {
            poller.finish(newest, None).await;
            return Ok(n);
        }
        poller.finish(newest, Some(to)).await;
        if to >= end {
            return Ok(n);
        }
    }
}

/// The rows from `start` to `to` not sent before, oldest first, a query at
/// a time, each from the last one's newest row on, until a query brings
/// nothing this window has not seen (the API may return fewer rows than
/// asked), or `CAP` new rows are held: then true.
#[allow(clippy::too_many_arguments)]
async fn window(
    client: &reqwest::Client,
    cfg: &SupabaseConfig,
    project: &str,
    token: &str,
    poller: &Poller,
    start: DateTime<Utc>,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<(Vec<(DateTime<Utc>, String, Value)>, bool)> {
    let url = format!(
        "{}/v1/projects/{project}/analytics/endpoints/logs",
        cfg.api.trim_end_matches('/')
    );
    let mut walked = HashSet::new();
    let mut out = Vec::new();
    let mut after = start;
    loop {
        let sql = format!(
            "select id, timestamp, event_message, severity_text, log_attributes from logs \
             where source = '{}' and timestamp >= '{}' order by timestamp, id limit {PAGE}",
            cfg.log,
            after.format("%Y-%m-%d %H:%M:%S%.6f"),
        );
        let resp = client
            .get(&url)
            .bearer_auth(token)
            .query(&[
                ("sql", sql.as_str()),
                ("iso_timestamp_start", &iso(from)),
                ("iso_timestamp_end", &iso(to)),
            ])
            .send()
            .await
            .context("logs request")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "logs {status}: {}",
                body.chars().take(200).collect::<String>()
            );
        }
        let body: Value = resp.json().await.context("logs body")?;
        match &body["error"] {
            Value::Null => {}
            Value::String(s) if s.is_empty() => {}
            e => bail!(
                "logs query: {}",
                e.to_string().chars().take(200).collect::<String>()
            ),
        }
        let Some(rows) = body["result"].as_array() else {
            bail!("logs body has no `result`");
        };
        let mut fresh = false;
        for row in rows {
            let t = row_time(&row["timestamp"])
                .with_context(|| format!("a row's timestamp, {}", row["timestamp"]))?;
            after = after.max(t);
            let id = match row["id"].as_str() {
                Some(id) if !id.is_empty() => id.to_string(),
                _ => format!(
                    "{}:{}",
                    t.timestamp_micros(),
                    row["event_message"].as_str().unwrap_or("")
                ),
            };
            if !walked.insert(id.clone()) {
                continue;
            }
            fresh = true;
            if poller.seen(&id).await {
                continue;
            }
            let mut v = row.clone();
            if let Some(obj) = v.as_object_mut() {
                obj.insert("log".into(), Value::String(cfg.log.clone()));
            }
            out.push((t, id, v));
        }
        if !fresh {
            return Ok((out, false));
        }
        if out.len() >= CAP {
            return Ok((out, true));
        }
    }
}

/// A row's `timestamp`: RFC 3339, ClickHouse's `2026-11-09 12:00:00.123456`
/// (UTC), or epoch seconds, milliseconds or microseconds.
fn row_time(v: &Value) -> Option<DateTime<Utc>> {
    let n = match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    };
    if let Some(us) = n.filter(|n| n.abs() > 1e14) {
        return DateTime::from_timestamp_micros(us as i64);
    }
    parse_time(v).or_else(|| {
        let s = v.as_str()?.trim();
        ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"]
            .iter()
            .find_map(|f| NaiveDateTime::parse_from_str(s, f).ok())
            .map(|t| t.and_utc())
    })
}

fn iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::{extract::Query, http::StatusCode, response::IntoResponse, routing::get, Json};
    use serde_json::json;

    use super::*;
    use crate::sources::poll::testing::{serve, Keeper};

    const PATH: &str = "/v1/projects/abcdefghijklmnopqrst/analytics/endpoints/logs";

    /// The logs endpoint over `rows` (each at its time): those in the
    /// query's window, from the time its `timestamp >=` names, oldest
    /// first, at most `cap` of them however many were asked for. A window
    /// past a day, or not on the minute, is a 400, as the API's own
    /// validation would have it.
    async fn api(rows: Vec<(DateTime<Utc>, Value)>, cap: usize) -> String {
        let rows = Arc::new(rows);
        serve(|_| {
            axum::Router::new().route(
                PATH,
                get(move |Query(q): Query<HashMap<String, String>>| {
                    let from: DateTime<Utc> = q["iso_timestamp_start"].parse().unwrap();
                    let to: DateTime<Utc> = q["iso_timestamp_end"].parse().unwrap();
                    let sql = &q["sql"];
                    assert!(sql.contains("where source = 'auth_logs'"), "{sql}");
                    let after = sql.split("timestamp >= '").nth(1).unwrap();
                    let after = NaiveDateTime::parse_from_str(
                        &after[..after.find('\'').unwrap()],
                        "%Y-%m-%d %H:%M:%S%.f",
                    )
                    .unwrap()
                    .and_utc();
                    let resp = if to - from > Duration::hours(24) || from.timestamp() % 60 != 0 {
                        (StatusCode::BAD_REQUEST, "window").into_response()
                    } else {
                        let result: Vec<Value> = rows
                            .iter()
                            .filter(|(t, _)| *t >= from && *t <= to && *t >= after)
                            .take(cap)
                            .map(|(_, v)| v.clone())
                            .collect();
                        Json(json!({ "result": result, "error": null })).into_response()
                    };
                    async move { resp }
                }),
            )
        })
        .await
    }

    fn row(i: usize, t: DateTime<Utc>) -> (DateTime<Utc>, Value) {
        let v = json!({
            "id": format!("r{i}"),
            "timestamp": t.format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
            "event_message": "{\"msg\":\"Login\"}",
            "severity_text": "INFO",
            "log_attributes": {"auth_event.action": "login", "remote_addr": "203.0.113.9"},
        });
        (t, v)
    }

    fn config(base: &str, since: &str) -> SupabaseConfig {
        serde_json::from_value(json!({"api": base, "since": since})).unwrap()
    }

    /// Now, to the microsecond, as ClickHouse's times are.
    fn now_us() -> DateTime<Utc> {
        DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap()
    }

    #[tokio::test]
    async fn two_days_back_comes_out_once_and_oldest_first() {
        // two days of rows, twenty minutes apart, two to a microsecond;
        // the API returns 25 rows a query, so queries break inside one
        let t0 = now_us() - Duration::days(2) + Duration::minutes(1);
        let mut rows = Vec::new();
        for i in 0..143 {
            let t = t0 + Duration::minutes(20 * i as i64);
            rows.push(row(2 * i, t));
            rows.push(row(2 * i + 1, t));
        }
        let base = api(rows, 25).await;
        let cfg = config(&base, "2d");
        let client = reqwest::Client::new();
        let keeper = Keeper::new("supabase");
        let project = "abcdefghijklmnopqrst";
        let n = poll(&client, &cfg, project, "t", &keeper.poller)
            .await
            .unwrap();
        assert_eq!(n, 286);
        let n = poll(&client, &cfg, project, "t", &keeper.poller)
            .await
            .unwrap();
        assert_eq!(n, 0, "and only once");
        let want: Vec<String> = (0..286).map(|i| format!("r{i}")).collect();
        let mut sent = keeper.sent("/id").await;
        // each microsecond's pair may go out in either order
        for pair in sent.chunks_mut(2) {
            pair.sort_by_key(|id| id[1..].parse::<usize>().unwrap());
        }
        assert_eq!(sent, want);
    }

    #[tokio::test]
    async fn a_row_names_its_log_and_source() {
        let t = now_us() - Duration::minutes(10);
        let base = api(vec![row(0, t)], 25).await;
        let keeper = Keeper::new("supabase");
        let n = poll(
            &reqwest::Client::new(),
            &config(&base, "1h"),
            "abcdefghijklmnopqrst",
            "t",
            &keeper.poller,
        )
        .await
        .unwrap();
        assert_eq!(n, 1);
        assert_eq!(keeper.sent("/log").await, ["auth_logs"]);
    }

    #[tokio::test]
    async fn a_query_error_in_the_body_is_an_error() {
        let base = serve(|_| {
            axum::Router::new().route(
                PATH,
                get(|| async {
                    Json(json!({"result": [], "error": {"message": "unknown function"}}))
                }),
            )
        })
        .await;
        let keeper = Keeper::new("supabase");
        let err = poll(
            &reqwest::Client::new(),
            &config(&base, "1h"),
            "abcdefghijklmnopqrst",
            "t",
            &keeper.poller,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unknown function"), "{err:#}");
    }

    #[test]
    fn row_times_in_four_shapes() {
        let want: DateTime<Utc> = "2026-11-09T12:00:00.123456Z".parse().unwrap();
        for v in [
            json!("2026-11-09T12:00:00.123456Z"),
            json!("2026-11-09 12:00:00.123456"),
            json!(1_794_225_600_123_456i64),
            json!("1794225600123456"),
        ] {
            assert_eq!(row_time(&v), Some(want), "{v}");
        }
    }
}
