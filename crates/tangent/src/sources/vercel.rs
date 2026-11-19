//! A Vercel team's activity log, polled.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::Value;
use tangent_shared::sources::vercel::VercelConfig;
use tokio_util::sync::CancellationToken;

use crate::router::Router;
use crate::sources::poll::{idle, opt, parse_time, secret, Poller};
use crate::state::StateStore;

const SOURCE: &str = "vercel";
const LATE_MS: i64 = 5 * 60 * 1000;
/// Events asked for a page.
const PAGE: usize = 100;

pub async fn run_consumer(
    name: Arc<str>,
    cfg: VercelConfig,
    router: Arc<Router>,
    store: Arc<dyn StateStore>,
    shutdown: CancellationToken,
) -> Result<()> {
    let (Some(team), Some(token)) = (opt(&cfg.team_id), secret(&cfg.token)) else {
        idle(&name, "vercel team_id or token");
        shutdown.cancelled().await;
        return Ok(());
    };
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
    tracing::info!(source = %name, team, since = %cfg.since, "vercel source polling the activity log");

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            _ = ticker.tick() => match poll(&client, &cfg, team, token, &poller).await {
                Ok(n) => {
                    failing = false;
                    if n > 0 {
                        tracing::debug!(source = %name, events = n, "vercel poll");
                    }
                }
                Err(e) if !failing => {
                    failing = true;
                    tracing::warn!(source = %name, "vercel poll failed (retrying each interval): {e:#}");
                }
                Err(e) => tracing::debug!(source = %name, "vercel poll failed: {e:#}"),
            },
        }
    }
    Ok(())
}

/// From the cursor to now, an hour at a time: each hour's new events are
/// emitted oldest first, and the cursor moves after each, so a first start
/// a week back holds one hour's events at a time. The next hour starts
/// where this one ended, not at the saved cursor: a store that cannot save
/// it would have the poll read one hour forever.
async fn poll(
    client: &reqwest::Client,
    cfg: &VercelConfig,
    team: &str,
    token: &str,
    poller: &Poller,
) -> Result<usize> {
    let end = Utc::now();
    let mut n = 0;
    let mut start = poller.start(&cfg.since).await;
    loop {
        let to = end.min(start + Duration::hours(1));
        let out = walk(client, cfg, team, token, poller, start, to).await?;
        let newest = out.iter().map(|(t, _, _)| *t).max();
        n += poller.emit(SOURCE, out).await?;
        poller.finish(newest, Some(to)).await;
        if to >= end {
            return Ok(n);
        }
        start = to;
    }
}

/// The events of `[start, to]` not sent before. Vercel answers newest
/// first and has no page token, so each page asks for what is older than
/// the last page's oldest event, until a page brings nothing this walk has
/// not seen.
async fn walk(
    client: &reqwest::Client,
    cfg: &VercelConfig,
    team: &str,
    token: &str,
    poller: &Poller,
    start: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<(DateTime<Utc>, String, Value)>> {
    let url = format!("{}/v3/events", cfg.api.trim_end_matches('/'));
    let mut walked = HashSet::new();
    let mut out = Vec::new();
    let mut until = to;
    loop {
        let resp = client
            .get(&url)
            .bearer_auth(token)
            .query(&[
                ("teamId", team),
                ("since", &iso(start)),
                ("until", &iso(until)),
                ("limit", &PAGE.to_string()),
                ("withPayload", "true"),
            ])
            .send()
            .await
            .context("events request")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "events {status}: {}",
                body.chars().take(200).collect::<String>()
            );
        }
        let body: Value = resp.json().await.context("events body")?;
        let Some(page) = body["events"].as_array() else {
            bail!("events body has no `events`");
        };
        let mut fresh = false;
        let mut oldest = until;
        let mut prev: Option<DateTime<Utc>> = None;
        for v in page {
            let t = parse_time(&v["createdAt"]).unwrap_or(prev.unwrap_or(until));
            if prev.is_some_and(|p| t > p) {
                bail!("events came oldest first; this source pages newest first");
            }
            prev = Some(t);
            oldest = oldest.min(t);
            let id = match v["id"].as_str() {
                Some(id) if !id.is_empty() => id.to_string(),
                _ => format!(
                    "{}:{}",
                    t.timestamp_millis(),
                    v["type"].as_str().unwrap_or("")
                ),
            };
            if !walked.insert(id.clone()) {
                continue;
            }
            fresh = true;
            if poller.seen(&id).await {
                continue;
            }
            out.push((t, id, v.clone()));
        }
        if !fresh {
            return Ok(out);
        }
        // Whether `until` is inclusive or not, a millisecond past the
        // oldest event leaves none of its millisecond out; what repeats was
        // walked already.
        until = oldest + Duration::milliseconds(1);
    }
}

fn iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{extract::Query, http::StatusCode, response::IntoResponse, Json};
    use serde_json::json;

    use super::*;
    use crate::sources::poll::testing::{serve, Keeper};

    /// `/v3/events` over `events` (each at its time): those between
    /// `since` and `until`, both inclusive, newest first, at most `page` of
    /// them however many were asked for. With `throttle`, the second
    /// request answers 429.
    async fn api(events: Vec<(DateTime<Utc>, Value)>, page: usize, throttle: bool) -> String {
        let events = Arc::new(events);
        let calls = Arc::new(AtomicUsize::new(0));
        serve(|_| {
            axum::Router::new().fallback(move |Query(q): Query<HashMap<String, String>>| {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                let since: DateTime<Utc> = q["since"].parse().unwrap();
                let until: DateTime<Utc> = q["until"].parse().unwrap();
                let limit: usize = q["limit"].parse().unwrap();
                assert_eq!(q["teamId"], "team_acme");
                let mut hits: Vec<_> = events
                    .iter()
                    .filter(|(t, _)| *t >= since && *t <= until)
                    .collect();
                hits.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
                let hits: Vec<Value> = hits
                    .into_iter()
                    .take(limit.min(page))
                    .map(|(_, v)| v.clone())
                    .collect();
                let resp = if throttle && call == 1 {
                    StatusCode::TOO_MANY_REQUESTS.into_response()
                } else {
                    Json(json!({ "events": hits })).into_response()
                };
                async move { resp }
            })
        })
        .await
    }

    /// Now, to the millisecond, as Vercel's times are.
    fn now_ms() -> DateTime<Utc> {
        DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap()
    }

    fn event(i: usize, t: DateTime<Utc>) -> (DateTime<Utc>, Value) {
        let v = json!({
            "id": format!("uev_{i}"),
            "createdAt": t.timestamp_millis(),
            "type": "deployment",
            "principalId": "user_1",
        });
        (t, v)
    }

    fn config(base: &str, since: &str) -> VercelConfig {
        serde_json::from_value(json!({"api": base, "since": since})).unwrap()
    }

    #[tokio::test]
    async fn three_hours_back_comes_out_once_and_oldest_first() {
        // three hours of events, two to a millisecond, a minute apart;
        // Vercel pages 15 at a time, so pages break inside a millisecond
        let t0 = now_ms() - Duration::hours(3) + Duration::seconds(30);
        let mut events = Vec::new();
        for i in 0..170 {
            let t = t0 + Duration::minutes(i as i64);
            events.push(event(2 * i, t));
            events.push(event(2 * i + 1, t));
        }
        let base = api(events, 15, false).await;
        let cfg = config(&base, "3h");
        let client = reqwest::Client::new();
        let keeper = Keeper::new("vercel");
        let n = poll(&client, &cfg, "team_acme", "t", &keeper.poller)
            .await
            .unwrap();
        assert_eq!(n, 340);
        let n = poll(&client, &cfg, "team_acme", "t", &keeper.poller)
            .await
            .unwrap();
        assert_eq!(n, 0, "and only once");
        let want: Vec<String> = (0..340).map(|i| format!("uev_{i}")).collect();
        let mut sent = keeper.sent("/id").await;
        // each millisecond's pair may go out in either order
        for pair in sent.chunks_mut(2) {
            pair.sort();
        }
        assert_eq!(sent, want);
    }

    #[tokio::test]
    async fn a_429_on_page_two_leaves_page_one_to_the_next_poll() {
        let t0 = now_ms() - Duration::minutes(30);
        let events = (0..150)
            .map(|i| event(i, t0 + Duration::seconds(i as i64)))
            .collect();
        let base = api(events, 100, true).await;
        let cfg = config(&base, "1h");
        let client = reqwest::Client::new();
        let keeper = Keeper::new("vercel");
        let err = poll(&client, &cfg, "team_acme", "t", &keeper.poller)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("429"), "{err:#}");
        let n = poll(&client, &cfg, "team_acme", "t", &keeper.poller)
            .await
            .unwrap();
        assert_eq!(n, 150, "both pages, on the next poll");
        let n = poll(&client, &cfg, "team_acme", "t", &keeper.poller)
            .await
            .unwrap();
        assert_eq!(n, 0, "and only once");
        let all: Vec<String> = (0..150).map(|i| format!("uev_{i}")).collect();
        assert_eq!(keeper.sent("/id").await, all);
    }

    #[tokio::test]
    async fn a_store_that_refuses_the_cursor_does_not_hold_the_poll_on_one_hour() {
        let t0 = now_ms() - Duration::hours(3) + Duration::seconds(30);
        let events = (0..170)
            .map(|i| event(i, t0 + Duration::minutes(i as i64)))
            .collect();
        let base = api(events, 100, false).await;
        let cfg = config(&base, "3h");
        let client = reqwest::Client::new();
        let keeper = Keeper::refusing("vercel");
        let poll = poll(&client, &cfg, "team_acme", "t", &keeper.poller);
        let n = tokio::time::timeout(StdDuration::from_secs(20), poll)
            .await
            .expect("the poll ends")
            .unwrap();
        assert_eq!(n, 170);
        let all: Vec<String> = (0..170).map(|i| format!("uev_{i}")).collect();
        assert_eq!(keeper.sent("/id").await, all);
    }

    #[tokio::test]
    async fn events_oldest_first_are_an_error_not_a_gap() {
        let t0 = now_ms() - Duration::minutes(30);
        let page: Vec<Value> = (0..3)
            .map(|i| event(i, t0 + Duration::seconds(i as i64)).1)
            .collect();
        let base = serve(|_| {
            axum::Router::new().fallback(move || {
                let resp = Json(json!({ "events": page.clone() })).into_response();
                async move { resp }
            })
        })
        .await;
        let cfg = config(&base, "1h");
        let keeper = Keeper::new("vercel");
        let err = poll(
            &reqwest::Client::new(),
            &cfg,
            "team_acme",
            "t",
            &keeper.poller,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("oldest first"), "{err:#}");
        assert!(keeper.sent("/id").await.is_empty());
    }
}
