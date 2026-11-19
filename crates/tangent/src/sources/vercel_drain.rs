//! A Vercel log drain, received. Vercel POSTs batches of log objects; each
//! delivery is checked against its signature, split into records, stamped
//! and forwarded before it is answered, so a delivery answered 200 is one
//! the pipeline has.

use std::{io::Read, sync::Arc};

use anyhow::{anyhow, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header::CONTENT_ENCODING, Request, StatusCode},
    routing::post,
    serve, Router as AxumRouter,
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;
use tangent_shared::dag::NodeRef;
use tangent_shared::sources::vercel_drain::VercelDrainConfig;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use super::poll::{frame, idle, parse_time, secret, stamp};
use crate::router::Router;

/// What every record is stamped with.
const SOURCE: &str = "vercel_drain";
/// The largest delivery taken, as sent and as unpacked. Vercel's batches
/// are up to 1 MB.
const MAX_BODY: usize = 16 * 1024 * 1024;

struct Drain {
    secret: String,
    from: NodeRef,
    router: Arc<Router>,
}

/// Why a delivery was refused, and the status it is answered with.
struct Refused(StatusCode, String);

pub async fn run_consumer(
    name: Arc<str>,
    cfg: VercelDrainConfig,
    router: Arc<Router>,
    shutdown: CancellationToken,
) -> Result<()> {
    let Some(secret) = secret(&cfg.secret) else {
        idle(&name, "vercel_drain secret");
        shutdown.cancelled().await;
        return Ok(());
    };
    let drain = Arc::new(Drain {
        secret: secret.to_string(),
        from: NodeRef::Source { name: name.clone() },
        router,
    });
    let listener = TcpListener::bind(cfg.bind_address).await.with_context(|| {
        format!(
            "failed to bind vercel drain listener on {}",
            cfg.bind_address
        )
    })?;
    let app = AxumRouter::new()
        .route(cfg.path.as_str(), post(deliver))
        .with_state(drain);
    tracing::info!(source = %name, address = %cfg.bind_address, path = %cfg.path, "vercel drain source listening");
    serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .map_err(|e| anyhow!("vercel drain server error: {e}"))
}

async fn deliver(
    State(drain): State<Arc<Drain>>,
    req: Request<Body>,
) -> (StatusCode, &'static str) {
    match take(&drain, req).await {
        Ok(n) => {
            tracing::debug!(records = n, "vercel drain delivery");
            (StatusCode::OK, "ok")
        }
        // A delivery that fails is refused and the source keeps listening:
        // anyone who can reach the port can send one.
        Err(Refused(status, why)) => {
            tracing::warn!("vercel drain delivery refused: {why}");
            (status, "refused")
        }
    }
}

/// One delivery: how many records it held.
async fn take(drain: &Drain, req: Request<Body>) -> Result<usize, Refused> {
    let (parts, body) = req.into_parts();
    let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
    let body = to_bytes(body, MAX_BODY).await.map_err(|e| {
        Refused(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("reading the body: {e}"),
        )
    })?;
    // The signature is of the bytes as sent, so it is checked before
    // anything is unpacked or parsed.
    let signature = header("x-vercel-signature")
        .ok_or_else(|| Refused(StatusCode::FORBIDDEN, "no x-vercel-signature".into()))?;
    if !signed(&drain.secret, &body, signature) {
        return Err(Refused(
            StatusCode::FORBIDDEN,
            "x-vercel-signature is not the body's".into(),
        ));
    }
    let bad = |e: String| Refused(StatusCode::BAD_REQUEST, e);
    let text = match header(CONTENT_ENCODING.as_str()) {
        Some(enc) if enc.eq_ignore_ascii_case("gzip") => gunzip(&body).map_err(bad)?,
        Some(enc) if !enc.eq_ignore_ascii_case("identity") => {
            return Err(Refused(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("content-encoding {enc}"),
            ))
        }
        _ => body.to_vec(),
    };
    let mut frames = Vec::new();
    for mut v in records(&text).map_err(bad)? {
        finish(&mut v);
        frames.push(frame(&v).map_err(|e| bad(e.to_string()))?);
    }
    let n = frames.len();
    if n > 0 {
        drain
            .router
            .forward(&drain.from, frames, Vec::new())
            .await
            .map_err(|e| {
                Refused(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("forwarding: {e:#}"),
                )
            })?;
    }
    Ok(n)
}

/// Whether `signature` is the hex HMAC-SHA1 of `body` under `secret`.
fn signed(secret: &str, body: &[u8], signature: &str) -> bool {
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes());
    constant_time_eq::constant_time_eq(
        expected.as_bytes(),
        signature.trim().to_ascii_lowercase().as_bytes(),
    )
}

fn gunzip(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(body)
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("gzip: {e}"))?;
    if out.len() > MAX_BODY {
        return Err(format!("unpacks to more than {MAX_BODY} bytes"));
    }
    Ok(out)
}

/// The log objects of a delivery, which is a JSON array or NDJSON. Vercel
/// says which a drain sends when the drain is made, not in the delivery, so
/// the body is read for it. What is not an object is left out.
fn records(body: &[u8]) -> Result<Vec<Value>, String> {
    let text = std::str::from_utf8(body).map_err(|e| format!("not UTF-8: {e}"))?;
    let all: Vec<Value> = if text.trim_start().starts_with('[') {
        serde_json::from_str(text).map_err(|e| format!("not a JSON array: {e}"))?
    } else {
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).map_err(|e| format!("not NDJSON: {e}")))
            .collect::<Result<_, _>>()?
    };
    Ok(all.into_iter().filter(Value::is_object).collect())
}

/// Vercel's `source` (which of its logs the record is from) becomes `log`,
/// and the record gets the pipeline's `source` and `ts`, the latter from
/// `timestamp`, or now when there is none.
fn finish(v: &mut Value) {
    let Some(obj) = v.as_object_mut() else { return };
    if let Some(log) = obj.remove("source") {
        obj.insert("log".into(), log);
    }
    let t = obj
        .get("timestamp")
        .and_then(parse_time)
        .unwrap_or_else(Utc::now);
    stamp(SOURCE, t, v);
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use bytes::BytesMut;

    use super::*;
    use crate::sinks::manager::{Sink, SinkManager, SinkWrite};

    /// What reached the sink, a write at a time.
    #[derive(Default)]
    struct Deliveries(tokio::sync::Mutex<Vec<BytesMut>>);

    #[async_trait::async_trait]
    impl Sink for Deliveries {
        async fn write(&self, req: SinkWrite) -> Result<()> {
            self.0.lock().await.push(req.payload);
            Ok(())
        }
    }

    /// `x-vercel-signature` for `body` under the secret `s3cret`.
    fn signature(body: &[u8]) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(b"s3cret").unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    /// A drain listening with the secret `secret`, and what its sink gets.
    async fn listening(
        secret: &str,
    ) -> (
        SocketAddr,
        Arc<Deliveries>,
        CancellationToken,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let deliveries = Arc::new(Deliveries::default());
        let sink: Arc<dyn Sink> = deliveries.clone();
        let sinks = SinkManager::for_test(vec![(Arc::from("deliveries"), sink)], 1);
        let mut outs = ahash::AHashMap::default();
        outs.insert(
            NodeRef::Source {
                name: Arc::from("vercel"),
            },
            vec![NodeRef::Sink {
                name: Arc::from("deliveries"),
            }],
        );
        let router = Arc::new(Router::new(outs, Arc::new(sinks)));
        // a port that was free a moment ago
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .unwrap();
        let cfg = VercelDrainConfig {
            bind_address: addr,
            path: "/vercel".to_string(),
            secret: Some(secret.into()),
        };
        let shutdown = CancellationToken::new();
        let source = tokio::spawn(run_consumer(
            Arc::from("vercel"),
            cfg,
            router,
            shutdown.clone(),
        ));
        (addr, deliveries, shutdown, source)
    }

    async fn up(addr: SocketAddr) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while tokio::net::TcpStream::connect(addr).await.is_err() {
            assert!(Instant::now() < deadline, "the drain never listened");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// POST `body` with `signature`, if any, and `encoding`, if any: the status.
    async fn post_to(
        addr: SocketAddr,
        body: Vec<u8>,
        signature: Option<String>,
        encoding: Option<&str>,
    ) -> u16 {
        let mut req = reqwest::Client::new()
            .post(format!("http://{addr}/vercel"))
            .body(body);
        if let Some(signature) = signature {
            req = req.header("x-vercel-signature", signature);
        }
        if let Some(encoding) = encoding {
            req = req.header("content-encoding", encoding);
        }
        req.send()
            .await
            .expect("the drain is listening")
            .status()
            .as_u16()
    }

    /// Every record the sink has, once it has `n`.
    async fn got(deliveries: &Deliveries, n: usize) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let records: Vec<Value> = deliveries
                .0
                .lock()
                .await
                .iter()
                .flat_map(|w| {
                    String::from_utf8_lossy(w)
                        .lines()
                        .map(|l| serde_json::from_str(l).unwrap())
                        .collect::<Vec<Value>>()
                })
                .collect();
            if records.len() >= n {
                return records;
            }
            assert!(
                Instant::now() < deadline,
                "{n} records never reached the sink"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    const ARRAY: &str = r#"[{"id":"1","source":"lambda","timestamp":1573817187330,"message":"hello","proxy":{"clientIp":"203.0.113.9"}},{"id":"2","source":"firewall","timestamp":1573817188000}]"#;

    #[tokio::test]
    async fn only_a_signed_delivery_is_taken() {
        let (addr, deliveries, shutdown, source) = listening("s3cret").await;
        up(addr).await;
        let body = ARRAY.as_bytes().to_vec();

        assert_eq!(
            post_to(addr, body.clone(), None, None).await,
            403,
            "unsigned"
        );
        let other = signature(b"another body");
        assert_eq!(
            post_to(addr, body.clone(), Some(other), None).await,
            403,
            "signed over another body"
        );
        let good = signature(&body);
        assert_eq!(
            post_to(
                addr,
                b"[not json".to_vec(),
                Some(signature(b"[not json")),
                None
            )
            .await,
            400,
            "signed, but not log objects"
        );
        assert_eq!(
            post_to(addr, body.clone(), Some(good.to_uppercase()), None).await,
            200,
            "signed"
        );

        let records = got(&deliveries, 2).await;
        assert_eq!(records.len(), 2, "the signed delivery, and only it");
        assert_eq!(records[0]["source"], "vercel_drain");
        assert_eq!(records[0]["log"], "lambda", "Vercel's own source");
        assert_eq!(records[0]["ts"], "2019-11-15T11:26:27Z");
        assert_eq!(records[0]["proxy"]["clientIp"], "203.0.113.9");
        assert_eq!(records[1]["log"], "firewall");
        shutdown.cancel();
        source.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ndjson_and_gzip_are_read_as_the_array_is() {
        let (addr, deliveries, shutdown, source) = listening("s3cret").await;
        up(addr).await;

        let ndjson = b"{\"id\":\"1\",\"source\":\"edge\",\"timestamp\":1573817187330}\n\n{\"id\":\"2\",\"source\":\"build\",\"timestamp\":1573817188000}\n\"not an object\"\n".to_vec();
        let sig = signature(&ndjson);
        assert_eq!(post_to(addr, ndjson, Some(sig), None).await, 200, "ndjson");

        // signed as sent: packed
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(ARRAY.as_bytes()).unwrap();
        let packed = gz.finish().unwrap();
        let sig = signature(&packed);
        assert_eq!(
            post_to(addr, packed.clone(), Some(sig.clone()), Some("gzip")).await,
            200,
            "gzip"
        );
        assert_eq!(
            post_to(addr, packed, Some(sig), Some("br")).await,
            415,
            "an encoding it cannot unpack"
        );

        let logs: Vec<String> = got(&deliveries, 4)
            .await
            .iter()
            .map(|r| r["log"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(logs, ["edge", "build", "lambda", "firewall"]);
        shutdown.cancel();
        source.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn without_a_secret_it_does_not_listen() {
        let (addr, _deliveries, shutdown, source) = listening(" ").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "nothing listens unsigned"
        );
        shutdown.cancel();
        source.await.unwrap().unwrap();
    }

    #[test]
    fn a_record_without_a_time_gets_now() {
        let mut v = serde_json::json!({"id": "1", "source": "static"});
        finish(&mut v);
        assert_eq!(v["source"], "vercel_drain");
        assert_eq!(v["log"], "static");
        assert!(v["ts"].as_str().is_some_and(|t| t.ends_with('Z')));
    }
}
