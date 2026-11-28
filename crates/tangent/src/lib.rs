use crate::stop::Stop;
use anyhow::{bail, Result};
use std::{net::SocketAddr, path::PathBuf};
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::info;

use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
    HistogramVec, IntCounter, IntCounterVec, IntGauge,
};

use tangent_shared::Config;

use crate::dag::DagRuntime;

pub mod dag;
pub mod enrichment;
pub mod group;
pub mod inference;
pub mod pending;
pub mod query;
pub mod record;
pub mod replay;
pub mod router;
pub mod sinks;
pub mod sources;
pub mod state;
pub mod stop;
pub mod wasm;
pub mod worker;

/// Options for running the runtime.
#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub prometheus_bind: Option<SocketAddr>,
    pub once: bool,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            prometheus_bind: Some("0.0.0.0:9184".parse().unwrap()),
            once: false,
        }
    }
}

lazy_static::lazy_static! {
    pub static ref GUEST_LATENCY: HistogramVec = register_histogram_vec!(
        "tangent_guest_seconds",
        "WASM guest call latency (sec)",
        &["worker"],
        vec![5e-5,1e-4,2e-4,4e-4,8e-4,1.6e-3,3.2e-3,6.4e-3,1.28e-2,2.56e-2,5.12e-2,0.102,0.204,0.409,0.819,1.638]
    ).unwrap();

    /// A model's request from asked to answered, its retries included and its
    /// wait for a place among the model's `concurrency` not: a judge's
    /// batch, or one turn of a conversation.
    pub static ref INFERENCE_SECONDS: HistogramVec = register_histogram_vec!(
        "tangent_inference_seconds",
        "Model request latency, by inference node (sec)",
        &["node"],
        vec![0.5, 1.0, 2.0, 4.0, 8.0, 15.0, 30.0, 60.0, 120.0, 300.0]
    ).unwrap();

    pub static ref GUEST_BYTES_TOTAL: IntCounter =
        register_int_counter!("tangent_guest_bytes_total", "Bytes fed to WASM guest").unwrap();

    pub static ref PLUGIN_TRAPS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tangent_plugin_traps_total",
        "Plugin instances that trapped (panicked) and were instantiated again",
        &["plugin"]
    ).unwrap();

    pub static ref CONSUMER_BYTES_TOTAL: IntCounter =
        register_int_counter!("tangent_consumer_bytes_total", "Bytes consumed (raw input)").unwrap();

    pub static ref CONSUMER_OBJECTS_TOTAL: IntCounter =
        register_int_counter!("tangent_consumer_objects_total", "Objects consumed (raw input)").unwrap();

    pub static ref WAL_SEALED_BYTES_TOTAL: IntCounter =
        register_int_counter!("tangent_wal_sealed_bytes_total", "Bytes sealed to WAL files").unwrap();

    pub static ref WAL_SEALED_FILES_TOTAL: IntCounter =
        register_int_counter!("tangent_wal_sealed_files_total", "WAL files sealed").unwrap();

    pub static ref SINK_BYTES_TOTAL: IntCounter =
        register_int_counter!("tangent_sink_bytes_total", "Bytes uploaded to sink").unwrap();

    pub static ref SINK_BYTES_UNCOMPRESSED_TOTAL: IntCounter =
        register_int_counter!("tangent_sink_bytes_uncompressed_total", "Bytes (uncompressed) uploaded to sink").unwrap();

    pub static ref SINK_OBJECTS_TOTAL: IntCounter =
        register_int_counter!("tangent_sink_objects_total", "Objects sent to sink").unwrap();

    pub static ref SINK_RECORDS_UNFIT_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tangent_sink_records_unfit_total",
        "Records a sink's encoding could not take: kept (whole, in the record column, typed columns null) or dropped",
        &["fate"]
    ).unwrap();

    pub static ref SINK_RECORDS_REJECTED_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tangent_sink_records_rejected_total",
        "Records a sink's destination refused for good (Slack: a 4xx other than 429): dropped, not retried",
        &["sink"]
    ).unwrap();

    pub static ref SINK_RECORDS_UNTIMED_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tangent_sink_records_untimed_total",
        "Records without an RFC 3339 time in their sink's timestamp_field: put under the prefix of the time they reached the sink",
        &["sink"]
    ).unwrap();

    pub static ref INFLIGHT: IntGauge =
        register_int_gauge!("tangent_inflight", "Batches enqueued but not yet persisted").unwrap();

    pub static ref WAL_PENDING_FILES: IntGauge =
        register_int_gauge!("tangent_wal_pending_files", "Sealed WAL files pending upload").unwrap();

    pub static ref WAL_PENDING_BYTES: IntGauge =
        register_int_gauge!("tangent_wal_pending_bytes", "Approx bytes pending in sealed WAL files").unwrap();

    pub static ref UNROUTED_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tangent_unrouted_records_total",
        "Records dropped because no target on their node's edges took them",
        &["node"]
    ).unwrap();

    pub static ref SOURCE_UNDECODABLE_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tangent_source_undecodable_total",
        "Messages, or objects they name, that a source could not decode and skipped",
        &["source"]
    ).unwrap();
}

/// How many files this process may have open, raised as far as it is let.
/// What launchd starts is given 256, and a query of the lake opens every
/// file of the hours it is asked about at once: a lake a few days old has
/// more than that, and the review that asked was failed with "Too many open
/// files". macOS takes no more than `OPEN_MAX` whatever the hard limit says.
#[cfg(unix)]
fn raise_open_files() {
    const ENOUGH: libc::rlim_t = 10_240;
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `limit` is a valid rlimit for both calls to read and write.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return;
        }
        let want = limit.rlim_max.min(ENOUGH);
        if limit.rlim_cur >= want {
            return;
        }
        let had = limit.rlim_cur;
        limit.rlim_cur = want;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
            tracing::warn!(open_files = had, "the limit on open files could not be raised");
        }
    }
}

#[cfg(not(unix))]
fn raise_open_files() {}

pub async fn run(config_path: &PathBuf, opts: RuntimeOptions) -> Result<()> {
    let cfg = Config::from_file(config_path)?;
    cfg.validate()?;
    for warning in cfg.warnings() {
        tracing::warn!("{warning}");
    }

    // Metrics are worth having, not worth dying for: a second tangent on the
    // box, or anything else on the port, must not keep this one from running.
    let _exporter_guard =
        opts.prometheus_bind
            .and_then(|addr| match prometheus_exporter::start(addr) {
                Ok(guard) => Some(guard),
                Err(e) => {
                    tracing::warn!(%addr, "metrics exporter not started: {e}");
                    None
                }
            });

    if cfg.sources.is_empty() {
        bail!("At least one source is required.");
    }
    if cfg.sinks.is_empty() {
        bail!("At least one sink is required.");
    }
    if cfg.edges().is_empty() {
        bail!("No node has `inputs`: nothing would be read.");
    }

    if std::env::var("DEBUG").is_ok_and(|x| x == "1") {
        console_subscriber::init();
    }
    tracing::debug!(target = "startup", config = ?cfg);

    raise_open_files();

    let ingest_shutdown = CancellationToken::new();
    let stop = Stop::default();

    info!(
        "Batch size: {} KiB, max age: {:?}",
        cfg.runtime.batch_size,
        cfg.batch_age_ms()
    );

    let dag_runtime =
        DagRuntime::build(cfg, &config_path, ingest_shutdown.clone(), stop.clone()).await?;
    info!("pipeline started");

    #[cfg(feature = "alloc-prof")]
    jemalloc_dump("warm");

    if opts.once {
        // Nothing here waits for a signal, so one ends the run's model
        // calls, as it does a replay's; what waited on them is saved, as
        // any run's is.
        let stop = stop.clone();
        tokio::spawn(async move {
            if wait_for_shutdown_signal().await.is_ok() {
                stopping(&stop);
            }
        });
    } else {
        wait_for_shutdown_signal().await?;
        info!("stopping: nothing more is read, and no new request goes to a model. The requests already sent are waited for, and what was still waiting is saved for the next start. A second signal ends those requests");
        finishing(&stop);
    }

    #[cfg(feature = "alloc-prof")]
    jemalloc_dump("pre_teardown");

    info!("received shutdown signal...");
    ingest_shutdown.cancel();

    dag_runtime
        .shutdown(Duration::from_secs(120), Duration::from_secs(120))
        .await?;

    Ok(())
}

/// What the first signal of a run starts: no request is sent to a model from
/// here on, and a second signal ends the ones under way ([`stopping`]). One
/// within a second of the first is the same stop: a terminal's SIGINT, and
/// the SIGTERM of whatever started tangent.
fn finishing(stop: &Stop) {
    stop.finish();
    let stop = stop.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if wait_for_shutdown_signal().await.is_ok() {
            tracing::warn!("second signal: the requests under way end, and their records are saved too. Another exits now");
            stopping(&stop);
        }
    });
}

/// The model calls end, and a signal a second or more after exits at once:
/// the second signal of a run, and the first of a replay.
pub(crate) fn stopping(stop: &Stop) {
    stop.end();
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if wait_for_shutdown_signal().await.is_ok() {
            tracing::warn!("another signal; exiting now");
            inference::serve::end_now();
            std::process::exit(130);
        }
    });
}

pub async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal;
        use tokio::signal::unix::{signal as unix_signal, SignalKind};
        let mut term = unix_signal(SignalKind::terminate())?;
        tokio::select! {
            _ = signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}

#[cfg(feature = "alloc-prof")]
fn jemalloc_dump(tag: &str) {
    use tikv_jemalloc_ctl;
    unsafe {
        let _: tikv_jemalloc_ctl::Result<()> =
            tikv_jemalloc_ctl::raw::write::<*const libc::c_char>(b"prof.dump\0", std::ptr::null());
    }
    tracing::warn!("jemalloc: forced heap dump ({tag})");
}

#[cfg(all(test, unix))]
mod open_files {
    #[test]
    fn what_launchd_gives_is_raised() {
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: `limit` is a valid rlimit to read into and to set from.
        unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
            // never below what the tests running beside this one have open
            let low = limit.rlim_cur.min(4096);
            limit.rlim_cur = low;
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
            super::raise_open_files();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
            assert_eq!(limit.rlim_cur, limit.rlim_max.min(10_240), "from {low}");
        }
    }
}
