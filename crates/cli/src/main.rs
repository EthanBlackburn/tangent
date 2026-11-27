use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_yaml::Value;
use tracing_subscriber::EnvFilter;

use tangent_bench::BenchOptions;

mod attest;
mod fetch;
mod follow;
mod init;
mod local;
mod mac;
mod notify;
use tangent_runtime::query;
mod scaffold;
mod simulate;
mod state;
mod status;
mod test;
mod watch;
mod wit_assets;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser, Debug)]
#[command(name = "tangent", version, about = "Tangent CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// What `tangent init` writes a pipeline for, and `tangent watch` runs one for.
#[derive(Subcommand, Debug)]
enum Watch {
    /// Your cloud and SaaS audit logs (CloudTrail, GitHub, Okta, ...)
    ///
    /// You say who judges them: --provider names who serves a hosted
    /// pair, and is sent every record, and --local keeps the records on
    /// this machine. With neither, it lists each and says which has its
    /// key in the environment already.
    Cloud {
        /// What to watch, one or more: --sources cloudtrail,github. Without
        /// it init writes the pipeline with no source yet
        #[arg(long, value_enum, value_delimiter = ',')]
        sources: Vec<init::Source>,
        /// A model on this machine, so no record leaves it: Inkling 2 Mini
        /// judges and reviews, on a server
        /// tangent starts with the pipeline (Apple Silicon, 32 GB of
        /// memory or more). With --model, a model server of your own at
        /// http://localhost:8080/v1 instead, which tangent does not start
        #[arg(long)]
        local: bool,
        /// Who serves the models: the pair measured with that provider,
        /// a model that judges and one that reviews
        #[arg(long, value_enum, conflicts_with = "local")]
        provider: Option<init::Provider>,
        /// Other models than the provider's pair, or with --local your
        /// server's, by the exact name each takes: one judges and reviews,
        /// and two with a comma are the judge's, then the reviewer's
        /// (--model gpt-6-luna,gpt-6.1-terra)
        #[arg(long)]
        model: Option<String>,
    },
    /// This Mac: what each program runs, opens and connects to, and what
    /// you ask Claude Code
    ///
    /// A model on this Mac judges it, so nothing the sensor reads leaves
    /// the machine: Inkling 2 Mini, on a server tangent starts with the
    /// pipeline (Apple Silicon, 32 GB of memory or more). --provider has
    /// a hosted pair judge it instead.
    Mac {
        /// Who serves the models, in place of one on this Mac: that
        /// provider's pair, a model that judges and one that reviews.
        /// Each session's summary is sent there, with its command lines,
        /// its paths and your prompts. Claude Haiku 5.5 and Sonnet 5.5
        /// (anthropic, bedrock) are the pair measured on the recorded Mac
        /// attacks
        #[arg(long, value_enum)]
        provider: Option<init::Provider>,
    },
}

/// What `tangent model` does with the model that runs on this machine.
#[derive(Subcommand, Debug)]
enum ModelCommand {
    /// Download Ollama and Inkling 2 Mini (20 GB) into tangent's cache
    ///
    /// What `tangent init cloud --local` offers to do. An Ollama of
    /// tangent's own and the model it pulls go under ~/.cache/tangent/models,
    /// apart from any Ollama of yours: the release is pinned and checked
    /// against its SHA-256, and the model against its digest. A fetch that
    /// was stopped goes on where it was.
    Fetch,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Bench {
        /// Path to tangent.yaml
        #[arg(long, value_name = "FILE")]
        config: PathBuf,

        /// Duration (seconds)
        #[arg(long, default_value_t = 15)]
        seconds: u64,

        /// Concurrent connections
        #[arg(long, default_value_t = 2)]
        connections: u16,

        /// Payload filepath.
        #[arg(long)]
        payload: PathBuf,

        /// Batch-bytes cap per write (0 = disabled)
        #[arg(long, default_value_t = 65_536)]
        max_bytes: usize,

        /// Prometheus metrics endpoint
        #[arg(long, default_value = "http://127.0.0.1:9184/metrics")]
        metrics_url: String,

        /// For S3 + SQS bench
        #[arg(long)]
        bucket: Option<String>,

        #[arg(long)]
        object_prefix: Option<String>,

        /// disable metrics. Only use if benchmarking outside of tangent watch.
        #[arg(long, default_value_t = false)]
        disable_metrics: bool,

        /// Synthesize logs. Used to generate payloads from the input payload.
        #[arg(long, default_value_t = false)]
        synthesize: bool,
    },

    Plugin {
        #[command(subcommand)]
        command: PluginCommands,
    },

    /// Print the config as tangent reads it: its includes merged, `${VAR}`
    /// expanded, defaults filled in. Secrets (tokens, api_key, webhook_url,
    /// passwords) are left out, so the output is for reading, not for running
    Config {
        /// Path to YAML config
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },

    /// Write tangent.yaml here, the whole pipeline in the one file: what
    /// you watch, a model that judges every record and one that reviews
    /// what it flagged. It asks nothing, says where your records go,
    /// fetches the plugins the config names, and writes over nothing
    Init {
        #[command(subcommand)]
        watch: Watch,
    },

    /// Run a pipeline and say what it finds: `watch cloud` and `watch mac`
    /// with nothing to keep, or `watch --config tangent.yaml` for a
    /// pipeline of your own.
    ///
    /// `watch cloud` and `watch mac` run the pipeline init would write for
    /// the same flags. It is kept in tangent's own directory
    /// (~/.local/share/tangent), written again at each start, and run from
    /// there, where its alerts and reviews are written and the next start
    /// goes on from what it has learned. It starts only with what it
    /// needs: a variable that is not set stops it, and --local downloads
    /// the model first
    #[command(args_conflicts_with_subcommands = true, arg_required_else_help = true)]
    Watch {
        #[command(subcommand)]
        watch: Option<Watch>,
        /// A pipeline of your own, run where you are: the file `tangent
        /// init` wrote, or any other. What it writes to alerts.ndjson,
        /// reviews.ndjson and verdicts.ndjson here is said as it is
        /// written, as init's pipelines do
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Exit after one drain cycle (for tests)
        #[arg(long, requires = "config")]
        once: bool,
        /// Show no notifications. Without it, at a Mac, a review that
        /// upholds an alert is shown as one, with a sound when it finds
        /// the alert malicious
        #[arg(long, global = true)]
        no_notify: bool,
    },

    /// Run an attack on this Mac, for `tangent watch mac` to catch, in a
    /// project made up for the run and against a server that is this
    /// command itself. Nothing of yours is opened or changed and nothing
    /// leaves the Mac
    Simulate {
        /// `credentials`: a script sweeps the project's keys and uploads
        /// them. `agent`: a script takes over the project's AI coding
        /// agent. With neither, the two are listed and you pick one
        attack: Option<String>,
    },

    /// The model that runs on this machine with `--local`
    Model {
        #[command(subcommand)]
        command: ModelCommand,
    },

    /// Read a past range of the config's sources through it, as fast as it
    /// is read, then close every group and wait for the judge. Each source
    /// whose past tangent can read is read (a cloudtrail source's, from its
    /// account's Event history), and the rest are left out, as are Slack, S3,
    /// sqlite and exec sinks. The history it builds starts empty and is gone
    /// after, and so is the lake a rolling_file sink writes, which is the
    /// replay's own; a live pipeline's state and lake are left as they are
    Replay {
        /// Path to YAML config
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// Start of the range: a date (2026-10-01, midnight UTC), an RFC 3339
        /// time, or a span before now (1d, 12h, 30m)
        #[arg(long, value_name = "WHEN")]
        from: String,
        /// End of the range, as --from; five minutes ago when left out, since
        /// CloudTrail typically has an event within five minutes of its call
        #[arg(long, value_name = "WHEN")]
        to: Option<String>,
    },

    /// Run one read-only SQL statement over Parquet files (a `rolling_file`
    /// sink's lake) and print the result as a table. The statement can read
    /// the tables and views named here and nothing else: it cannot create,
    /// change or copy anything, set an option, or name a file, so it may
    /// come from somewhere you do not trust. JSON text is read with
    /// `col->>'key'` and `json_get_str(col, 'key', …)`
    Query {
        /// NAME=PATH: a Parquet file, or a directory and every .parquet file
        /// under it. Repeat a name for one table over several paths
        #[arg(long = "table", value_name = "NAME=PATH", required = true)]
        tables: Vec<String>,
        /// NAME=SELECT: a view the statement can read, over the tables and
        /// the views before it
        #[arg(long = "view", value_name = "NAME=SELECT")]
        views: Vec<String>,
        /// Rows printed; the rest are counted
        #[arg(long, default_value_t = 1000)]
        max_rows: usize,
        /// Characters of a value printed; the rest are counted
        #[arg(long, default_value_t = 500)]
        max_cell: usize,
        /// Print each row as a JSON object on a line, its values whole, for
        /// a program to read
        #[arg(long)]
        json: bool,
        /// The statement
        sql: String,
    },

    /// Inspect a pipeline's state store (read-only, works while it runs)
    State {
        /// Path to YAML config; the store is found from `runtime.state`
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        #[command(subcommand)]
        command: state::StateCommands,
    },
}

#[derive(Subcommand, Debug)]
enum PluginCommands {
    /// Scaffold a new plugin project
    Scaffold {
        /// Project name (folder will be created with this name)
        #[arg(long)]
        name: String,
        /// Language: go|py|rust
        #[arg(long)]
        lang: String,
        /// Also run the project's setup.sh: installs the language toolchain
        /// and may add PATH lines to your shell profile
        #[arg(long)]
        setup: bool,
    },
    /// Test a plugin with input/expected fixtures
    Test {
        /// Test a specific plugin
        #[arg(long)]
        plugin: Option<String>,
        /// Runtime config
        #[arg(long, value_name = "FILE")]
        config: PathBuf,

        /// Enable http calls in tests
        #[arg(long, default_value_t = false)]
        enable_http: bool,
    },

    /// Compile a WASM component from a config (py via componentize-py; go via TinyGo)
    Compile {
        /// Path to YAML config (must contain entry_point, module_type)
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// A WIT directory (with the `processor` world) to compile every plugin
        /// against. Without it, each plugin compiles against this tangent's
        /// own WIT, written into the plugin's `.tangent/wit` first
        #[arg(long, value_name = "DIR")]
        wit: Option<PathBuf>,
        /// Compile one plugin, not every plugin in the config
        #[arg(long)]
        plugin: Option<String>,
    },

    /// Download the plugins a config names as `prebuilt`, compiled by their
    /// repository's CI, and check GitHub's attestation of each before it is
    /// kept, in tangent's cache for this version
    /// (~/.cache/tangent/<version>/plugins), in place of any `tangent plugin
    /// compile` build: no WASM toolchain needed, only `gh`. `tangent watch`
    /// fetches the ones it is missing; this fetches them again, or ahead of
    /// time
    Fetch {
        /// Path to YAML config
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// Fetch one plugin, not every prebuilt plugin in the config
        #[arg(long)]
        plugin: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // `tangent watch` writes runtime logs to `watch.log` in its pipeline
    // directory so the terminal stays readable, unless `RUST_LOG` is set.
    let watch_quiet =
        matches!(cli.command, Commands::Watch { .. }) && std::env::var_os("RUST_LOG").is_none();
    if !watch_quiet {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    match cli.command {
        Commands::Bench {
            config,
            seconds,
            connections,
            payload,
            max_bytes,
            metrics_url,
            bucket,
            object_prefix,
            disable_metrics,
            synthesize,
        } => {
            let opts = BenchOptions {
                config_path: Some(config.clone()),
                seconds,
                connections,
                payload,
                max_bytes,
                metrics_url,
                bucket,
                object_prefix,
                disable_metrics,
                synthesize,
            };
            tangent_bench::run(&config, opts).await?;
        }

        Commands::Config { config } => print!("{}", show_config(&config)?),

        Commands::Init {
            watch:
                Watch::Cloud {
                    sources,
                    local,
                    provider,
                    model,
                },
        } => {
            let command = init::command("init", &sources);
            let (server, models) = init::served(&command, local, provider, model.as_deref())?;
            init::run(Path::new("."), sources, server, models).await?
        }
        Commands::Init {
            watch: Watch::Mac { provider },
        } => mac::run(Path::new("."), provider).await?,

        Commands::Watch {
            watch:
                Some(Watch::Cloud {
                    sources,
                    local,
                    provider,
                    model,
                }),
            no_notify,
            ..
        } => {
            watch::sourced(&sources)?;
            let command = init::command("watch", &sources);
            let (server, models) = init::served(&command, local, provider, model.as_deref())?;
            watch::cloud(sources, server, models, no_notify).await?
        }
        Commands::Watch {
            watch: Some(Watch::Mac { provider }),
            no_notify,
            ..
        } => watch::mac(provider, no_notify).await?,
        Commands::Watch {
            watch: None,
            config,
            once,
            no_notify,
        } => {
            // clap shows the help when neither is given.
            let Some(config) = config else {
                anyhow::bail!("watch cloud, watch mac, or watch --config <FILE>");
            };
            watch::config(config, once, no_notify).await?
        }

        Commands::Simulate { attack } => simulate::run(attack)?,

        Commands::Model {
            command: ModelCommand::Fetch,
        } => local::fetch(&local::root()?).await?,

        Commands::Replay { config, from, to } => {
            let config = config.canonicalize().unwrap_or(config);
            fetch::missing(&config).await?;
            let state = tempfile::tempdir()?;
            tangent_runtime::replay::replay(tangent_runtime::replay::ReplayOptions {
                config,
                from,
                to,
                state_dir: state.path().to_path_buf(),
            })
            .await?;
        }

        Commands::Query {
            tables,
            views,
            max_rows,
            max_cell,
            json,
            sql,
        } => {
            let q = query::Query {
                tables,
                views,
                sql,
                max_rows,
                max_cell,
                json,
            };
            print!("{}", query::run(&q).await?);
        }

        Commands::State { config, command } => {
            let cfg = config.canonicalize().unwrap_or(config);
            state::run(&cfg, command).await?;
        }

        Commands::Plugin { command } => match command {
            PluginCommands::Compile {
                config,
                wit,
                plugin,
            } => {
                // resolve to absolute paths to help downstream error messages
                let cfg = config.canonicalize().unwrap_or(config);
                let wit = wit.map(|w| w.canonicalize().unwrap_or(w));
                let wit = match &wit {
                    Some(dir) => compile_wasm::Wit::Dir(dir),
                    None => compile_wasm::Wit::Write(&scaffold::write_embedded_wit),
                };
                compile_wasm::compile_from_config(&cfg, wit, plugin.as_deref())?;
            }
            PluginCommands::Fetch { config, plugin } => {
                let config = config.canonicalize().unwrap_or(config);
                fetch::run(fetch::FetchOptions {
                    config_path: config,
                    plugin,
                })
                .await?;
            }
            PluginCommands::Scaffold { name, lang, setup } => {
                scaffold::scaffold(&name, &lang, setup)?
            }
            PluginCommands::Test {
                plugin,
                config,
                enable_http,
            } => {
                let config = config.canonicalize().unwrap_or(config);
                test::run(test::TestOptions {
                    plugin,
                    config_path: config,
                    enable_http: enable_http,
                })
                .await?;
            }
        },
    }

    Ok(())
}

/// The config at `path` as YAML, after a header naming the files it was
/// merged from. Every path that names a file is absolute; `runtime` paths
/// are as written, relative to `path`. The DAG, each s3 sink's `key_prefix`,
/// each s3 and rolling_file sink's `timestamp_field`, and the required
/// tables' files are checked after: a config that does not hold together
/// still prints, then fails. What `run` would warn of is warned of on stderr.
fn show_config(path: &Path) -> Result<String> {
    let loaded = tangent_shared::Config::load(path)?;
    let dir = path
        .canonicalize()?
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default();
    let mut value = serde_yaml::to_value(&loaded.config)?;
    if let Value::Mapping(m) = &mut value {
        tangent_shared::include::rebase(m, &dir);
        // a plugin's own config is a hash map: in a fixed order, to diff
        if let Some(Value::Mapping(plugins)) = m.get_mut("plugins") {
            for p in plugins.values_mut() {
                if let Some(config) = p.get_mut("config") {
                    sort_keys(config);
                }
            }
        }
    }
    let mut out = String::from("# merged from, in order:\n");
    for f in &loaded.files {
        out.push_str(&format!("#   {}\n", f.display()));
    }
    out.push_str(
        "# secrets (tokens, api_key, webhook_url, passwords) are left out: read it, don't run it\n",
    );
    out.push_str(&serde_yaml::to_string(&value)?);
    // on stderr, so what is printed stays YAML
    for warning in loaded.config.warnings() {
        eprintln!("warning: {warning}");
    }
    let checked = loaded
        .config
        .validate()
        .and_then(|()| tangent_runtime::sinks::s3::check_sinks(&loaded.config.sinks))
        .and_then(|()| {
            loaded
                .config
                .enrichment_tables
                .iter()
                .try_for_each(|(name, table)| table.check(name, &dir))
        });
    if let Err(e) = checked {
        print!("{out}");
        return Err(e);
    }
    Ok(out)
}

fn sort_keys(v: &mut Value) {
    match v {
        Value::Mapping(m) => {
            let mut entries: Vec<(Value, Value)> = std::mem::take(m).into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| {
                serde_yaml::to_string(a)
                    .unwrap_or_default()
                    .cmp(&serde_yaml::to_string(b).unwrap_or_default())
            });
            for (k, mut v) in entries {
                sort_keys(&mut v);
                m.insert(k, v);
            }
        }
        Value::Sequence(items) => items.iter_mut().for_each(sort_keys),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Init's command line, and watch's, which is the same: what to watch
    /// is its subcommand, a provider is named alone or with other models
    /// than its pair, and a model on this machine is --local, not a
    /// provider.
    #[test]
    fn init_and_watch_take_what_to_watch_and_who_judges_it() {
        for command in ["init", "watch"] {
            let parses =
                |args: &[&str]| Cli::try_parse_from([&["tangent", command], args].concat()).is_ok();
            assert!(!parses(&[]), "{command} alone lists what it can watch");
            assert!(parses(&["cloud"]));
            assert!(parses(&["cloud", "--sources", "okta,github"]));
            assert!(parses(&["cloud", "--local"]));
            assert!(parses(&["cloud", "--local", "--model", "glm-4.7-flash"]));
            assert!(parses(&[
                "cloud",
                "--provider",
                "openai",
                "--model",
                "gpt-6-luna"
            ]));
            assert!(parses(&["cloud", "--provider", "openai"]));
            assert!(!parses(&[
                "cloud",
                "--local",
                "--provider",
                "openai",
                "--model",
                "gpt-6-luna"
            ]));
            assert!(!parses(&[
                "cloud",
                "--provider",
                "local",
                "--model",
                "glm-4.7-flash"
            ]));
            assert!(!parses(&["--sources", "okta"]), "the sources are cloud's");
            assert!(parses(&["mac"]));
            assert!(parses(&["mac", "--provider", "bedrock"]));
            assert!(!parses(&["mac", "--hosted"]), "a provider is named");
            assert!(
                !parses(&["mac", "--provider", "openai", "--model", "gpt-6-luna"]),
                "a Mac's models are its provider's pair"
            );
            assert!(
                !parses(&["mac", "--sources", "okta"]),
                "a Mac is watched whole"
            );
            assert!(
                !parses(&["mac", "--local"]),
                "a Mac is judged here unless --provider"
            );
        }
    }

    #[test]
    fn config_fails_on_a_required_table_without_its_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("profile")).unwrap();
        std::fs::write(dir.path().join("profile/profile.yaml"), "org: acme\n").unwrap();
        let config = |path: &str| {
            let file = dir.path().join("ingest.yaml");
            std::fs::write(
                &file,
                format!(
                    "enrichment_tables:\n  profile: {{ type: document, path: {path}, required: true }}\n  geo: {{ type: mmdb, path: missing.mmdb }}\n"
                ),
            )
            .unwrap();
            show_config(&file)
        };
        let shown = config("profile/profile.yaml").unwrap();
        assert!(shown.contains("required: true"), "{shown}");
        let err = format!("{:#}", config("profle/profile.yaml").unwrap_err());
        assert!(err.contains("enrichment table profile: "), "{err}");
        assert!(
            err.contains("profle/profile.yaml not found, and the table is required"),
            "{err}"
        );
    }

    #[test]
    fn config_prints_an_s3_key_prefix_and_fails_on_one_not_strftime() {
        let dir = tempfile::tempdir().unwrap();
        let config = |prefix: &str| {
            let file = dir.path().join("tangent.yaml");
            std::fs::write(
                &file,
                format!("sinks:\n  archive: {{ type: s3, bucket_name: logs, key_prefix: \"{prefix}\" }}\n"),
            )
            .unwrap();
            show_config(&file)
        };
        let shown = config("cloudtrail/%Y/%m/%d").unwrap();
        assert!(shown.contains("key_prefix: cloudtrail/%Y/%m/%d"), "{shown}");
        let err = format!("{:#}", config("cloudtrail/%Q").unwrap_err());
        assert!(
            err.contains("sink 'archive'") && err.contains("not a strftime template"),
            "{err}"
        );
    }

    #[test]
    fn config_shows_the_default_url_only_where_it_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tangent.yaml");
        std::fs::write(
            &file,
            "models:\n  cloud: { type: bedrock, model: m }\n  local: { type: openai, model: m }\n",
        )
        .unwrap();
        let shown = show_config(&file).unwrap();
        let value: Value = serde_yaml::from_str(&shown).unwrap();
        assert_eq!(
            value["models"]["cloud"].get("url"),
            None,
            "bedrock reads no url: {shown}"
        );
        assert_eq!(
            value["models"]["local"]["url"],
            Value::from("http://localhost:8080/v1"),
            "{shown}"
        );
    }

    /// Two inference nodes wired round in a cycle: `tangent config` fails, as
    /// `run` does, before a record goes round it.
    #[test]
    fn config_fails_on_a_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tangent.yaml");
        std::fs::write(
            &file,
            "sources:\n  input: { type: file, path: in.ndjson, decoding: { format: { type: ndjson } } }\n\
             models:\n  m: { type: openai, model: m }\n\
             inference:\n  first: { model: m, prompt_file: p.txt, inputs: [input, second] }\n  \
             second: { model: m, prompt_file: p.txt, inputs: [first] }\n\
             sinks:\n  looped: { type: file, path: looped.ndjson, inputs: [second] }\n",
        )
        .unwrap();
        let err = format!("{:#}", show_config(&file).unwrap_err());
        assert!(err.contains("a cycle: first -> second -> first"), "{err}");
    }
}
