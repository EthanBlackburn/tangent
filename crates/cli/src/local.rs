//! A model on this machine, fetched: what `tangent init cloud --local` and
//! `tangent model fetch` download so that `tangent watch` can start Inkling 2
//! Mini on Ollama with nothing else installed.
//!
//! Both go under tangent's cache ([`tangent_shared::cache::models`]), apart
//! from any Ollama the user has, and tangent writes nothing outside it: no
//! shell profile, no application, no package manager.
//!
//! - **Ollama**, the release named here, from GitHub: its archive's size and
//!   SHA-256 are in this file, checked as it is written.
//! - **The model**, which that Ollama pulls from its own library into a
//!   store under the cache. Ollama checks each file against the model's
//!   manifest, and the manifest's digest is in this file: a pull that ends
//!   with another build is refused. The build is the one the settings init
//!   writes were measured with.
//!
//! A fetch that is stopped goes on where it was: a part of the archive is
//! kept and resumed, and Ollama takes up a pull where it broke off.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt as _;

/// A file to fetch: its name, its size in bytes and its SHA-256.
type File = (&'static str, u64, &'static str);

/// Ollama, and its release's archive for a Mac.
const OLLAMA: &str = "0.40.18";
const ARCHIVE: File = (
    "ollama-darwin.tgz",
    188_838_885,
    "015261f434d31d7f0781f8ba6b59cc8e1f70ecb562a4e6db44dfdd5e02f7e562",
);

/// The model as Ollama's library names it, which is its name in a request
/// too: the build for Apple Silicon, by its own tag, since `latest` is
/// whichever build the library gives the machine that asks.
pub const MODEL: &str = "inkling-2-mini:26b-a5b-nvfp4";
/// The digest of that build's manifest, as Ollama reports it once pulled.
const DIGEST: &str = "d183b1321cb57f018c738d2a826d70f575656fbcb7cec67f333d15b0f6a3d178";
/// What the model's files come to.
const MODEL_BYTES: u64 = 20_188_097_680;

/// Where tangent's Ollama listens while it serves: a port of its own, so
/// an Ollama the user runs is neither used nor in the way.
pub const PORT: u16 = 11435;

/// How much room a fetch wants beyond what it downloads.
const SPARE: u64 = 4_000_000_000;
/// How often a download says how far it is.
const SAY_EVERY: Duration = Duration::from_secs(5);
/// How many times a download is taken up again after it breaks off.
const TRIES: usize = 5;
/// How long a started Ollama has to answer.
const READY: Duration = Duration::from_secs(60);

/// Where everything is kept.
pub fn root() -> Result<PathBuf> {
    tangent_shared::cache::models()
}

/// Ollama's own directory under `root`, with the program in it.
fn engine(root: &Path) -> PathBuf {
    root.join(format!("ollama-{OLLAMA}"))
}

/// Where tangent's Ollama keeps its models under `root`.
fn store(root: &Path) -> PathBuf {
    root.join("ollama-models")
}

/// The two paths the config names, under the cache as the config writes it
/// (`${HOME}/.cache`, say): the program that serves, and the directory its
/// models are in.
pub fn paths(cache: &str) -> (String, String) {
    let root = format!("{cache}/tangent/models");
    (
        format!("{root}/ollama-{OLLAMA}/ollama"),
        format!("{root}/ollama-models"),
    )
}

/// Written last into Ollama's directory, so one that is there is whole.
fn installed(root: &Path) -> PathBuf {
    engine(root).join(".tangent-installed")
}

/// Written into the store once the model is pulled and its digest checked.
fn pulled(root: &Path) -> PathBuf {
    store(root).join(format!(".tangent-{}", &DIGEST[..12]))
}

/// What is not there yet.
pub struct Missing {
    pub engine: bool,
    /// The bytes of the model still to download.
    pub model: u64,
}

impl Missing {
    pub fn nothing(&self) -> bool {
        !self.engine && self.model == 0
    }

    /// About how much there is to download, in bytes.
    pub fn bytes(&self) -> u64 {
        self.model + if self.engine { ARCHIVE.1 } else { 0 }
    }
}

/// A size as people, and the pages the model is downloaded from, say it:
/// in decimal units.
pub fn size(bytes: u64) -> String {
    match bytes {
        b if b >= 1_000_000_000 => format!("{:.1} GB", b as f64 / 1e9),
        b => format!("{} MB", b.div_ceil(1_000_000)),
    }
}

/// What of Ollama and the model is not under `root` yet. The model counts
/// once its digest has been checked; until then, what a pull that was
/// stopped has left in the store counts for what it holds.
pub fn missing(root: &Path) -> Missing {
    let model = if pulled(root).is_file() {
        0
    } else {
        let have: u64 = std::fs::read_dir(store(root).join("blobs"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.metadata().ok())
            .map(|m| m.len())
            .sum();
        // never nothing: the pull has still to end and be checked
        MODEL_BYTES.saturating_sub(have).max(1)
    };
    Missing {
        engine: !installed(root).is_file(),
        model,
    }
}

/// Fetches what is missing under `root`: Ollama, then the model.
pub async fn fetch(root: &Path) -> Result<()> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        bail!(
            "tangent starts Inkling 2 Mini on Apple Silicon Macs only, so there is nothing to fetch for this machine"
        );
    }
    std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let missing = missing(root);
    if missing.nothing() {
        println!(
            "Ollama {OLLAMA} and Inkling 2 Mini are already in {}.",
            root.display()
        );
        return Ok(());
    }
    let free = fs2::available_space(root)
        .with_context(|| format!("reading the free space of {}", root.display()))?;
    if free < missing.bytes() + SPARE {
        bail!(
            "{} has {} free, and this needs {} with {} to spare",
            root.display(),
            size(free),
            size(missing.bytes()),
            size(SPARE)
        );
    }
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(60))
        .build()?;
    if missing.engine {
        install(root, &http).await?;
    }
    if missing.model > 0 {
        pull(root, &http).await?;
    }
    println!(
        "Ollama {OLLAMA} and Inkling 2 Mini are in {}.",
        root.display()
    );
    Ok(())
}

/// Ollama's archive, checked and unpacked into a directory of its own.
async fn install(root: &Path, http: &reqwest::Client) -> Result<()> {
    let archive = root.join(ARCHIVE.0);
    let url = format!(
        "https://github.com/ollama/ollama/releases/download/v{OLLAMA}/{}",
        ARCHIVE.0
    );
    download(http, &url, &archive, ARCHIVE).await?;
    // A directory left by an install that did not finish is made again.
    let dir = engine(root);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    println!("Unpacking Ollama {OLLAMA} into {}", dir.display());
    run(
        tokio::process::Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&dir),
        "unpacking Ollama",
    )
    .await?;
    std::fs::remove_file(&archive).ok();
    if !dir.join("ollama").is_file() {
        bail!("Ollama's archive did not hold ollama");
    }
    std::fs::write(installed(root), format!("ollama {OLLAMA}\n"))?;
    Ok(())
}

/// The model, pulled by tangent's Ollama into its store, and its digest
/// checked. An Ollama is started for the pull, on a port of its own, and
/// stopped after it.
async fn pull(root: &Path, http: &reqwest::Client) -> Result<()> {
    let program = engine(root).join("ollama");
    let store = store(root);
    std::fs::create_dir_all(&store).with_context(|| format!("creating {}", store.display()))?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let host = format!("127.0.0.1:{port}");
    // its own address and store, and none of Ollama's hosted features
    let env = [
        ("OLLAMA_HOST", host.as_str()),
        ("OLLAMA_MODELS", &*store.to_string_lossy()),
        ("OLLAMA_NO_CLOUD", "1"),
    ];
    let mut server = tokio::process::Command::new(&program)
        .arg("serve")
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting {}", program.display()))?;
    let version = format!("http://{host}/api/version");
    let began = Instant::now();
    while !matches!(http.get(&version).send().await, Ok(r) if r.status().is_success()) {
        if let Some(status) = server.try_wait()? {
            bail!("Ollama stopped before it answered ({status})");
        }
        if began.elapsed() > READY {
            bail!("Ollama did not answer at {host} within a minute");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    println!(
        "Downloading Inkling 2 Mini ({}) into {}",
        size(MODEL_BYTES),
        store.display()
    );
    run(
        tokio::process::Command::new(&program)
            .args(["pull", MODEL])
            .envs(env),
        "downloading the model",
    )
    .await?;

    let tags: serde_json::Value = http
        .get(format!("http://{host}/api/tags"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("reading what Ollama pulled")?;
    let digest = tags["models"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|m| m["name"] == MODEL)
        .and_then(|m| m["digest"].as_str())
        .with_context(|| format!("Ollama pulled {MODEL} and does not list it"))?;
    if digest != DIGEST {
        bail!(
            "Ollama's library now gives another build of {MODEL} than the one tangent's settings were measured with (digest {digest}, not {DIGEST}); a newer tangent names the build it gives"
        );
    }
    std::fs::write(pulled(root), format!("{MODEL} {DIGEST}\n"))?;
    server.kill().await.ok();
    Ok(())
}

/// Runs `command` with tangent's own output, and fails when it does.
async fn run(command: &mut tokio::process::Command, doing: &str) -> Result<()> {
    let status = command
        .stdin(Stdio::null())
        .status()
        .await
        .with_context(|| format!("{doing}: starting {:?}", command.as_std().get_program()))?;
    if !status.success() {
        bail!("{doing} failed ({status})");
    }
    Ok(())
}

/// Where a file is written until it is whole and checked.
fn partial(to: &Path) -> PathBuf {
    let mut name = to.as_os_str().to_owned();
    name.push(".part");
    PathBuf::from(name)
}

/// `url` to `to`, which must come to `file`'s size and SHA-256. It is
/// written beside `to` and renamed once it has passed; what a download that
/// broke off left there is kept and added to, and one that does not pass
/// is removed.
async fn download(http: &reqwest::Client, url: &str, to: &Path, file: File) -> Result<()> {
    let (name, size, sha256) = file;
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let part = partial(to);
    let mut last = None;
    for attempt in 1..=TRIES {
        match resume(http, url, &part, name, size).await {
            Ok(digest) if digest == sha256 => {
                std::fs::rename(&part, to).with_context(|| format!("naming {}", to.display()))?;
                return Ok(());
            }
            Ok(digest) => {
                std::fs::remove_file(&part).ok();
                bail!("{name}: what was downloaded is not the file expected (SHA-256 {digest}, not {sha256}); it is removed");
            }
            Err(e) => {
                eprintln!("  {name}: {e:#}; trying again ({attempt} of {TRIES})");
                last = Some(e);
                tokio::time::sleep(Duration::from_secs(2 * attempt as u64)).await;
            }
        }
    }
    Err(last
        .expect("it was tried")
        .context(format!("downloading {name}")))
}

/// Downloads what `part` lacks of `size` bytes, and returns the SHA-256 of
/// the whole.
async fn resume(
    http: &reqwest::Client,
    url: &str,
    part: &Path,
    name: &str,
    size: u64,
) -> Result<String> {
    let mut have = std::fs::metadata(part).map_or(0, |m| m.len());
    if have > size {
        std::fs::remove_file(part)?;
        have = 0;
    }
    let mut hasher = Sha256::new();
    if have > 0 {
        let mut kept = std::fs::File::open(part)?;
        std::io::copy(&mut kept, &mut hasher)?;
    }
    if have < size {
        let mut request = http.get(url);
        if have > 0 {
            request = request.header(reqwest::header::RANGE, format!("bytes={have}-"));
        }
        let mut reply = request.send().await?.error_for_status()?;
        // A server that sends the whole file where the rest was asked for
        // is taken at its word: the part is started again.
        if have > 0 && reply.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            have = 0;
            hasher = Sha256::new();
        }
        let mut out = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(have > 0)
            .truncate(have == 0)
            .open(part)
            .await
            .with_context(|| format!("writing {}", part.display()))?;
        let mut said = Instant::now();
        while let Some(chunk) = reply.chunk().await? {
            out.write_all(&chunk).await?;
            hasher.update(&chunk);
            have += chunk.len() as u64;
            if have > size {
                bail!("more was sent than the file's {size} bytes");
            }
            if size > 64 << 20 && said.elapsed() >= SAY_EVERY {
                said = Instant::now();
                print!(
                    "\r  {name}: {} of {}   ",
                    self::size(have),
                    self::size(size)
                );
                std::io::stdout().flush().ok();
            }
        }
        out.flush().await?;
        if size > 64 << 20 {
            println!(
                "\r  {name}: {} of {}   ",
                self::size(have),
                self::size(size)
            );
        }
    }
    if have != size {
        bail!("{} of {size} bytes arrived", have);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The archive and the model are pinned by whole SHA-256 digests.
    #[test]
    fn what_is_fetched_is_named_by_its_digest() {
        for digest in [ARCHIVE.2, DIGEST] {
            assert_eq!(digest.len(), 64);
            assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        assert!(ARCHIVE.1 > 0);
        // a tag of its own, and not whichever build `latest` is
        assert!(MODEL.starts_with("inkling-2-mini:") && !MODEL.ends_with(":latest"));
    }

    /// The config's two paths are where the fetch puts Ollama and its
    /// models.
    #[test]
    fn the_config_names_what_the_fetch_writes() {
        let root = Path::new("/c/tangent/models");
        let (program, models) = paths("/c");
        assert_eq!(Path::new(&program), engine(root).join("ollama"));
        assert_eq!(Path::new(&models), store(root));
    }

    /// Nothing fetched is everything missing; what a stopped pull left
    /// counts for what it holds, and the model is there only once its
    /// digest was checked.
    #[test]
    fn what_is_missing_is_what_is_not_there_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let none = missing(tmp.path());
        assert!(none.engine);
        assert_eq!(none.model, MODEL_BYTES);
        assert_eq!(none.bytes(), MODEL_BYTES + ARCHIVE.1);
        assert!(!none.nothing());

        let blobs = store(tmp.path()).join("blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::write(blobs.join("sha256-00"), [0u8; 10]).unwrap();
        assert_eq!(missing(tmp.path()).model, MODEL_BYTES - 10);
        std::fs::write(pulled(tmp.path()), "").unwrap();
        assert_eq!(missing(tmp.path()).model, 0);

        std::fs::create_dir_all(engine(tmp.path())).unwrap();
        assert!(missing(tmp.path()).engine, "a directory is not an install");
        std::fs::write(installed(tmp.path()), "").unwrap();
        assert!(missing(tmp.path()).nothing());
    }

    /// A server of one file, which sends the rest of it when asked for a
    /// range, and `broken` times stops half way through what it was asked.
    async fn serves(body: Vec<u8>, broken: usize) -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        let asked = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&asked);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut head = vec![0u8; 4096];
                let n = sock.read(&mut head).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&head[..n]).to_ascii_lowercase();
                let from: usize = head
                    .split("range: bytes=")
                    .nth(1)
                    .and_then(|r| r.split('-').next())
                    .and_then(|n| n.trim().parse().ok())
                    .unwrap_or(0);
                let rest = &body[from..];
                let status = if from > 0 {
                    "206 Partial Content"
                } else {
                    "200 OK"
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    rest.len()
                );
                let _ = sock.write_all(reply.as_bytes()).await;
                let nth = count.fetch_add(1, Ordering::SeqCst);
                let send = if nth < broken {
                    &rest[..rest.len() / 2]
                } else {
                    rest
                };
                let _ = sock.write_all(send).await;
            }
        });
        (url, asked)
    }

    fn digest(body: &[u8]) -> &'static str {
        Box::leak(hex::encode(Sha256::digest(body)).into_boxed_str())
    }

    /// A download that breaks off is taken up where it stopped, and the
    /// file has its name only once the whole has its digest.
    #[tokio::test]
    async fn a_download_that_breaks_off_goes_on_from_its_part() {
        let body: Vec<u8> = (0..200_000u32).flat_map(|n| n.to_le_bytes()).collect();
        let (url, asked) = serves(body.clone(), 2).await;
        let tmp = tempfile::tempdir().unwrap();
        let to = tmp.path().join("dir").join("file");
        let file = ("file", body.len() as u64, digest(&body));

        download(&reqwest::Client::new(), &url, &to, file)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), body);
        assert!(!partial(&to).exists());
        assert_eq!(
            asked.load(Ordering::SeqCst),
            3,
            "twice broken, then the rest"
        );
    }

    /// A file that is not the one expected is removed, and the error says
    /// so.
    #[tokio::test]
    async fn a_file_with_another_digest_is_refused_and_removed() {
        let body = b"not the file".to_vec();
        let (url, _) = serves(body.clone(), 0).await;
        let tmp = tempfile::tempdir().unwrap();
        let to = tmp.path().join("file");
        let file = ("file", body.len() as u64, digest(b"the file"));

        let e = download(&reqwest::Client::new(), &url, &to, file)
            .await
            .unwrap_err();
        assert!(format!("{e:#}").contains("not the file expected"), "{e:#}");
        assert!(!to.exists());
        assert!(!partial(&to).exists());
    }
}
