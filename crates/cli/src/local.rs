//! A model on this machine, fetched: what `tangent init cloud --local` and
//! `tangent model fetch` download so that `tangent run` can start Inkling 2
//! Mini on MTPLX with nothing else installed.
//!
//! Everything goes under tangent's cache ([`tangent_shared::cache::models`]),
//! and nothing outside it is written: no shell profile, no system Python,
//! no package manager. Each step downloads one pinned thing and checks it:
//!
//! - **uv**, the release named here, from GitHub: its archive's SHA-256 is
//!   in this file.
//! - **Python**, which uv downloads for itself and checks against the
//!   digests it carries; a pinned uv is a pinned list of Pythons.
//! - **MTPLX** and what it needs, from PyPI, as mtplx.lock lists them: uv
//!   installs with `--require-hashes`, so a package is one of the files the
//!   lock names or the install fails. The lock is what the settings init
//!   writes were measured with.
//! - **The model**, from Hugging Face at one revision: each file's size and
//!   SHA-256 are in this file, checked as it is written, and a file is
//!   given its name only once it has passed.
//!
//! A fetch that is stopped goes on where it was: a part of a file is kept
//! and resumed, and a file already there is not fetched again.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt as _;

/// The uv that installs MTPLX, and its archive for Apple Silicon.
const UV: &str = "0.13.9";
const UV_ARCHIVE: File = (
    "uv-aarch64-apple-darwin.tar.gz",
    14_554_974,
    "5aeca67f2283f75235de40d0bd9c0a5bbc5fce23b6d48b3bf9fa1b2db08382ca",
);

/// The Python MTPLX runs on, which uv downloads.
const PYTHON: &str = "3.12";

/// MTPLX, and every package it is installed with, each with its hashes.
const MTPLX: &str = "2.13.1";
const LOCK: &str = include_str!("mtplx.lock");

/// The model: its repository on Hugging Face, and the revision whose files
/// are listed.
const REPO: &str = "Youssofal/Inkling-2-Mini-MTPLX-Optimized-Speed";
const REVISION: &str = "b7570c070c17d2c148979ce2fb9404efa4760bd6";
const MODEL: &str = "Inkling-2-Mini-MTPLX-Optimized-Speed";

/// A file to fetch: its name, its size in bytes and its SHA-256.
type File = (&'static str, u64, &'static str);

/// The model's files at [`REVISION`]. The pack's own SHA256SUMS lists the
/// same digests for the eighteen of them it covers.
const FILES: &[File] = &[
    (
        "README.md",
        11163,
        "11e9a49c5147437d000882dd435b495b88e7054db3ae0194c6738cfaaf9c8498",
    ),
    (
        "SHA256SUMS",
        1602,
        "472afc7b842d937f543738de80155590c86fe06162e5368aff3a368be0043539",
    ),
    (
        "chat_template.jinja",
        6868,
        "53a9035f3255945704b5857657cfb00c1165090c0641c4f782a0cbf268cc16dc",
    ),
    (
        "config.json",
        16387,
        "e626ee1f417fffb18ae9fc5d7621b71db9a6a5148adeafcc65d325f955b32fe5",
    ),
    (
        "generation_config.json",
        98,
        "a08737c07a65a8fdf69f7cf086576210e5aad4b241437090b26d7b0c4f7905f7",
    ),
    (
        "hf_quant_config.json",
        67502,
        "2a5a162df1cb36ce2f1a5ad1a05741a8583f4428622d9e9dc8e87f5a452cca3d",
    ),
    (
        "model-00001-of-00004.safetensors",
        4843767420,
        "a5b62917d8436446a435779c43ee2276b7f0afb98020b1d62f8b93af6615bf59",
    ),
    (
        "model-00002-of-00004.safetensors",
        4859129880,
        "136d9d020d086a579028936559bc65d33698dd05ae06c088162e0f3d5e544d1d",
    ),
    (
        "model-00003-of-00004.safetensors",
        4840240336,
        "f041cf5e4ee73480ac87928f06ca359f16e831996424c48175f156b1ed88200e",
    ),
    (
        "model-00004-of-00004.safetensors",
        2033850692,
        "130148560286359e2a8ab633924940110a8413351d89cf85579891081ce2944d",
    ),
    (
        "model.safetensors.index.json",
        138206,
        "47ed0b7e27f2613d91a74dcb3d3005cd5fe341e6e88621eb920f95f6483a47a9",
    ),
    (
        "mtp.safetensors",
        635801416,
        "7c3b651317f01f73bcf4e1dceba66ef8b7e1a1eac6bc171e882e690a4b10a1d2",
    ),
    (
        "mtplx-pack.json",
        568,
        "d145eb704c59b6cf4be8e60ce6e2358c60de14cb96271f5fe0afa1bae014fb7e",
    ),
    (
        "mtplx_runtime.json",
        2836,
        "0ca9fb890b3d5b0496fd6aa5df5652a703dfd813dea588bd376a35c79c096a90",
    ),
    (
        "processor_config.json",
        461,
        "d7350adce18c8be4b607f261c8f0f7eabbf720bb7aaf648a43d4f8372bbacc2d",
    ),
    (
        "special_tokens_map.json",
        529,
        "c16f44b3594563d82743ddb0417a2be1bfe3e2000dfad2da4b8f32554593e1a0",
    ),
    (
        "tiktoken/tokenizer.model",
        3386494,
        "f170372dd655728909228220d77cf6b8104a59f38a91262a7d2c4027906ec0d8",
    ),
    (
        "tokenizer.json",
        26178678,
        "7f332727f9a3f093dd452a39cc978e6757627e5dad1b0673aa4e75174f236dd6",
    ),
    (
        "tokenizer_config.json",
        13235,
        "bf09342d285139fd37ce10c70878af1d52cb390e9901e10248654293a80ee636",
    ),
    (
        "vision-audit.json",
        399,
        "f145b6e0cb248f1f09081f1a7ec3ce4c896e6f4c23727386af4a36e136259e5c",
    ),
];

/// How much room a fetch wants beyond what it downloads.
const SPARE: u64 = 4_000_000_000;
/// About what uv, Python and MTPLX's packages take, for what init says.
const ENGINE_BYTES: u64 = 500_000_000;
/// How often a download says how far it is.
const SAY_EVERY: Duration = Duration::from_secs(5);
/// How many times a download is taken up again after it breaks off.
const TRIES: usize = 5;

/// Where everything is kept.
pub fn root() -> Result<PathBuf> {
    tangent_shared::cache::models()
}

/// MTPLX's own directory under `root`, and the program in it.
fn engine(root: &Path) -> PathBuf {
    root.join(format!("mtplx-{MTPLX}"))
}

/// The model's directory under `root`, named for its revision.
fn model(root: &Path) -> PathBuf {
    root.join(MODEL).join(&REVISION[..12])
}

/// The two paths the config names, under the cache as the config writes it
/// (`${HOME}/.cache`, say): the program that serves, and the model's
/// directory.
pub fn paths(cache: &str) -> (String, String) {
    let root = format!("{cache}/tangent/models");
    (
        format!("{root}/mtplx-{MTPLX}/bin/mtplx"),
        format!("{root}/{MODEL}/{}", &REVISION[..12]),
    )
}

/// Written last into MTPLX's directory, so one that is there is whole.
fn installed(root: &Path) -> PathBuf {
    engine(root).join(".tangent-installed")
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
        self.model + if self.engine { ENGINE_BYTES } else { 0 }
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

/// What of MTPLX and the model is not under `root` yet. A file of the
/// model counts once it is there at its full size: it is given its name
/// only after its digest is checked.
pub fn missing(root: &Path) -> Missing {
    let dir = model(root);
    let model = FILES
        .iter()
        .map(|(name, size, _)| {
            let there = std::fs::metadata(dir.join(name)).map_or(0, |m| m.len());
            let part = std::fs::metadata(partial(&dir.join(name))).map_or(0, |m| m.len());
            if there == *size {
                0
            } else {
                size.saturating_sub(part)
            }
        })
        .sum();
    Missing {
        engine: !installed(root).is_file(),
        model,
    }
}

/// Fetches what is missing under `root`: uv and MTPLX, then the model.
pub async fn fetch(root: &Path) -> Result<()> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        bail!(
            "MTPLX runs on Apple Silicon Macs only, so there is nothing to fetch for this machine"
        );
    }
    std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let missing = missing(root);
    if missing.nothing() {
        println!(
            "MTPLX {MTPLX} and Inkling 2 Mini are already in {}.",
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
    let dir = model(root);
    for file in FILES {
        let to = dir.join(file.0);
        if std::fs::metadata(&to).is_ok_and(|m| m.len() == file.1) {
            continue;
        }
        let url = format!(
            "https://huggingface.co/{REPO}/resolve/{REVISION}/{}",
            file.0
        );
        download(&http, &url, &to, *file).await?;
    }
    println!(
        "MTPLX {MTPLX} and Inkling 2 Mini are in {}.",
        root.display()
    );
    Ok(())
}

/// uv, then a Python and MTPLX in a directory of their own.
async fn install(root: &Path, http: &reqwest::Client) -> Result<()> {
    let uv = root.join(format!("uv-{UV}")).join("uv");
    if !uv.is_file() {
        let archive = root.join(UV_ARCHIVE.0);
        let url = format!(
            "https://github.com/astral-sh/uv/releases/download/{UV}/{}",
            UV_ARCHIVE.0
        );
        download(http, &url, &archive, UV_ARCHIVE).await?;
        let dir = uv.parent().expect("uv is in a directory");
        std::fs::create_dir_all(dir)?;
        // The archive holds one directory, with uv and uvx in it.
        run(
            tokio::process::Command::new("tar")
                .arg("-xzf")
                .arg(&archive)
                .args(["--strip-components", "1", "-C"])
                .arg(dir),
            "unpacking uv",
        )
        .await?;
        std::fs::remove_file(&archive).ok();
        if !uv.is_file() {
            bail!("uv's archive did not hold uv");
        }
    }

    // What uv keeps is kept here too, and what the user has set up for
    // their own uv is not read.
    let with = |command: &mut tokio::process::Command| {
        command
            .env("UV_CACHE_DIR", root.join("uv-cache"))
            .env("UV_PYTHON_INSTALL_DIR", root.join("python"))
            .env("UV_PYTHON_PREFERENCE", "only-managed")
            .env("UV_NO_CONFIG", "1")
            .env_remove("VIRTUAL_ENV");
    };
    // A directory left by an install that did not finish is made again: its
    // programs name their own path, so it is made where it stays.
    let venv = engine(root);
    if venv.exists() {
        std::fs::remove_dir_all(&venv).with_context(|| format!("removing {}", venv.display()))?;
    }
    println!(
        "Installing Python {PYTHON} and MTPLX {MTPLX} into {}",
        venv.display()
    );
    let mut make = tokio::process::Command::new(&uv);
    make.args(["venv", "--quiet", "--python", PYTHON])
        .arg(&venv);
    with(&mut make);
    run(&mut make, "making MTPLX's Python").await?;

    let lock = root.join(format!("mtplx-{MTPLX}.lock"));
    std::fs::write(&lock, LOCK).with_context(|| format!("writing {}", lock.display()))?;
    let mut add = tokio::process::Command::new(&uv);
    add.args([
        "pip",
        "install",
        "--require-hashes",
        "--only-binary",
        ":all:",
        "--python",
    ])
    .arg(venv.join("bin").join("python"))
    .arg("-r")
    .arg(&lock);
    with(&mut add);
    run(&mut add, "installing MTPLX").await?;
    // What uv downloaded is installed, and its own copy is not kept.
    std::fs::remove_dir_all(root.join("uv-cache")).ok();
    std::fs::write(installed(root), format!("mtplx {MTPLX}, uv {UV}\n"))?;
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

    /// The model's list is whole: each file once, each digest a SHA-256,
    /// and together the size Hugging Face gives the revision without its
    /// .gitattributes.
    #[test]
    fn the_models_files_are_listed_once_with_their_digests() {
        let mut names: Vec<&str> = FILES.iter().map(|f| f.0).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), FILES.len());
        for (name, size, sha256) in FILES {
            assert!(*size > 0, "{name}");
            assert_eq!(sha256.len(), 64, "{name}");
            assert!(sha256.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
        }
        assert_eq!(FILES.iter().map(|f| f.1).sum::<u64>(), 17_242_614_770);
    }

    /// The lock pins MTPLX itself, at the version named here, and every
    /// line that names a package gives it a hash.
    #[test]
    fn the_lock_is_for_this_mtplx_and_hashes_every_package() {
        assert!(
            LOCK.contains(&format!("\nmtplx[server]=={MTPLX} \\\n"))
                || LOCK.contains(&format!("\nmtplx=={MTPLX} \\\n"))
        );
        let packages = LOCK
            .lines()
            .filter(|l| !l.starts_with(' ') && l.contains("=="))
            .count();
        let hashed = LOCK
            .split("\n")
            .collect::<Vec<_>>()
            .windows(2)
            .filter(|w| {
                !w[0].starts_with(' ')
                    && w[0].contains("==")
                    && w[1].trim_start().starts_with("--hash=sha256:")
            })
            .count();
        assert!(packages > 30, "{packages}");
        assert_eq!(packages, hashed);
    }

    /// The config's two paths are where the fetch puts MTPLX and the model.
    #[test]
    fn the_config_names_what_the_fetch_writes() {
        let root = Path::new("/c/tangent/models");
        let (program, dir) = paths("/c");
        assert_eq!(Path::new(&program), engine(root).join("bin").join("mtplx"));
        assert_eq!(Path::new(&dir), model(root));
    }

    /// Nothing fetched is everything missing; a file of the model at its
    /// full size is not, and a part of one counts for what it holds.
    #[test]
    fn what_is_missing_is_what_is_not_there_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let all: u64 = FILES.iter().map(|f| f.1).sum();
        let none = missing(tmp.path());
        assert!(none.engine);
        assert_eq!(none.model, all);
        assert!(!none.nothing());

        let dir = model(tmp.path());
        std::fs::create_dir_all(&dir).unwrap();
        let (name, size, _) = FILES.iter().min_by_key(|f| f.1).unwrap();
        std::fs::write(dir.join(name), vec![0u8; *size as usize]).unwrap();
        assert_eq!(missing(tmp.path()).model, all - size);
        let (other, _, _) = FILES.iter().find(|f| f.0 != *name).unwrap();
        std::fs::write(partial(&dir.join(other)), [0u8; 10]).unwrap();
        assert_eq!(missing(tmp.path()).model, all - size - 10);

        std::fs::create_dir_all(engine(tmp.path())).unwrap();
        assert!(missing(tmp.path()).engine, "a directory is not an install");
        std::fs::write(installed(tmp.path()), "").unwrap();
        assert!(!missing(tmp.path()).engine);
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
