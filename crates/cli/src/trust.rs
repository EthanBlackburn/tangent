//! The certificates a watch trusts, read once at its start.
//!
//! The models' clients read macOS's trusted certificates the first time
//! they connect, once for the process, and keep what they got. macOS now and
//! then fails a process launchd has just started with an I/O error for its
//! own roots (the System domain), and the client is then left with the few
//! the user added: every server's issuer is unknown to it, its provider's
//! sign-in included, for as long as it runs.
//!
//! So the watch reads them itself before anything connects, again until
//! macOS gives all three domains, and writes them to a file beside its
//! pipeline. `SSL_CERT_FILE` names the file, which is where the clients then
//! read them from. A Mac that will not give its roots at all is given
//! `/etc/ssl/cert.pem`, the roots macOS ships as a file, with whatever of
//! the user's it did give.

use std::path::Path;
use std::time::Duration;

use base64::Engine as _;

const FILE: &str = "roots.pem";
/// macOS's roots as a file: fewer than its keychain's, and none of the
/// user's.
const SHIPPED: &str = "/etc/ssl/cert.pem";
const TRIES: u32 = 10;

/// Reads the certificates and names them to the clients. A caller that set
/// `SSL_CERT_FILE` or `SSL_CERT_DIR` has said where they are.
pub fn settle(dir: &Path) {
    if !cfg!(target_os = "macos") {
        return;
    }
    if ["SSL_CERT_FILE", "SSL_CERT_DIR"]
        .iter()
        .any(|var| std::env::var_os(var).is_some_and(|v| !v.is_empty()))
    {
        return;
    }
    let mut read = rustls_native_certs::load_native_certs();
    for attempt in 1..TRIES {
        if whole(&read) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200 * u64::from(attempt)));
        read = rustls_native_certs::load_native_certs();
    }
    let mut pem = String::new();
    for cert in &read.certs {
        pem.push_str(&one(cert.as_ref()));
    }
    if !whole(&read) {
        eprintln!(
            "macOS did not give its trusted certificates ({:?}): {SHIPPED} is trusted with the {} it gave",
            read.errors,
            read.certs.len()
        );
        pem.push_str(&std::fs::read_to_string(SHIPPED).unwrap_or_default());
    }
    if pem.is_empty() {
        return;
    }
    let path = dir.join(FILE);
    match std::fs::write(&path, pem) {
        Ok(()) => std::env::set_var("SSL_CERT_FILE", &path),
        Err(e) => eprintln!("{} could not be written: {e}", path.display()),
    }
}

/// Whether every domain was read. One certificate macOS would not say the
/// trust of is left out, and is no reason to read again.
fn whole(read: &rustls_native_certs::CertificateResult) -> bool {
    !read.certs.is_empty() && !read.errors.iter().any(|e| e.context.starts_with("failed to load"))
}

/// A certificate as PEM.
fn one(der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_is_written_as_pem_reads_it() {
        let der: Vec<u8> = (0..200u8).collect();
        let pem = one(&der);
        let mut lines = pem.lines();
        assert_eq!(lines.next(), Some("-----BEGIN CERTIFICATE-----"));
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert!(pem.lines().all(|l| l.len() <= 64));
        assert_eq!(
            base64::engine::general_purpose::STANDARD.decode(body).unwrap(),
            der
        );
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn what_is_written_is_what_the_clients_read() {
        let dir = tempfile::tempdir().unwrap();
        let had = std::env::var_os("SSL_CERT_FILE");
        std::env::remove_var("SSL_CERT_FILE");
        settle(dir.path());
        let named = std::env::var_os("SSL_CERT_FILE").expect("it is named");
        assert_eq!(Path::new(&named), dir.path().join(FILE));
        // as the clients read it: from the file, and all of it
        let read = rustls_native_certs::load_native_certs();
        assert!(read.errors.is_empty(), "{:?}", read.errors);
        assert!(read.certs.len() > 50, "{} certificates", read.certs.len());
        match had {
            Some(v) => std::env::set_var("SSL_CERT_FILE", v),
            None => std::env::remove_var("SSL_CERT_FILE"),
        }
    }
}
