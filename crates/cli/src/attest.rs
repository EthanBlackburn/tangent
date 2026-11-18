//! A fetched component's attestation, checked here, with no other program
//! and no network.
//!
//! GitHub attests a build with a Sigstore bundle, the asset beside the
//! component on its release: a statement naming each file the build made by
//! its digest, signed with a certificate Sigstore issued to the workflow run
//! for ten minutes, and the public log's entry for that signature. Checking
//! one is two parts.
//!
//! The cryptography is `sigstore-verify`'s, against the Sigstore root it
//! carries: the certificate chains to Sigstore's authority and was logged,
//! the signature was logged while the certificate was valid, and it is the
//! certificate's key's signature over this statement.
//!
//! What the certificate and the statement must then say is tangent's own
//! check, below: who signed (GitHub Actions, a workflow of `repo`, the one
//! named when `prebuilt` names one), what it built (`repo`, at the
//! release's tag), and that the statement names the file by this digest as
//! the asset asked for. A digest alone is not enough there: a statement may
//! cover several files, and one attested component of a release passed off
//! as another (the asset swapped on the release) would be kept under the
//! other's name and run with its config.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use sigstore_verify::trust_root::{TrustedRoot, SIGSTORE_PRODUCTION_TRUSTED_ROOT};
use sigstore_verify::types::{Bundle, Sha256Hash, SignatureContent};
use sigstore_verify::{VerificationPolicy, Verifier};
use tangent_shared::plugins::Prebuilt;

/// Who GitHub Actions' certificates are issued by.
const ISSUER: &str = "https://token.actions.githubusercontent.com";

/// What a build's provenance statement is.
const PROVENANCE: &str = "https://slsa.dev/provenance/v1";

/// The host whose attestations are signed with the public Sigstore.
const GITHUB: &str = "github.com";

/// Who built a component, as its attestation's certificate says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    /// The workflow that signed it, `owner/repo/.github/workflows/x.yml@ref`.
    pub signer: String,
    /// The commit it was built from.
    pub commit: String,
    /// The git ref it was built from, `refs/tags/v0.1.10`.
    pub source_ref: String,
}

/// The file with `sha256` (hex) is the `asset` that `p.repo`'s workflow
/// built for `release`, by the attestation in `bundle` (a Sigstore bundle's
/// JSON).
pub fn verify(
    sha256: &str,
    asset: &str,
    bundle: &str,
    p: &Prebuilt,
    release: &str,
) -> Result<Attested> {
    if !p.host().eq_ignore_ascii_case(GITHUB) {
        bail!(
            "{} signs its attestations with a Sigstore of its own, whose root tangent does not \
             carry: only {GITHUB}'s are checked",
            p.host()
        );
    }
    let root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
        .context("reading the Sigstore root tangent carries")?;
    let verifier = Verifier::new(&root).context("reading the Sigstore root tangent carries")?;
    let bundle = Bundle::from_json(bundle).context("reading the attestation bundle")?;
    let digest = Sha256Hash::from_hex(sha256).context("the component's sha256")?;

    // The signer is checked below, where the repo's name may differ in case.
    let policy = VerificationPolicy::any_identity().require_issuer(ISSUER);
    let checked = verifier.verify(digest, &bundle, &policy).map_err(|e| {
        anyhow!("{e}").context("the attestation does not verify against Sigstore's root")
    })?;
    if !(checked.certificate_verified() && checked.sct_verified() && checked.tlog_verified()) {
        bail!("the attestation's certificate or its log entry was not checked");
    }

    let cert = checked
        .certificate()
        .ok_or_else(|| anyhow!("the attestation has no certificate"))?;
    let claim = |value: &Option<String>, what: &str| -> Result<String> {
        value
            .clone()
            .ok_or_else(|| anyhow!("the attestation's certificate has no {what}"))
    };
    let san = cert
        .identity
        .as_ref()
        .ok_or_else(|| anyhow!("the attestation's certificate names no signer"))?
        .as_str();
    let signer = signed_by(san, p, release)?;
    let source = claim(&cert.ci_claims.source_repository_uri, "source repository")?;
    if !source.eq_ignore_ascii_case(&format!("https://{GITHUB}/{}", p.repo)) {
        bail!("it was built from {source}, not from {}", p.repo);
    }
    let source_ref = claim(&cert.ci_claims.source_repository_ref, "source ref")?;
    if source_ref != format!("refs/tags/{release}") {
        bail!("it was built from {source_ref}, not from the release's tag, refs/tags/{release}");
    }
    let commit = claim(&cert.ci_claims.source_repository_digest, "source commit")?;

    named_as(&bundle, sha256, asset)?;
    Ok(Attested {
        signer,
        commit,
        source_ref,
    })
}

/// The signer a certificate names, `https://github.com/owner/repo/<workflow>@<ref>`,
/// as `owner/repo/<workflow>@<ref>`, when it is a workflow of `p.repo` at
/// the release's tag, and `p.workflow` when that is named.
fn signed_by(san: &str, p: &Prebuilt, release: &str) -> Result<String> {
    let not_ours = || anyhow!("it was signed by {san}, not by a workflow of {}", p.repo);
    let signer = san
        .strip_prefix(&format!("https://{GITHUB}/"))
        .ok_or_else(not_ours)?;
    let (path, at) = signer.rsplit_once('@').ok_or_else(not_ours)?;
    let workflow = path
        .get(..p.repo.len())
        .filter(|repo| repo.eq_ignore_ascii_case(&p.repo))
        .and_then(|_| path[p.repo.len()..].strip_prefix('/'))
        .ok_or_else(not_ours)?;
    match &p.workflow {
        Some(named) if workflow != named.trim_start_matches('/') => bail!(
            "it was signed by workflow {workflow}, not by {}",
            named.trim_start_matches('/')
        ),
        None if !workflow.starts_with(".github/workflows/") => return Err(not_ours()),
        _ => {}
    }
    if at != format!("refs/tags/{release}") {
        bail!("it was signed at {at}, not at the release's tag, refs/tags/{release}");
    }
    Ok(signer.to_string())
}

/// The bundle's statement is a build's provenance and names the file with
/// `sha256` as `asset`.
fn named_as(bundle: &Bundle, sha256: &str, asset: &str) -> Result<()> {
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        bail!("the attestation is a bare signature, not a statement about a build");
    };
    let statement: Value = serde_json::from_slice(envelope.payload.as_bytes())
        .context("reading the attestation's statement")?;
    let kind = statement.get("predicateType").and_then(Value::as_str);
    if kind != Some(PROVENANCE) {
        bail!(
            "the attestation is {}, not a build's provenance",
            kind.unwrap_or("of no kind")
        );
    }
    let subjects = statement
        .get("subject")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("the attestation's statement has no subjects"))?;
    let mut named = Vec::new();
    for s in subjects {
        let sha = s.pointer("/digest/sha256").and_then(Value::as_str);
        if sha.is_some_and(|sha| sha.eq_ignore_ascii_case(sha256)) {
            let name = s.get("name").and_then(Value::as_str).unwrap_or("");
            if name == asset {
                return Ok(());
            }
            named.push(name.to_string());
        }
    }
    if named.is_empty() {
        bail!("the attestation names no file with sha256 {sha256}");
    }
    bail!(
        "the file with sha256 {sha256} is attested as {}, not as {asset}: another file of the \
         release under this asset's name",
        named.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tangent 0.2.0's cloudtrail plugin, as its release has it: the
    /// bundle, and the component's digest.
    const BUNDLE: &str = include_str!("../testdata/cloudtrail.component.wasm.sigstore.json");
    const SHA256: &str = "e0f3a3c03b9400b8c0c9482caee0a52191a771ff08cbd9eb4d672d203d7b6ddd";
    const ASSET: &str = "cloudtrail.component.wasm";
    const RELEASE: &str = "v0.2.0";

    fn prebuilt(yaml: &str) -> Prebuilt {
        serde_yaml::from_str(yaml).unwrap()
    }

    fn ours() -> Prebuilt {
        prebuilt("{ repo: EthanBlackburn/tangent, workflow: .github/workflows/attest-packs.yml }")
    }

    fn refused(sha256: &str, asset: &str, bundle: &str, p: &Prebuilt, release: &str) -> String {
        format!(
            "{:#}",
            verify(sha256, asset, bundle, p, release).expect_err("verified")
        )
    }

    /// A release's own component verifies, with nothing but its digest and
    /// the bundle, and says who built it; a repo written in another case is
    /// the same repo, and with no workflow named any of the repo's will do.
    #[test]
    fn a_releases_component_verifies_and_says_who_built_it() {
        let attested = verify(SHA256, ASSET, BUNDLE, &ours(), RELEASE).unwrap();
        assert_eq!(
            attested.signer,
            "EthanBlackburn/tangent/.github/workflows/attest-packs.yml@refs/tags/v0.2.0"
        );
        assert_eq!(attested.source_ref, "refs/tags/v0.2.0");
        assert_eq!(attested.commit.len(), 40, "{}", attested.commit);

        for p in [
            "{ repo: ethanblackburn/Tangent, workflow: /.github/workflows/attest-packs.yml }",
            "repo: EthanBlackburn/tangent",
        ] {
            assert_eq!(
                verify(SHA256, ASSET, BUNDLE, &prebuilt(p), RELEASE).unwrap(),
                attested,
                "{p}"
            );
        }
    }

    /// Another file, another release, another workflow or another repo is
    /// refused, each for what it is.
    #[test]
    fn what_was_not_built_as_asked_is_refused() {
        let other = "0000000000000000000000000000000000000000000000000000000000000000";
        let e = refused(other, ASSET, BUNDLE, &ours(), RELEASE);
        assert!(e.contains("does not match any subject"), "{e}");

        let e = refused(SHA256, ASSET, BUNDLE, &ours(), "v0.1.9");
        assert!(
            e.contains("not at the release's tag, refs/tags/v0.1.9"),
            "{e}"
        );

        let p =
            prebuilt("{ repo: EthanBlackburn/tangent, workflow: .github/workflows/release.yml }");
        let e = refused(SHA256, ASSET, BUNDLE, &p, RELEASE);
        assert!(
            e.contains("signed by workflow .github/workflows/attest-packs.yml, not by .github/workflows/release.yml"),
            "{e}"
        );

        for repo in [
            "someone/else",
            "EthanBlackburn/tangent-eval",
            "EthanBlackburn/tan",
        ] {
            let e = refused(
                SHA256,
                ASSET,
                BUNDLE,
                &prebuilt(&format!("repo: {repo}")),
                RELEASE,
            );
            assert!(e.contains(&format!("not by a workflow of {repo}")), "{e}");
        }
    }

    /// The file is attested, but as another asset: the digest alone does not
    /// make it the one asked for.
    #[test]
    fn the_file_must_be_attested_under_the_assets_name() {
        let e = refused(SHA256, "okta.component.wasm", BUNDLE, &ours(), RELEASE);
        assert!(
            e.contains("is attested as cloudtrail.component.wasm, not as okta.component.wasm"),
            "{e}"
        );
    }

    /// A statement changed after it was signed no longer carries the
    /// signature, whatever it now says.
    #[test]
    fn a_statement_edited_after_signing_is_refused() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut bundle: Value = serde_json::from_str(BUNDLE).unwrap();
        let payload = bundle["dsseEnvelope"]["payload"].as_str().unwrap();
        let statement = String::from_utf8(b64.decode(payload).unwrap()).unwrap();
        assert!(statement.contains(ASSET));
        let renamed = statement.replace(ASSET, "okta.component.wasm");
        bundle["dsseEnvelope"]["payload"] = b64.encode(renamed).into();

        let e = refused(
            SHA256,
            "okta.component.wasm",
            &bundle.to_string(),
            &ours(),
            RELEASE,
        );
        assert!(e.contains("does not verify against Sigstore's root"), "{e}");
        assert!(e.contains("signature"), "{e}");
    }

    /// What is no bundle, or another host's, is refused before anything is
    /// trusted.
    #[test]
    fn what_cannot_be_checked_is_refused() {
        let e = refused(SHA256, ASSET, "{}", &ours(), RELEASE);
        assert!(e.contains("reading the attestation bundle"), "{e}");

        let p = prebuilt("{ repo: acme/packs, host: github.acme.example }");
        let e = refused(SHA256, ASSET, BUNDLE, &p, RELEASE);
        assert!(
            e.contains("github.acme.example signs its attestations with a Sigstore of its own"),
            "{e}"
        );
    }
}
