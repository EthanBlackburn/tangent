//! `eslogger`'s events, from a Mac, into the few records a model should read:
//! every program run, with its environment cut to the names that steer an AI
//! agent; every write, and the reads that matter, on the files an agent is
//! steered, extended and read through, on credentials and on what runs at
//! login (`paths.rs`); nothing else. Each record carries the program that
//! acted (for an exec, the one that started), the chain of programs above it
//! (from a process tree kept in state from `fork`, `exec` and `exit`), and
//! `_norm`/`_facts` as every pack's do; its actor is the job it belongs to
//! (its process group's leader), so there is no principal for a profile to
//! know. An event that is only noise here is dropped before any record is
//! built.

wit_bindgen::generate!({
    path: ".tangent/wit",
    world: "processor",
    generate_all,
});

mod paths;

use exports::tangent::logs::mapper::{Guest, Meta, Pred, Selector};
use normkit::{Norm, Stamp};
use paths::{group, home, scratch, Group};
use serde_json::{json, Map, Value};
use tangent::logs::enrichment::lookup;
use tangent::logs::log::{Logview, Scalar};
use tangent::logs::state;

struct Component;

export!(Component);

/// The environment names a record keeps. They steer a program: where an
/// agent sends its API traffic and keeps its config; the code an interpreter
/// or the loader puts in every process (`NODE_OPTIONS=--require`,
/// `DYLD_INSERT_LIBRARIES`); the proxy and certificates traffic goes
/// through; and npm's names for the package script that is running, which
/// say a postinstall from a dependency. Every other variable is dropped,
/// with its value: a program's environment is where its keys are.
const ENV_KEEP: &[&str] = &[
    "ANTHROPIC_BASE_URL",
    "OPENAI_BASE_URL",
    "GOOGLE_GEMINI_BASE_URL",
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "GEMINI_CLI_HOME",
    "NODE_OPTIONS",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "RUBYOPT",
    "BASH_ENV",
    "GIT_SSH_COMMAND",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "npm_lifecycle_event",
    "npm_lifecycle_script",
    "npm_package_name",
    "npm_package_version",
];

/// A proxy URL without the user and password it may carry
/// (`http://user:pass@proxy:8080`).
fn without_userinfo(v: &str) -> String {
    let Some((scheme, rest)) = v.split_once("://") else {
        return v.to_string();
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}://…@{host}{}", &rest[authority.len()..]),
        None => v.to_string(),
    }
}

/// The `OTEL_*` names that say where telemetry goes and what it carries
/// (`OTEL_EXPORTER_OTLP_ENDPOINT`, `..._METRICS_ENDPOINT`, `..._HEADERS`,
/// whose values are dropped: see [`header_names`]).
/// The rest say nothing: Claude Code sets
/// `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE` on every child.
fn otel_matters(name: &str) -> bool {
    name.starts_with("OTEL_EXPORTER_OTLP_")
        && (name.ends_with("_ENDPOINT") || name.ends_with("_HEADERS"))
}

/// Programs above the actor named in a record, nearest first: the whole
/// chain, to this bound (a terminal tab's agent running a package's script is
/// nine deep).
const PARENTS: usize = 16;

/// Where a chain of parents ends: at launchd, which starts every app and
/// service; at a process the tree does not know (older than the log and in no
/// snapshot, or long gone); or at [`PARENTS`], with more above.
const LAUNCHD: &str = "/sbin/launchd";
const UNSEEN: &str = "(unknown)";
const MORE: &str = "…";

/// `open`'s `fflag`: the kernel's FREAD and FWRITE bits.
const FWRITE: i64 = 2;

/// A command line is kept to this many bytes, each argument to
/// [`ARG_BYTES`], and what is past them counted: an agent's long shell
/// commands are what most needs reading.
const ARGS_BYTES: usize = 1500;
const ARG_BYTES: usize = 400;

fn cut(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// The arguments in order, each cut to [`ARG_BYTES`], until [`ARGS_BYTES`];
/// then how many more there were.
fn cut_args(args: &Value) -> Value {
    let Some(a) = args.as_array() else {
        return normkit::shrink(args, ARGS_BYTES);
    };
    let mut out = Vec::new();
    let mut bytes = 0;
    for (i, x) in a.iter().enumerate() {
        let s = x
            .as_str()
            .map_or_else(|| x.to_string(), |s| cut(s, ARG_BYTES));
        if bytes + s.len() > ARGS_BYTES && !out.is_empty() {
            out.push(json!(format!("… {} more arguments", a.len() - i)));
            break;
        }
        bytes += s.len();
        out.push(json!(s));
    }
    Value::Array(out)
}

fn str_at<'a>(v: &'a Value, ptr: &str) -> Option<&'a str> {
    v.pointer(ptr).and_then(Value::as_str)
}

fn int_at(v: &Value, ptr: &str) -> Option<i64> {
    v.pointer(ptr).and_then(Value::as_i64)
}

fn put(m: &mut Map<String, Value>, key: &str, v: Option<impl Into<Value>>) {
    if let Some(v) = v {
        m.insert(key.to_string(), v.into());
    }
}

/// A process block (`process`, `event.exec.target`, `event.fork.child`), as
/// much of it as a verdict reads.
#[derive(Clone)]
struct Proc {
    pid: i64,
    ppid: i64,
    path: String,
    /// its signing identity
    signer: Option<String>,
    platform: bool,
    /// its Developer ID team: Apple issues it to the vendor, so an ad hoc
    /// signature cannot claim one
    team: Option<String>,
    /// for an interpreter or a shell running a file, the script it runs
    name: Option<String>,
    /// the arguments it was given after its program, or after its script
    /// when it has a name: what its children's `parents` say it was doing
    command: Option<String>,
    uid: Option<i64>,
    tty: Option<String>,
    /// the process macOS holds responsible (the app a terminal is), when another
    responsible: Option<i64>,
    /// its process group: what a shell makes of a command line, and an app
    /// of itself
    group: Option<i64>,
}

fn proc_of(v: &Value) -> Option<Proc> {
    let pid = int_at(v, "/audit_token/pid")?;
    let signer = str_at(v, "/signing_id")
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Some(Proc {
        pid,
        ppid: int_at(v, "/ppid").unwrap_or(0),
        path: str_at(v, "/executable/path").unwrap_or("").to_string(),
        signer,
        platform: v["is_platform_binary"].as_bool().unwrap_or(false),
        team: str_at(v, "/team_id")
            .filter(|t| !t.is_empty())
            .map(str::to_string),
        name: None,
        command: None,
        uid: int_at(v, "/audit_token/euid"),
        tty: str_at(v, "/tty/path").map(str::to_string),
        responsible: int_at(v, "/responsible_audit_token/pid").filter(|r| *r != pid),
        group: int_at(v, "/group_id"),
    })
}

impl Proc {
    /// Who the program is: for an
    /// interpreter, the script it runs, so npm, a package's postinstall and
    /// an MCP server are not one `node`; else a vendor's signing identity,
    /// which an update keeps (Claude Code's path names its version); else
    /// its path. Apple's command-line tools share one signing identity
    /// (/usr/bin/git and python3 are both the Xcode shim), and an ad hoc
    /// signature is the binary's hash, so those are their path.
    fn ident(&self) -> String {
        if let Some(n) = &self.name {
            return n.clone();
        }
        match &self.signer {
            Some(s) if self.team.is_some() && !self.platform => s.clone(),
            _ => self.path.clone(),
        }
    }

    fn json(&self) -> Value {
        let mut m = Map::new();
        m.insert("pid".into(), json!(self.pid));
        m.insert("ppid".into(), json!(self.ppid));
        m.insert("path".into(), json!(self.path));
        put(&mut m, "name", self.name.clone());
        put(&mut m, "signer", self.signer.clone());
        put(&mut m, "team", self.team.clone());
        m.insert("platform".into(), json!(self.platform));
        put(&mut m, "uid", self.uid);
        put(&mut m, "tty", self.tty.clone());
        put(&mut m, "responsible", self.responsible);
        Value::Object(m)
    }
}

// The process tree, in state: `p:<pid>` holds
// "<ppid>\t<program>\t<name>\t<command>\t<ident>\t<entry pid>\t<entry ident>\t<signer>\t<team>\t<platform>".
// fork adds the child with its parent's program, name and command and its
// session's entry point, exec replaces the program and keeps the rest, exit
// leaves the entry for [`EXITED_TTL_MS`]; a process seen before any of those
// is added as the event shows it. The tree answers which programs are above
// this one and what each was doing, the name of a process whose exec it saw,
// who a process group's leader is, and which session a process is in.

struct Known {
    ppid: i64,
    path: String,
    name: Option<String>,
    command: Option<String>,
    /// who it is, as [`Proc::ident`] says
    ident: String,
    /// its session's entry point, pid and who, when its fork was seen
    entry: Option<(i64, String)>,
    /// whether an event showed it; else it is known from a snapshot of what
    /// was running (`ps`), by path alone
    seen: bool,
    /// its code identity, as its last event gave it: what a connection, which
    /// tcpdump reports by pid alone, is matched to a program's profile by
    signer: Option<String>,
    team: Option<String>,
    platform: bool,
}

impl Known {
    /// Who it is: its name, else its path.
    fn who(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.path)
    }
}

fn known(pid: i64) -> Option<Known> {
    match state::get(&format!("p:{pid}")) {
        Ok(Some(Scalar::Str(s))) => {
            let mut f = s.splitn(10, '\t');
            let ppid = f.next()?.parse().ok()?;
            let path = f.next()?.to_string();
            let mut field = || f.next().filter(|n| !n.is_empty()).map(str::to_string);
            let name = field();
            let command = field();
            let ident = field();
            let seen = ident.is_some();
            let ident = ident
                .or_else(|| name.clone())
                .unwrap_or_else(|| path.clone());
            let entry = match (field().and_then(|e| e.parse().ok()), field()) {
                (Some(pid), who) => Some((pid, who.unwrap_or_default())),
                _ => None,
            };
            let signer = field();
            let team = field();
            let platform = field().is_some();
            Some(Known {
                ppid,
                path,
                name,
                command,
                ident,
                entry,
                seen,
                signer,
                team,
                platform,
            })
        }
        _ => None,
    }
}

/// A process the tree never saw exit is forgotten after a day. Core's state
/// keeps keys until told otherwise, and pids come back.
const PROC_TTL_MS: u64 = 86_400_000;

/// An exited process stays this long, so that what it left running (a
/// daemon forked twice, `nohup … &`) still has it in its `parents`. A fork
/// that takes its pid again replaces it.
const EXITED_TTL_MS: u64 = 600_000;

fn store(p: &Proc, entry: Option<&(i64, String)>, ttl: u64) {
    let (epid, ewho) = match entry {
        Some((pid, who)) => (pid.to_string(), who.as_str()),
        None => (String::new(), ""),
    };
    let _ = state::set(
        &format!("p:{}", p.pid),
        &Scalar::Str(format!(
            "{}\t{}\t{}\t{}\t{}\t{epid}\t{ewho}\t{}\t{}\t{}",
            p.ppid,
            p.path,
            p.name.as_deref().unwrap_or(""),
            p.command.as_deref().unwrap_or(""),
            p.ident(),
            p.signer.as_deref().unwrap_or(""),
            p.team.as_deref().unwrap_or(""),
            if p.platform { "1" } else { "" }
        )),
        Some(ttl),
    );
}

fn remember(p: &Proc, entry: Option<&(i64, String)>) {
    store(p, entry, PROC_TTL_MS);
}

/// A line of ps/ps.py: a process that was running when the capture
/// began, which no fork or exec will ever show. The tree takes its parent
/// and path, so the programs started before the log (the terminal, the
/// apps, an agent left open) are named in `parents` and as `responsible`;
/// a process the tree already knows keeps what its events said.
fn snapshot(rec: &Map<String, Value>) {
    let Some(p) = rec.get("ps") else { return };
    let (Some(pid), Some(path)) = (int_at(p, "/pid"), str_at(p, "/path")) else {
        return;
    };
    if pid < 1 || known(pid).is_some() {
        return;
    }
    let ppid = int_at(p, "/ppid").unwrap_or(0);
    // no ident: [`Known::seen`] is false until an event shows the process
    let _ = state::set(
        &format!("p:{pid}"),
        &Scalar::Str(format!("{ppid}\t{path}\t\t\t\t\t")),
        Some(PROC_TTL_MS),
    );
}

/// Whose work a record is, for the judge's groups and the baseline: the job
/// it belongs to, as Elastic's group leader and Apple's responsible process
/// say. A process group is what a shell makes of a command line (`claude`,
/// `npm install`) and an app makes of itself, so its leader names the job,
/// and what the job runs (the agent's git and `security`, a postinstall under
/// npm) is read with it. A process in launchd's group (a service, an XPC
/// helper) works for the process macOS holds responsible, as does one whose
/// leader the tree never saw; failing that, a process is its own job.
fn job(p: &Proc) -> String {
    match p.group {
        Some(g) if g == p.pid => return p.ident(),
        Some(g) if g > 1 => {
            if let Some(k) = known(g) {
                return k.ident;
            }
        }
        _ => {}
    }
    p.responsible
        .and_then(known)
        .map(|k| k.ident)
        .unwrap_or_else(|| p.ident())
}

/// The programs whose children start a session of their own: a terminal
/// tab's login and a remote shell.
const ENTRY_PARENTS: &[&str] = &["/usr/bin/login", "/usr/sbin/sshd"];

/// The entry point of a process's session, as ECS's entry leader: the one its
/// fork inherited, which a process keeps when what started it exits; else,
/// walking up the tree, the first process whose parent is launchd (a service
/// or an app) or a login or sshd (a terminal tab, a remote shell), else the
/// oldest the tree knows. Its pid and who it is: everything a terminal tab,
/// an agent started before the log, or an app went on to run is one session.
fn entry(pid: i64) -> (i64, String) {
    if let Some((e, who)) = known(pid).and_then(|k| k.entry) {
        // the entry point's name as it is now, if it exec'd since
        let who = known(e).map(|k| k.ident).unwrap_or(who);
        return (e, who);
    }
    let mut cur = pid;
    for _ in 0..40 {
        let Some(k) = known(cur) else { break };
        if k.ppid <= 1 {
            break;
        }
        match known(k.ppid) {
            Some(p) if !ENTRY_PARENTS.contains(&p.path.as_str()) => cur = k.ppid,
            _ => break,
        }
    }
    (cur, known(cur).map(|k| k.ident).unwrap_or_default())
}

/// The five minutes an event's time falls in, as its start
/// (`2026-11-03T21:25`): a session's records are summarized a window at a
/// time by when they happened, so a replay groups as a live run does.
fn window(time: &str) -> Option<String> {
    let minute: u32 = time.get(14..16)?.parse().ok()?;
    Some(format!("{}{:02}", time.get(..14)?, minute - minute % 5))
}

/// The session a child forked from `parent` is in: its own, when `parent` is
/// launchd, a login or sshd; else the parent's.
fn inherited(parent: &Proc, child: &Proc) -> (i64, String) {
    if parent.pid <= 1 || ENTRY_PARENTS.contains(&parent.path.as_str()) {
        (child.pid, child.ident())
    } else {
        entry(parent.pid)
    }
}

/// The processes above `ppid`, nearest first, and where the chain ends
/// ([`LAUNCHD`], [`UNSEEN`] or [`MORE`]): no parents and "launchd started it"
/// are not one thing, and a model reads the first as a program from nowhere.
fn parents(mut ppid: i64) -> (Vec<Known>, &'static str) {
    let mut out = Vec::new();
    loop {
        if ppid == 1 {
            return (out, LAUNCHD);
        }
        if out.len() == PARENTS {
            return (out, MORE);
        }
        let Some(k) = known(ppid) else {
            return (out, UNSEEN);
        };
        ppid = k.ppid;
        out.push(k);
    }
}

/// A command's arguments past this many bytes are cut: enough to tell
/// `npm test` from `npm install`, not a whole script.
const COMMAND_BYTES: usize = 80;

/// The arguments from `from` on, one line, cut at COMMAND_BYTES; None when
/// there are none.
fn command(args: &[&str], from: usize) -> Option<String> {
    let mut s = args
        .get(from..)
        .unwrap_or_default()
        .join(" ")
        .replace(['\t', '\n', '\r'], " ");
    if s.len() > COMMAND_BYTES {
        let mut cut = COMMAND_BYTES;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push('…');
    }
    Some(s).filter(|s| !s.is_empty())
}

/// Interpreters and shells: the program they run is the file they are given.
fn interpreter(path: &str) -> Option<&'static str> {
    let base = path.rsplit('/').next().unwrap_or(path);
    Some(match base {
        "node" => "node",
        "bun" => "bun",
        "deno" => "deno",
        "ruby" => "ruby",
        "perl" => "perl",
        "osascript" => "osascript",
        "sh" | "bash" | "zsh" | "dash" => base_static(base),
        "Python" => "python",
        b if b.starts_with("python") => "python",
        _ => return None,
    })
}

fn base_static(b: &str) -> &'static str {
    match b {
        "sh" => "sh",
        "bash" => "bash",
        "zsh" => "zsh",
        _ => "dash",
    }
}

/// Long flags that take the next argument as their value, before the script.
const VALUE_FLAGS: &[&str] = &["--require", "--import", "--loader", "--inspect-port"];

/// An interpreter's short flags, which come in clusters (`zsh -lc`,
/// `node -pe`, `python -Bc`): the letters that run inline code or read the
/// program from stdin (a shell's `-s`), and the letters that take a value (the
/// rest of the cluster, or the next argument).
fn short_flags(interp: &str) -> (&'static str, &'static str) {
    match interp {
        "sh" | "bash" | "zsh" | "dash" => ("cs", "o"),
        "python" => ("c", "WX"),
        "node" | "bun" => ("ep", "r"),
        "ruby" => ("e", "rI"),
        "perl" => ("eE", "IM"),
        "osascript" => ("e", "l"),
        _ => ("", ""),
    }
}

/// What an exec runs, when the program is an interpreter: `node <script>`,
/// `python -m <module>`, the script joined to the working directory and
/// written from `~`; and where its own arguments start. None for inline
/// code (`-c`, `-lc`, `-e`), a program on stdin (`python -`, `sh -s`) and a
/// bare shell.
fn script_name(path: &str, args: &[&str], cwd: Option<&str>) -> Option<(String, usize)> {
    let interp = interpreter(path)?;
    let (inline, valued) = short_flags(interp);
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match *a {
            "--eval" | "--print" | "-" => return None,
            "-m" => return args.get(i + 1).map(|m| (format!("{interp} -m {m}"), i + 2)),
            f if VALUE_FLAGS.contains(&f) => i += 1,
            f if f.starts_with("--") => {}
            f if f.starts_with('-') => {
                let letters: Vec<char> = f.chars().skip(1).collect();
                for (j, c) in letters.iter().enumerate() {
                    if inline.contains(*c) {
                        return None;
                    }
                    if valued.contains(*c) {
                        if j + 1 == letters.len() {
                            i += 1; // the value is the next argument
                        }
                        break;
                    }
                }
            }
            script => {
                let full = if script.starts_with('/') {
                    script.to_string()
                } else {
                    let rel = script.trim_start_matches("./");
                    match cwd {
                        Some(d) => format!("{}/{rel}", d.trim_end_matches('/')),
                        None => rel.to_string(),
                    }
                };
                let shown = home(&full).map(|(_, t)| t).unwrap_or(full);
                return Some((format!("{interp} {shown}"), i + 1));
            }
        }
        i += 1;
    }
    None
}

/// The path a `create` or `rename` wrote to: an existing file, or a new name
/// in a directory.
fn destination(body: &Value) -> Option<String> {
    if let Some(p) = str_at(body, "/destination/existing_file/path") {
        return Some(p.to_string());
    }
    let dir = str_at(body, "/destination/new_path/dir/path")?;
    let name = str_at(body, "/destination/new_path/filename")?;
    Some(format!("{}/{name}", dir.trim_end_matches('/')))
}

/// An OTLP headers value (`Authorization=Bearer …,x-team=acme`) with each
/// header's value taken out: which headers telemetry carries says where it
/// goes, and their values are its keys.
fn header_names(v: &str) -> String {
    v.split(',')
        .map(|h| match h.split_once('=') {
            Some((name, _)) => format!("{}=…", name.trim()),
            None => "…".to_string(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// `K=V` entries to the kept names, and how many there were.
fn environment(env: Option<&Value>) -> (Map<String, Value>, usize) {
    let mut kept = Map::new();
    let Some(entries) = env.and_then(Value::as_array) else {
        return (kept, 0);
    };
    for e in entries.iter().filter_map(Value::as_str) {
        let Some((k, v)) = e.split_once('=') else {
            continue;
        };
        if ENV_KEEP.contains(&k) || otel_matters(k) {
            let v = if k.ends_with("_HEADERS") {
                header_names(v)
            } else if k.to_ascii_lowercase().ends_with("_proxy") {
                without_userinfo(v)
            } else {
                v.to_string()
            };
            kept.insert(k.to_string(), json!(v));
        }
    }
    (kept, entries.len())
}

/// A record's place in the tree: the programs above `pid` (`parents`, with
/// their arguments, and `lineage`, without), each ending where the chain
/// does, and its `session`. launchd itself has none.
fn situate(out: &mut Map<String, Value>, pid: i64, ppid: i64, rec: &Map<String, Value>) {
    if pid > 1 {
        let (above, end) = parents(ppid);
        let mut shown: Vec<String> = above
            .iter()
            .map(|k| match &k.command {
                Some(c) => format!("{} {c}", k.who()),
                None => k.who().to_string(),
            })
            .collect();
        shown.push(end.to_string());
        out.insert("parents".into(), json!(shown));
        // who each is without its arguments, for the summary to tell the same
        // program run by the person from one run by a package's script
        let mut lineage: Vec<&str> = above.iter().map(Known::who).collect();
        lineage.push(end);
        out.insert("lineage".into(), json!(lineage));
    }
    let (sid, who) = entry(pid);
    let mut session = json!({"id": sid.to_string(), "entry": who});
    // an agent's session is cut at the person's prompts and then into
    // pieces of its turn, any other by the clock
    let time = rec.get("time").and_then(Value::as_str);
    match turn(sid) {
        Some(t) => {
            session["window"] = json!(piece(&t, time));
            session["turn"] = json!(t);
        }
        None => {
            if let Some(w) = time.and_then(window) {
                session["window"] = json!(w);
            }
        }
    }
    out.insert("session".into(), session);
}

/// A turn is summarized and judged this many seconds of its events at a
/// time: a long turn whole was fifty kilobytes with half its programs left
/// out, and its verdict came when it ended. Not finer: at thirty seconds a
/// nine-minute turn was twenty-three verdicts, each a chance to flag what
/// the last had passed.
const PIECE_SECS: i64 = 300;

/// Seconds since 1970 of an RFC 3339 time in UTC, to the second.
fn secs(t: &str) -> Option<i64> {
    let n = |r: std::ops::Range<usize>| t.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    // days from the civil date (Howard Hinnant's algorithm)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some(days * 86_400 + n(11..13)? * 3600 + n(14..16)? * 60 + n(17..19)?)
}

/// The piece of the turn begun at `turn` that an event at `time` is in:
/// `<turn>+<n>`, by the event's own time, so a replay cuts as a live run does.
fn piece(turn: &str, time: Option<&str>) -> String {
    let n = time
        .and_then(secs)
        .zip(secs(turn))
        .map_or(0, |(at, began)| (at - began).max(0) / PIECE_SECS);
    format!("{turn}+{n:03}")
}

/// A session's turn lasts this long after its prompt, unless another comes:
/// what an agent runs for an hour was asked for once; what its program does
/// the next day was not.
const TURN_TTL_MS: u64 = 7_200_000;

/// The window of a session a person has prompted an agent in: the time of
/// their latest prompt, to the second. Records are summarized a window at a
/// time, so a prompt and everything the agent did until the next are one
/// summary (or several in a row, when it runs long), never a prompt in one
/// and the commands it caused in the next.
fn turn(sid: i64) -> Option<String> {
    match state::get(&format!("turn:{sid}")) {
        Ok(Some(Scalar::Str(t))) => Some(t),
        _ => None,
    }
}

/// A connection from net/net.py (tcpdump's process-tagged packets): the
/// program that opened it as the tree knows it, else as tcpdump names it, in
/// its session like any event. A connection a system daemon made for an app
/// is the app's (`epid`), with the daemon as `via`.
fn connection(rec: &Map<String, Value>) -> Option<(Map<String, Value>, Norm)> {
    let c = rec.get("net")?;
    let tagged = |k: &str| c.get(k).and_then(Value::as_str).map(str::to_string);
    let pid = int_at(c, "/epid").or_else(|| int_at(c, "/pid"))?;
    let named = tagged("eproc").or_else(|| tagged("proc"));
    let k = known(pid);
    let mut p = Map::new();
    p.insert("pid".into(), json!(pid));
    let ppid = k.as_ref().map_or(0, |k| k.ppid);
    match &k {
        Some(k) => {
            p.insert("ppid".into(), json!(k.ppid));
            p.insert("path".into(), json!(k.path));
            put(&mut p, "name", k.name.clone());
            put(&mut p, "signer", k.signer.clone());
            put(&mut p, "team", k.team.clone());
            if k.seen {
                p.insert("platform".into(), json!(k.platform));
            }
        }
        // a process older than the log: tcpdump's name for it
        None => put(&mut p, "name", named.clone()),
    }
    let mut out = Map::new();
    out.insert("event".into(), json!("connect"));
    out.insert("process".into(), Value::Object(p));
    situate(&mut out, pid, ppid, rec);
    if out["session"]["entry"] == "" {
        out["session"]["entry"] = json!(named.clone().unwrap_or_default());
    }
    let mut x = Map::new();
    for f in ["proto", "dst", "port", "host", "named_by"] {
        if let Some(v) = c.get(f) {
            x.insert(f.into(), v.clone());
        }
    }
    if c.get("epid").is_some() {
        put(&mut x, "via", tagged("proc"));
    }
    out.insert("connect".into(), Value::Object(x));
    let target = tagged("host").or_else(|| tagged("dst"));
    let mut n = Norm {
        actor: Some(k.map(|k| k.ident).or(named).unwrap_or_default()),
        kind: Some("connect".into()),
        principal: Some("none"),
        target,
        ..Norm::default()
    };
    // whose network the address is in, from the enrichment tables
    // (`_facts.ips`): a host name says what was asked for, not who answers
    if let Some(dst) = tagged("dst") {
        n.address("connect.dst", dst);
    }
    Some((out, n))
}

/// A prompt kept to this many bytes: enough to say what was asked; a pasted
/// file is not the request.
const PROMPT_BYTES: usize = 4000;

/// A line of agent/transcripts.py: what a person asked an AI coding agent,
/// as the agent's transcript records it. Endpoint Security shows what the
/// agent then ran and never why, so the prompt is a record in the session
/// the agent is in: `pids` names the agent's process, and the first of them
/// the tree knows places it. A prompt with no pid the tree knows (a session
/// no running agent holds) belongs to no session and is dropped.
fn prompt(rec: &Map<String, Value>) -> Option<(Map<String, Value>, Norm)> {
    let p = rec.get("prompt")?;
    let text = str_at(p, "/text").filter(|t| !t.trim().is_empty())?;
    let (pid, k) = p
        .get("pids")?
        .as_array()?
        .iter()
        .filter_map(Value::as_i64)
        .find_map(|pid| known(pid).map(|k| (pid, k)))?;
    let mut proc = Map::new();
    proc.insert("pid".into(), json!(pid));
    proc.insert("ppid".into(), json!(k.ppid));
    proc.insert("path".into(), json!(k.path));
    put(&mut proc, "name", k.name.clone());
    let mut out = Map::new();
    out.insert("event".into(), json!("prompt"));
    out.insert("process".into(), Value::Object(proc));
    situate(&mut out, pid, k.ppid, rec);
    // a prompt opens its session's next turn, and is the first record of it;
    // one typed while the agent worked adds to the turn under way
    let during = p["during"] == true;
    if during {
        // nothing to open
    } else if let (Some(at), Some(sid)) = (
        rec.get("time")
            .and_then(Value::as_str)
            .and_then(|t| t.get(..19)),
        out["session"]["id"].as_str().map(str::to_string),
    ) {
        let _ = state::set(
            &format!("turn:{sid}"),
            &Scalar::Str(at.to_string()),
            Some(TURN_TTL_MS),
        );
        out["session"]["window"] = json!(piece(at, Some(at)));
        out["session"]["turn"] = json!(at);
    }
    let mut end = text.len().min(PROMPT_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut x = Map::new();
    x.insert("text".into(), json!(&text[..end]));
    // `after`: what the agent last said before the prompt, its start and end
    for f in ["agent", "session", "cwd", "after"] {
        if let Some(v) = p.get(f).filter(|v| v.is_string()) {
            x.insert(f.into(), v.clone());
        }
    }
    if during {
        x.insert("during".into(), json!(true));
    }
    out.insert("prompt".into(), Value::Object(x));
    let n = Norm {
        actor: Some(k.ident),
        kind: Some("prompt".into()),
        principal: Some("none"),
        ..Norm::default()
    };
    Some((out, n))
}

/// The record as a model reads it, and its `_norm`; None for an event that
/// is nobody's business.
fn finished(rec: &Map<String, Value>) -> Option<(Map<String, Value>, Norm)> {
    let event = rec.get("event")?.as_object()?;
    let (kind, body) = event.iter().next()?;
    let actor = proc_of(rec.get("process")?)?;

    // the tree first, whatever becomes of the event
    let mine = known(actor.pid);
    match &mine {
        None => remember(&actor, None),
        // known from a snapshot: now by its signature too, under the parent
        // the snapshot saw if launchd has taken it since
        Some(k) if !k.seen => {
            let mut a = actor.clone();
            if a.ppid <= 1 && k.ppid > 1 {
                a.ppid = k.ppid;
            }
            remember(&a, None);
        }
        Some(_) => {}
    }
    match kind.as_str() {
        "fork" => {
            if let Some(mut child) = proc_of(&body["child"]) {
                if let Some(k) = &mine {
                    child.name = k.name.clone();
                    child.command = k.command.clone();
                }
                let e = inherited(&actor, &child);
                remember(&child, Some(&e));
            }
            return None;
        }
        "exit" => {
            if let Some(k) = mine {
                let mut gone = actor;
                gone.ppid = k.ppid;
                gone.name = k.name;
                gone.command = k.command;
                store(&gone, k.entry.as_ref(), EXITED_TTL_MS);
            }
            return None;
        }
        _ => {}
    }
    // the parent the tree saw it forked from: when that exits, launchd
    // takes the child, and the event's ppid says 1
    let first_ppid = |live: i64| match &mine {
        Some(k) if live <= 1 && k.ppid > 1 => k.ppid,
        _ => live,
    };

    // An exec's process is the program that started, under the pid it took
    // over; the one that launched it is the first of its parents.
    let actor = match kind.as_str() {
        "exec" => {
            let mut target = proc_of(&body["target"])?;
            let args: Vec<&str> = body
                .get("args")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let named = match (str_at(body, "/script/path"), interpreter(&target.path)) {
                // a `#!` file: its arguments follow it
                (Some(s), Some(i)) => {
                    let base = s.rsplit('/').next().unwrap_or(s);
                    let at = args
                        .iter()
                        .skip(1)
                        .position(|a| a.rsplit('/').next() == Some(base))
                        .map_or(1, |p| p + 2);
                    let shown = home(s).map(|(_, t)| t).unwrap_or(s.to_string());
                    Some((format!("{i} {shown}"), at))
                }
                _ => script_name(&target.path, &args, str_at(body, "/cwd/path")),
            };
            let from = named.as_ref().map_or(1, |(_, at)| *at);
            target.name = named.map(|(n, _)| n);
            target.command = command(&args, from);
            target.ppid = first_ppid(target.ppid);
            // an exec keeps the process's session; an entry point that execs
            // (login's shell, a shell's `exec`) takes its new name
            let e = mine.and_then(|k| k.entry).map(|(pid, who)| {
                if pid == target.pid {
                    (pid, target.ident())
                } else {
                    (pid, who)
                }
            });
            remember(&target, e.as_ref());
            target
        }
        _ => {
            let mut a = actor;
            a.ppid = first_ppid(a.ppid);
            a.name = mine.filter(|k| k.path == a.path).and_then(|k| k.name);
            a
        }
    };

    let mut out = Map::new();
    out.insert("event".into(), json!(kind));
    out.insert("process".into(), actor.json());
    situate(&mut out, actor.pid, actor.ppid, rec);
    // whose behalf it works on, by name: `process.responsible` is a pid
    if let Some(r) = actor.responsible {
        let who = match known(r) {
            Some(k) => k.who().to_string(),
            None if r == 1 => LAUNCHD.to_string(),
            None => UNSEEN.to_string(),
        };
        out.insert("responsible".into(), json!(who));
    }

    let mut n = Norm {
        actor: Some(job(&actor)),
        kind: Some(kind.clone()),
        principal: Some("none"), // a program, not a person the profile could know
        ..Norm::default()
    };
    let mut org = home(&actor.path).map(|(name, _)| name.to_string());

    // what the event touched, and whether that is worth a model's time
    let mut touched: Option<(String, Option<Group>)> = None;
    match kind.as_str() {
        "exec" => {
            let mut x = Map::new();
            if let Some(args) = body.get("args") {
                x.insert("args".into(), cut_args(args));
            }
            let cwd = str_at(body, "/cwd/path");
            org = org.or_else(|| cwd.and_then(home).map(|(name, _)| name.to_string()));
            put(&mut x, "cwd", cwd);
            put(&mut x, "script", str_at(body, "/script/path"));
            let (env, count) = environment(body.get("env"));
            x.insert("env_count".into(), json!(count));
            if !env.is_empty() {
                n.fact(
                    "steering_env",
                    "the environment sets code every process loads, where traffic goes, an AI agent's config or telemetry, or names the package script that is running",
                );
                x.insert("env".into(), Value::Object(env));
            }
            // the program, or the script an interpreter runs
            let script = str_at(body, "/script/path")
                .map(str::to_string)
                .or_else(|| {
                    actor
                        .name
                        .as_deref()
                        .and_then(|n| n.split_once(' '))
                        .map(|(_, p)| p.to_string())
                });
            if scratch(&actor.path) || script.as_deref().is_some_and(scratch) {
                n.fact(
                    "scratch_program",
                    "the program runs from a temporary, cache, download or node_modules directory",
                );
            }
            if actor.signer.is_none() && actor.team.is_none() && !actor.platform {
                n.fact("unsigned", "the program has no code signature");
            }
            out.insert("exec".into(), Value::Object(x));
        }
        "open" => {
            let file = str_at(body, "/file/path")?.to_string();
            let write = int_at(body, "/fflag").unwrap_or(0) & FWRITE != 0;
            let g = group(&file)?;
            if !write && !g.read_matters() {
                return None;
            }
            out.insert("access".into(), json!(if write { "write" } else { "read" }));
            touched = Some((file, Some(g)));
        }
        "close" => {
            if !body["modified"].as_bool().unwrap_or(false) {
                return None;
            }
            let file = str_at(body, "/target/path")?.to_string();
            let g = group(&file)?;
            out.insert("modified".into(), json!(true));
            touched = Some((file, Some(g)));
        }
        "create" => {
            let file = destination(body)?;
            let g = group(&file)?;
            touched = Some((file, Some(g)));
        }
        "unlink" => {
            let file = str_at(body, "/target/path")?.to_string();
            let g = group(&file)?;
            touched = Some((file, Some(g)));
        }
        "rename" => {
            let from = str_at(body, "/source/path")?.to_string();
            let to = destination(body)?;
            let g = group(&to).or_else(|| group(&from))?;
            if body.pointer("/destination/existing_file").is_some() {
                n.fact(
                    "rename_over",
                    "the file was replaced by renaming another over it",
                );
            }
            out.insert("from".into(), json!(from));
            touched = Some((to, Some(g)));
        }
        // rare and each its own story (btm_launch_item_add, tcc_modify, ...): as it came, less the stat blocks
        _ => {
            let mut detail = body.clone();
            if let Value::Object(m) = &mut detail {
                normkit::prune(m, &|k, _| k == "stat");
            }
            out.insert("detail".into(), normkit::shrink(&detail, ARGS_BYTES));
        }
    }

    if let Some((file, g)) = touched {
        if let Some(g) = g {
            n.fact(g.key(), g.note());
        }
        org = org.or_else(|| home(&file).map(|(name, _)| name.to_string()));
        n.target = Some(file.clone());
        out.insert("file".into(), json!(file));
    }
    n.org = org;
    Some((out, n))
}

impl Guest for Component {
    fn metadata() -> Meta {
        Meta {
            name: "macos".to_string(),
            version: "0.1.0".to_string(),
        }
    }

    /// An eslogger line: an `event` from a `process`; or a connection from
    /// net/net.py.
    fn probe() -> Vec<Selector> {
        vec![
            Selector {
                any: Vec::new(),
                all: vec![
                    Pred::Has("event".to_string()),
                    Pred::Has("process.audit_token".to_string()),
                ],
                none: Vec::new(),
            },
            Selector {
                any: Vec::new(),
                all: vec![Pred::Has("net.dst".to_string())],
                none: Vec::new(),
            },
            Selector {
                any: Vec::new(),
                all: vec![Pred::Has("ps.pid".to_string())],
                none: Vec::new(),
            },
            Selector {
                any: Vec::new(),
                all: vec![Pred::Has("prompt.text".to_string())],
                none: Vec::new(),
            },
        ]
    }

    fn process_logs(input: Vec<Logview>) -> Result<Vec<u8>, String> {
        let kit = factskit::kit(lookup);
        let mut out = Vec::new();
        for lv in input {
            let read = normkit::record(&lv.log())?;
            let made = if read.contains_key("ps") {
                snapshot(&read);
                None
            } else if read.contains_key("net") {
                connection(&read)
            } else if read.contains_key("prompt") {
                prompt(&read)
            } else {
                finished(&read)
            };
            if let Some((rec, n)) = made {
                // eslogger's `time`, and no `source`: the stamp is built, not read
                let mut stamp = Stamp::of(&read);
                if let Some(t) = read.get("time").and_then(Value::as_str) {
                    stamp.ts = t.to_string();
                }
                stamp.source = "macos".into();
                kit.write(&mut out, stamp, rec, n)?;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(path: &str, args: &[&str], cwd: &str) -> Option<String> {
        script_name(path, args, Some(cwd)).map(|(n, _)| n)
    }

    #[test]
    fn a_turn_is_cut_into_pieces_by_its_events_times() {
        let turn = "2026-11-10T19:01:36";
        let at = |t: &str| piece(turn, Some(t));
        assert_eq!(at("2026-11-10T19:01:36.421Z"), "2026-11-10T19:01:36+000");
        assert_eq!(at("2026-11-10T19:06:35.999Z"), "2026-11-10T19:01:36+000");
        assert_eq!(at("2026-11-10T19:06:36.000Z"), "2026-11-10T19:01:36+001");
        assert_eq!(at("2026-11-10T19:10:46.000Z"), "2026-11-10T19:01:36+001");
        // across midnight, and an event the reader sent a moment early
        assert_eq!(
            piece("2026-11-10T23:59:50", Some("2026-11-11T00:04:55Z")),
            "2026-11-10T23:59:50+001"
        );
        assert_eq!(at("2026-11-10T19:01:35.000Z"), "2026-11-10T19:01:36+000");
        assert_eq!(secs("1970-01-02T00:00:01Z"), Some(86_401));
    }

    #[test]
    fn interpreters_are_named_by_their_script() {
        let node = "/opt/homebrew/Cellar/node/26.0.0/bin/node";
        assert_eq!(
            name(
                node,
                &["node", "scripts/postinstall.js"],
                "/Users/a/code/x/node_modules/p"
            ),
            Some("node ~/code/x/node_modules/p/scripts/postinstall.js".into())
        );
        assert_eq!(
            name(
                node,
                &["node", "/opt/homebrew/bin/npm", "install"],
                "/Users/a/code/x"
            ),
            Some("node /opt/homebrew/bin/npm".into())
        );
        assert_eq!(
            name(
                node,
                &["node", "--require", "./hook.js", "./server.js"],
                "/Users/a/s"
            ),
            Some("node ~/s/server.js".into())
        );
        assert_eq!(
            name(
                "/usr/bin/python3",
                &["python3", "-m", "pytest", "-q"],
                "/Users/a/x"
            ),
            Some("python -m pytest".into())
        );
        assert_eq!(name("/bin/sh", &["sh", "-c", "node x.js"], "/"), None);
        assert_eq!(name("/bin/zsh", &["-zsh"], "/Users/a"), None);
        assert_eq!(name("/usr/bin/git", &["git", "status"], "/Users/a"), None);
        // inline code in a cluster of flags
        assert_eq!(
            name(
                "/bin/zsh",
                &["/bin/zsh", "-lc", "ls src tests"],
                "/Users/a/x"
            ),
            None
        );
        assert_eq!(
            name("/usr/bin/python3", &["python3", "-Bc", "print(1)"], "/"),
            None
        );
        assert_eq!(name(node, &["node", "-pe", "1"], "/"), None);
        // the program on stdin: its arguments are not a script
        assert_eq!(
            name(
                "/usr/bin/python3",
                &["python3", "-I", "-", "/Users/a/.local/share/x", "/Users/a"],
                "/Users/a"
            ),
            None
        );
        assert_eq!(
            name(
                "/bin/sh",
                &["sh", "-s", "--", "--default-toolchain", "stable"],
                "/Users/a"
            ),
            None
        );
        // a value-taking letter ends the cluster
        assert_eq!(
            name(
                "/usr/bin/python3",
                &["python3", "-Werror::DeprecationWarning", "t.py"],
                "/Users/a"
            ),
            Some("python ~/t.py".into())
        );
        assert_eq!(
            name(
                "/bin/bash",
                &["bash", "-o", "pipefail", "-e", "run.sh"],
                "/Users/a"
            ),
            Some("bash ~/run.sh".into())
        );
    }

    #[test]
    fn telemetry_headers_keep_their_names_not_their_values() {
        let env = json!([
            "OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer s3cret,x-team=acme",
            "OTEL_EXPORTER_OTLP_ENDPOINT=https://otel.example.com",
            "AWS_SECRET_ACCESS_KEY=abc",
        ]);
        let (kept, n) = environment(Some(&env));
        assert_eq!(n, 3);
        assert_eq!(
            kept["OTEL_EXPORTER_OTLP_HEADERS"],
            "Authorization=…,x-team=…"
        );
        assert_eq!(
            kept["OTEL_EXPORTER_OTLP_ENDPOINT"],
            "https://otel.example.com"
        );
        assert!(kept.get("AWS_SECRET_ACCESS_KEY").is_none());
    }

    #[test]
    fn a_postinstall_and_an_injected_library_are_kept_a_proxy_password_is_not() {
        let env = json!([
            "npm_lifecycle_event=postinstall",
            "npm_package_name=evil-pkg",
            "NODE_OPTIONS=--require /tmp/x.js",
            "DYLD_INSERT_LIBRARIES=/tmp/libx.dylib",
            "HTTPS_PROXY=http://bob:hunter2@proxy.example.com:8080",
            "npm_config__authToken=npm_secret",
        ]);
        let (kept, _) = environment(Some(&env));
        assert_eq!(kept["npm_lifecycle_event"], "postinstall");
        assert_eq!(kept["npm_package_name"], "evil-pkg");
        assert_eq!(kept["NODE_OPTIONS"], "--require /tmp/x.js");
        assert_eq!(kept["DYLD_INSERT_LIBRARIES"], "/tmp/libx.dylib");
        assert_eq!(kept["HTTPS_PROXY"], "http://…@proxy.example.com:8080");
        assert!(kept.get("npm_config__authToken").is_none());
    }

    #[test]
    fn a_window_is_the_five_minutes_an_event_falls_in() {
        assert_eq!(
            window("2026-11-03T21:27:59.326138034Z").as_deref(),
            Some("2026-11-03T21:25")
        );
        assert_eq!(
            window("2026-11-03T21:30:00Z").as_deref(),
            Some("2026-11-03T21:30")
        );
        assert_eq!(window("bad"), None);
    }

    #[test]
    fn long_arguments_are_cut_not_dropped() {
        let long = "x".repeat(1000);
        let args = json!(["/bin/zsh", "-c", long, "a", "b", "c"]);
        let out = cut_args(&args);
        let out: Vec<&str> = out
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(out[0], "/bin/zsh");
        assert_eq!(out[2].len(), ARG_BYTES + "…".len());
        assert_eq!(out.len(), 6);
        let many: Vec<String> = (0..400).map(|i| format!("file{i}.txt")).collect();
        let out = cut_args(&json!(many));
        let last = out
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            last.starts_with("… ") && last.ends_with(" more arguments"),
            "{last}"
        );
        assert!(paths::scratch("~/Downloads/x/proxy.py"));
    }

    #[test]
    fn a_command_is_what_follows_the_script() {
        let args = ["node", "/opt/homebrew/bin/npm", "test"];
        let at = script_name("/opt/homebrew/bin/node", &args, Some("/Users/a/x")).map(|(_, at)| at);
        assert_eq!(at, Some(2));
        assert_eq!(command(&args, 2), Some("test".into()));
        assert_eq!(command(&["/bin/zsh", "-l"], 1), Some("-l".into()));
        assert_eq!(command(&["/usr/bin/true"], 1), None);
        let long = "x".repeat(200);
        assert_eq!(
            command(&["sh", "-c", &long], 1).map(|c| c.len()),
            Some(COMMAND_BYTES + '…'.len_utf8())
        );
    }
}
