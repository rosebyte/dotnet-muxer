// dotnet-muxer: Routes dotnet invocations to the right runtime/SDK.
//
// Requires DOTNET_MUXER_TARGET env var (repo root path). Uses
// <root>/.dotnet/dotnet and redirects testhost.dll invocations from
// the pinned SDK to the repo's locally-built testhost.
//
// Build:   cargo build --release
// Install: ./install.sh

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const EXIT_EXEC_ERROR: i32 = 127;
const UNKNOWN: &str = "unknown";
const DOTNET_MUXER_TARGET: &str = "DOTNET_MUXER_TARGET";
const TIMESTAMP_FALLBACK: &str = "????-??-??T??:??:??Z";

// ---------------------------------------------------------------------------
// Logging — single atomic write per invocation
// ---------------------------------------------------------------------------

struct LogEntry {
    file: Option<fs::File>,
    parent_name: String,
    args: String,
    cwd: String,
    pid: u32,
    target: Option<String>,
    messages: Vec<String>,
}

impl LogEntry {
    fn new() -> Self {
        let pid = process::id();
        let file = env::var("DOTNET_MUXER_VERBOSE")
            .ok()
            .filter(|v| matches!(v.as_str(), "1" | "true" | "True" | "TRUE"))
            .and_then(|_| {
                let log_path = env::current_exe().ok()?.parent()?.join("log.log");
                fs::OpenOptions::new().create(true).append(true).open(log_path).ok()
            });
        Self {
            file,
            parent_name: parent_process_name(pid),
            args: env::args().collect::<Vec<_>>().join(" "),
            cwd: env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| UNKNOWN.to_string()),
            pid,
            target: None,
            messages: Vec::new(),
        }
    }

    fn msg(&mut self, msg: impl Into<String>) {
        self.messages.push(msg.into());
    }

    fn dispatch(&mut self, path: &Path) {
        self.target = Some(path.display().to_string());
    }

    fn flush(&mut self) {
        let Some(ref mut f) = self.file else { return };

        let ts = timestamp();
        let target = self.target.as_deref().unwrap_or("none");
        let msgs = if self.messages.is_empty() {
            String::new()
        } else {
            format!(" messages=\"{}\"", self.messages.join("; "))
        };

        let _ = writeln!(
            f,
            "ts={ts} parent=\"{}\" pid={} cwd=\"{}\" args=\"{}\" target=\"{target}\"{msgs}",
            self.parent_name, self.pid, self.cwd, self.args
        );
    }
}

#[cfg(unix)]
fn parent_process_name(pid: u32) -> String {
    let ppid = ps_field(pid, "ppid=").and_then(|s| s.parse::<u32>().ok());

    ppid
        .and_then(|id| ps_field(id, "comm="))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| UNKNOWN.to_string())
}

#[cfg(not(unix))]
fn parent_process_name(_pid: u32) -> String {
    UNKNOWN.to_string()
}

#[cfg(unix)]
fn ps_field(pid: u32, field: &str) -> Option<String> {
    let pid = pid.to_string();
    process::Command::new("ps")
        .args(["-o", field, "-p", pid.as_str()])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}

impl Drop for LogEntry {
    fn drop(&mut self) {
        self.flush();
    }
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
    .unwrap_or_else(|_| TIMESTAMP_FALLBACK.to_string())
}

// ---------------------------------------------------------------------------
// Platform helpers
// ---------------------------------------------------------------------------

fn dotnet_exe() -> &'static str {
    if cfg!(windows) { "dotnet.exe" } else { "dotnet" }
}

// ---------------------------------------------------------------------------
// Testhost detection
// ---------------------------------------------------------------------------

fn is_testhost_from_sdk(args: &[String], sdk_dir: &Path) -> bool {
    let sdk_root = sdk_dir.join("sdk");
    args.iter().skip(1).any(|arg| {
        let path = Path::new(arg.as_str());
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.eq_ignore_ascii_case("vstest.console.dll"))
            .unwrap_or(false)
            && path.parent()
                .and_then(|v| v.parent())
                .map(|p| p == sdk_root)
                .unwrap_or(false)
    })
}

fn find_testhost_dotnet(repo_root: &Path) -> Option<PathBuf> {
    let testhost_dir = repo_root.join("artifacts/bin/testhost");
    let mut fallback: Option<PathBuf> = None;

    for entry in fs::read_dir(&testhost_dir).ok()?.flatten() {
        let candidate = entry.path().join(dotnet_exe());
        if !candidate.is_file() {
            continue;
        }

        if fallback.is_none() {
            fallback = Some(candidate.clone());
        }

        if candidate.components().any(|c| c.as_os_str() == "Release") {
            return Some(candidate);
        }
    }
    fallback
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn exec_dotnet(dotnet_path: &Path, args: &[String], log: &mut LogEntry) -> ! {
    use std::os::unix::process::CommandExt;
    log.dispatch(dotnet_path);
    log.flush();
    let err = process::Command::new(dotnet_path).args(&args[1..]).exec();
    eprintln!("[dotnet-muxer] Failed to exec {}: {err}", dotnet_path.display());
    process::exit(EXIT_EXEC_ERROR);
}

#[cfg(not(unix))]
fn exec_dotnet(dotnet_path: &Path, args: &[String], log: &mut LogEntry) -> ! {
    log.dispatch(dotnet_path);
    log.flush();
    match process::Command::new(dotnet_path).args(&args[1..]).status() {
        Ok(status) => process::exit(status.code().unwrap_or(EXIT_EXEC_ERROR)),
        Err(e) => {
            eprintln!("[dotnet-muxer] Failed to exec {}: {e}", dotnet_path.display());
            process::exit(EXIT_EXEC_ERROR);
        }
    }
}

fn require_repo_root(log: &mut LogEntry) -> PathBuf {
    match env::var(DOTNET_MUXER_TARGET) {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value),
        _ => fail(log, "DOTNET_MUXER_TARGET not set", "[dotnet-muxer] DOTNET_MUXER_TARGET is required"),
    }
}

fn target_dotnet_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".dotnet").join(dotnet_exe())
}

fn ensure_target_dotnet_exists(log: &mut LogEntry, target_path: &Path) {
    if target_path.is_file() {
        return;
    }

    let msg = format!("{} not found", target_path.display());
    let err = format!(
        "[dotnet-muxer] DOTNET_MUXER_TARGET does not contain {}",
        target_path.display()
    );
    fail(log, &msg, &err);
}

fn fail(log: &mut LogEntry, log_msg: &str, err_msg: &str) -> ! {
    log.msg(log_msg);
    eprintln!("{err_msg}");
    process::exit(EXIT_EXEC_ERROR);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let mut log = LogEntry::new();
    let args: Vec<String> = env::args().collect();

    let repo_root = require_repo_root(&mut log);
    let dotnet_dir = repo_root.join(".dotnet");
    let target_path = target_dotnet_path(&repo_root);
    ensure_target_dotnet_exists(&mut log, &target_path);

    if is_testhost_from_sdk(&args, &dotnet_dir) {
        if let Some(testhost) = find_testhost_dotnet(&repo_root) {
            log.msg("testhost redirect");
            exec_dotnet(&testhost, &args, &mut log);
        }
        log.msg("testhost not found, falling through");
    }

    exec_dotnet(&target_path, &args, &mut log);
}
