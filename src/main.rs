// dotnet-muxer: Routes dotnet invocations to the right runtime/SDK.
//
// Requires DOTNET_MUXER_TARGET env var (repo root path). Uses
// <root>/.dotnet/dotnet and redirects testhost.dll invocations from
// the pinned SDK to the repo's locally-built testhost.
// Falls back to next dotnet in PATH if DOTNET_MUXER_TARGET is not set.
//
// Build:   cargo build --release
// Install: ./install.sh

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// Logging — single atomic write per invocation
// ---------------------------------------------------------------------------

struct LogEntry {
    file: Option<fs::File>,
    args: String,
    pid: u32,
    target: Option<String>,
    messages: Vec<String>,
}

impl LogEntry {
    fn new() -> Self {
        let file = env::var("DOTNET_MUXER_VERBOSE")
            .ok()
            .filter(|v| matches!(v.as_str(), "1" | "true" | "True" | "TRUE"))
            .and_then(|_| {
                let log_path = env::current_exe().ok()?.parent()?.join("log.log");
                fs::OpenOptions::new().create(true).append(true).open(log_path).ok()
            });
        Self {
            file,
            args: env::args().collect::<Vec<_>>().join(" "),
            pid: process::id(),
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
            "ts={ts} pid={} args=\"{}\" target=\"{target}\"{msgs}",
            self.pid, self.args
        );
    }
}

impl Drop for LogEntry {
    fn drop(&mut self) {
        self.flush();
    }
}

fn timestamp() -> String {
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let days = secs / 86400;
    let time = secs % 86400;
    let (y, mo, da) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{da:02}T{:02}:{:02}:{:02}Z", time / 3600, (time % 3600) / 60, time % 60)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970;
    loop {
        let ydays = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
        if days < ydays { break; }
        days -= ydays;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 0;
    for md in mdays {
        if days < md { break; }
        days -= md;
        mo += 1;
    }
    (y, mo + 1, days + 1)
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
        let candidate = entry.path().join(dotnet_exe());        if !candidate.is_file() { continue; }
        if fallback.is_none() { fallback = Some(candidate.clone()); }
        if candidate.components().any(|c| c.as_os_str() == "Release") {
            return Some(candidate);
        }
    }
    fallback
}

// ---------------------------------------------------------------------------
// PATH scanning
// ---------------------------------------------------------------------------

fn find_next_dotnet_in_path() -> Option<PathBuf> {
    let self_path = env::current_exe()
        .ok()
        .and_then(|p| fs::canonicalize(p).ok());

    for dir in env::split_paths(&env::var_os("PATH")?) {
        let candidate = dir.join(dotnet_exe());        if !candidate.is_file() { continue; }
        if let Some(self_path) = &self_path {
            if let Ok(resolved) = fs::canonicalize(&candidate) {
                if resolved == *self_path { continue; }
            }
        }
        return Some(candidate);
    }
    None
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
    process::exit(127);
}

#[cfg(not(unix))]
fn exec_dotnet(dotnet_path: &Path, args: &[String], log: &mut LogEntry) -> ! {
    log.dispatch(dotnet_path);
    log.flush();
    match process::Command::new(dotnet_path).args(&args[1..]).status() {
        Ok(s) => process::exit(s.code().unwrap_or(127)),
        Err(e) => {
            eprintln!("[dotnet-muxer] Failed to exec {}: {e}", dotnet_path.display());
            process::exit(127);
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let mut log = LogEntry::new();
    let args: Vec<String> = env::args().collect();

    // DOTNET_MUXER_TARGET → repo root
    if let Some(repo_root) = env::var("DOTNET_MUXER_TARGET")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
    {
        let dotnet_dir = repo_root.join(".dotnet");
        let target_path = dotnet_dir.join(dotnet_exe());

        if target_path.is_file() {
            if is_testhost_from_sdk(&args, &dotnet_dir) {
                if let Some(testhost) = find_testhost_dotnet(&repo_root) {
                    log.msg("testhost redirect");
                    exec_dotnet(&testhost, &args, &mut log);
                }
                log.msg("testhost not found, falling through");
            }
            exec_dotnet(&target_path, &args, &mut log);
        }
        log.msg(format!("{} not found", target_path.display()));
    }

    // Fallback to next dotnet in PATH
    if let Some(next) = find_next_dotnet_in_path() {
        log.msg("PATH fallback");
        exec_dotnet(&next, &args, &mut log);
    }

    log.msg("no dotnet found");
    eprintln!("[dotnet-muxer] No DOTNET_MUXER_TARGET set and no dotnet found in PATH");
    process::exit(127);
}
