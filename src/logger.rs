use std::env;
use std::ffi::OsString;
use std::fs;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::process;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const UNKNOWN: &str = "unknown";
const TIMESTAMP_FALLBACK: &str = "????-??-??T??:??:??Z";

pub fn run(target_path: &Path, args: &[OsString]) {
    let verbose = env::var("DOTNET_MUXER_VERBOSE").unwrap_or_default();
    if !verbose.eq_ignore_ascii_case("true") {
        return;
    }

    let process_path = env::current_exe().ok();
    let log_dir = process_path
        .as_deref()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."));
    let log_path = log_dir.join("log.log");

    let args_text = args
        .iter()
        .map(|a| a.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let cwd = env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| UNKNOWN.to_string());
    let process_text = process_path
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| UNKNOWN.to_string());

    let mut line = String::new();
    line.push_str("args=\"");
    line.push_str(&args_text);
    line.push_str("\" ");
    line.push_str("target=\"");
    line.push_str(&target_path.display().to_string());
    line.push_str("\" ");
    line.push_str("cwd=\"");
    line.push_str(&cwd);
    line.push_str("\" ");
    line.push_str("process=\"(");
    line.push_str(&process::id().to_string());
    line.push_str(") ");
    line.push_str(&process_text);
    line.push_str("\" ");
    line.push_str("parents=\"");
    line.push_str(&parent_process_chain(process::id()));
    line.push_str("\" ");
    line.push_str("ts=\"");
    line.push_str(&timestamp());
    line.push_str("\"\n");

    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = file.write_all(line.as_bytes());
    }
}

#[cfg(unix)]
fn parent_process_chain(start_pid: u32) -> String {
    let mut visited = HashSet::new();
    let mut chain = Vec::new();
    let mut pid = start_pid;

    while pid != 0 {
        if !visited.insert(pid) {
            break;
        }

        let Some((parent_pid, parent_name)) = parent_of(pid) else {
            break;
        };

        chain.push(format!("({parent_pid}) {parent_name}"));
        pid = parent_pid;
    }

    if chain.is_empty() {
        UNKNOWN.to_string()
    } else {
        chain.join(" -> ")
    }
}

#[cfg(not(unix))]
fn parent_process_chain(_pid: u32) -> String {
    UNKNOWN.to_string()
}

#[cfg(unix)]
fn parent_of(pid: u32) -> Option<(u32, String)> {
    let parent_pid = ps_field(pid, "ppid=")?.parse::<u32>().ok()?;
    if parent_pid == 0 || parent_pid == pid {
        return None;
    }

    let parent_name = ps_field(parent_pid, "comm=")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| UNKNOWN.to_string());

    Some((parent_pid, parent_name))
}

#[cfg(unix)]
fn ps_field(pid: u32, field: &str) -> Option<String> {
    let pid_text = pid.to_string();
    process::Command::new("ps")
        .args(["-o", field, "-p", pid_text.as_str()])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_string())
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| TIMESTAMP_FALLBACK.to_string())
}
