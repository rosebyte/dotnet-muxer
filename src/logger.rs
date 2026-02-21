mod platform;

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub(crate) const UNKNOWN: &str = "unknown";
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
    write_field(&mut line, "args", &args_text);
    write_field(&mut line, "target", &target_path.display().to_string());
    write_field(&mut line, "cwd", &cwd);
    write_field(
        &mut line,
        "process",
        &format!("({}) {process_text}", process::id()),
    );
    platform::write_parent_fields(&mut line, process::id());
    write_field(&mut line, "ts", &timestamp());
    line.push('\n');

    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = file.write_all(line.as_bytes());
    }
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| TIMESTAMP_FALLBACK.to_string())
}

fn write_field(line: &mut String, key: &str, value: &str) {
    line.push_str(key);
    line.push_str("=\"");
    line.push_str(value);
    line.push_str("\" ");
}
