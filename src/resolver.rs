use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

const DOTNET_MUXER_TARGET: &str = "DOTNET_MUXER_TARGET";

pub(crate) fn resolve_dispatch_target(args: &[OsString]) -> PathBuf {
    let target_path = read_target_or_exit();
    return try_get_testhost_path(args, target_path);
}

fn read_target_or_exit() -> PathBuf {
    match env::var_os(DOTNET_MUXER_TARGET) {
        Some(value) if !value.is_empty() => return PathBuf::from(value),
        _ => {
            eprintln!("[dotnet-muxer] {DOTNET_MUXER_TARGET} is not set");
            process::exit(1);
        }
    }
}

fn try_get_testhost_path(args: &[OsString], target_path: PathBuf) -> PathBuf {
    let Some(argument) = args.first().map(Path::new) else {
        return target_path;
    };

    let is_vstest = argument
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("vstest.console.dll"));
    if !is_vstest {
        return target_path;
    }

    let Some(dotnet_dir) = target_path.parent() else {
        return target_path;
    };

    if dotnet_dir.file_name() != Some(OsStr::new(".dotnet")) {
        return target_path;
    }

    let Some(repo_root) = dotnet_dir.parent() else {
        return target_path;
    };

    let mut sdk_root = repo_root.to_path_buf();
    sdk_root.push(".dotnet");
    sdk_root.push("sdk");

    let full_argument = fs::canonicalize(argument).unwrap_or_else(|_| argument.to_path_buf());
    if !full_argument.starts_with(&sdk_root) {
        return target_path;
    }

    let mut testhost_dir = repo_root.to_path_buf();
    testhost_dir.push("artifacts");
    testhost_dir.push("bin");
    testhost_dir.push("testhost");
    if !testhost_dir.is_dir() {
        return target_path;
    }

    let dotnet_name = if cfg!(windows) {
        OsStr::new("dotnet.exe")
    } else {
        OsStr::new("dotnet")
    };

    let mut selected = target_path;

    if let Ok(entries) = fs::read_dir(&testhost_dir) {
        for entry in entries.flatten() {
            let mut candidate = entry.path();
            candidate.push(dotnet_name);
            if !candidate.is_file() {
                continue;
            }

            let is_release = candidate
                .components()
                .any(|c| {
                    c.as_os_str()
                        .to_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case("Release"))
                });
            selected = candidate;
            if is_release {
                return selected;
            }
        }
    }

    return selected;
}
