mod dispatch;
mod logger;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

const DOTNET_MUXER_TARGET: &str = "DOTNET_MUXER_TARGET";

fn main() {
    let args: Vec<OsString> = env::args_os().collect();

    let target_path = match env::var_os(DOTNET_MUXER_TARGET) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => {
            eprintln!("[dotnet-muxer] {DOTNET_MUXER_TARGET} is not set");
            process::exit(1);
        }
    };

    if !target_path.is_file() {
        eprintln!(
            "[dotnet-muxer] DOTNET_MUXER_TARGET not found: {}",
            target_path.display()
        );
        process::exit(1);
    }

    let target_path = try_get_testhost_path(&args, target_path);
    dispatch::run(&target_path, &args);
}

fn try_get_testhost_path(args: &[OsString], target_path: PathBuf) -> PathBuf {
    if args.is_empty() || args.len() < 2 {
        return target_path;
    }

    let argument = PathBuf::from(&args[1]);
    let is_vstest = argument
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.eq_ignore_ascii_case("vstest.console.dll"))
        .unwrap_or(false);
    if !is_vstest {
        return target_path;
    }

    let Some(repo_root) = repo_root_from_target(&target_path) else {
        return target_path;
    };

    let sdk_root = repo_root.join(".dotnet").join("sdk");
    let full_argument = fs::canonicalize(&argument).unwrap_or(argument);
    if !full_argument.starts_with(&sdk_root) {
        return target_path;
    }

    let testhost_dir = repo_root.join("artifacts").join("bin").join("testhost");
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
            let candidate = entry.path().join(dotnet_name);
            if !candidate.is_file() {
                continue;
            }

            let is_release = candidate
                .components()
                .any(|c| c.as_os_str().to_string_lossy().eq_ignore_ascii_case("Release"));
            selected = candidate;
            if is_release {
                return selected;
            }
        }
    }

    selected
}

fn repo_root_from_target(target_path: &Path) -> Option<PathBuf> {
    let dotnet_dir = target_path.parent()?;
    if dotnet_dir.file_name()? != OsStr::new(".dotnet") {
        return None;
    }
    Some(dotnet_dir.parent()?.to_path_buf())
}
