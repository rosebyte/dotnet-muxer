// dotnet-muxer: Routes dotnet invocations to the right runtime/SDK.
//
// Uses DOTNET_MUXER_TARGET env var as the repo root (e.g. /repo).
// The dotnet executable is expected at $DOTNET_MUXER_TARGET/.dotnet/dotnet.
// If DOTNET_MUXER_TARGET is missing or empty, delegates directly to the
// next dotnet found on PATH.
// When a testhost.dll from the pinned SDK is invoked, redirects to the
// repo's locally-built testhost instead.
//
// Build:   cargo build --release
// Install: place target/release/dotnet early in $PATH
// Config:  export DOTNET_MUXER_TARGET=/path/to/dotnet-runtime

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

fn muxer_eprintln(msg: &str) {
    for line in msg.lines() {
        eprintln!("[dotnet-muxer] {line}");
    }
}

fn verbose(verbose_enabled: bool, msg: &str) {
    if verbose_enabled {
        muxer_eprintln(msg);
    }
}

fn find_next_dotnet_in_path() -> Option<PathBuf> {
    let current_exe = env::current_exe()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok());

    let path_var = env::var_os("PATH")?;

    for dir in env::split_paths(&path_var) {
        let candidate = dir.join("dotnet");

        if !candidate.is_file() {
            continue;
        }

        if let Some(current_exe) = &current_exe {
            if let Ok(candidate_canonical) = fs::canonicalize(&candidate) {
                if candidate_canonical == *current_exe {
                    continue;
                }
            }
        }

        return Some(candidate);
    }

    None
}

// ---------------------------------------------------------------------------
// Testhost detection
// ---------------------------------------------------------------------------

/// Check if any arg matches <sdk_dir>/sdk/<version>/testhost.dll.
fn is_testhost_from_sdk(args: &[String], sdk_dir: &Path) -> bool {
    let sdk_root = sdk_dir.join("sdk");

    for arg in args.iter().skip(1) {
        let path = Path::new(arg);

        let is_testhost = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.eq_ignore_ascii_case("testhost.dll"))
            .unwrap_or(false);

        if !is_testhost {
            continue;
        }

        let Some(version_dir) = path.parent() else {
            continue;
        };

        let Some(sdk_parent) = version_dir.parent() else {
            continue;
        };

        if sdk_parent == sdk_root {
            return true;
        }
    }

    false
}

/// Look for <repo>/artifacts/bin/testhost/*/dotnet.
/// Prefers Release builds when multiple configs exist.
fn find_testhost_dotnet(repo_root: &Path) -> Option<PathBuf> {
    let testhost_dir = repo_root.join("artifacts/bin/testhost");
    let mut fallback: Option<PathBuf> = None;

    for entry in fs::read_dir(&testhost_dir).ok()?.flatten() {
        let candidate = entry.path().join("dotnet");

        if !candidate.is_file() {
            continue;
        }

        if fallback.is_none() {
            fallback = Some(candidate.clone());
        }

        if candidate
            .components()
            .any(|component| component.as_os_str() == "Release")
        {
            return Some(candidate);
        }
    }

    fallback
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn exec_dotnet(dotnet_path: &Path, args: &[String], verbose_enabled: bool) -> ! {
    use std::os::unix::process::CommandExt;
    verbose(verbose_enabled, &format!("Dispatching to: {}", dotnet_path.display()));
    let err = process::Command::new(dotnet_path)
        .args(&args[1..])
        .exec();
    muxer_eprintln(&format!("Failed to exec {}: {err}", dotnet_path.display()));
    process::exit(127);
}

#[cfg(not(unix))]
fn exec_dotnet(dotnet_path: &Path, args: &[String], verbose_enabled: bool) -> ! {
    verbose(verbose_enabled, &format!("Dispatching to: {}", dotnet_path.display()));
    match process::Command::new(dotnet_path).args(&args[1..]).status() {
        Ok(s) => process::exit(s.code().unwrap_or(127)),
        Err(e) => {
            muxer_eprintln(&format!("Failed to exec {}: {e}", dotnet_path.display()));
            process::exit(127);
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let verbose_enabled = env::var_os("DOTNET_MUXER_VERBOSE").is_some();

    let args: Vec<String> = env::args().collect();
    verbose(verbose_enabled, &format!("args: {}", args.join(" ")));

    let repo_root = match env::var("DOTNET_MUXER_TARGET") {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value),
        _ => {
            verbose(
                verbose_enabled,
                "DOTNET_MUXER_TARGET is missing/empty, delegating to next dotnet on PATH",
            );

            if let Some(next_dotnet) = find_next_dotnet_in_path() {
                exec_dotnet(&next_dotnet, &args, verbose_enabled);
            }

            let path_value = env::var_os("PATH")
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<unset>".to_string());
            muxer_eprintln(&format!(
                "DOTNET_MUXER_TARGET is missing/empty and no fallback dotnet was found on PATH={path_value}"
            ));
            process::exit(127);
        }
    };

    let target_path = repo_root.join(".dotnet/dotnet");
    let dotnet_dir = repo_root.join(".dotnet");

    // If a testhost.dll from the pinned SDK is being invoked,
    // redirect to the repo's built testhost instead.
    if is_testhost_from_sdk(&args, &dotnet_dir) {
        if let Some(testhost) = find_testhost_dotnet(&repo_root) {
            verbose(verbose_enabled, &format!("Found testhost: {}", testhost.display()));
            exec_dotnet(&testhost, &args, verbose_enabled);
        }

        verbose(verbose_enabled, "Testhost not found, falling through to target");
    }

    exec_dotnet(&target_path, &args, verbose_enabled);
}
