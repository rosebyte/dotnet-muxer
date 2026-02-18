// dotnet-muxer: Routes dotnet invocations to the right runtime/SDK.
//
// Resolution order for the repo root:
//   1. DOTNET_MUXER_TARGET env var (repo root path)
//   2. ~/.dotnet-muxer/workspaces/ PID files written by the companion VSCode extension
//   3. Next dotnet in PATH (fallback)
//
// Once a repo root is found, the muxer uses <root>/.dotnet/dotnet and
// redirects testhost.dll invocations from the pinned SDK to the repo's
// locally-built testhost in <root>/artifacts/bin/testhost/.
//
// Build:   cargo build --release
// Install: place target/release/dotnet early in $PATH

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

// ---------------------------------------------------------------------------
// Workspace discovery via ~/.dotnet-muxer
// ---------------------------------------------------------------------------

/// Read ~/.dotnet-muxer.d/<pid> files and find a workspace whose PID is an ancestor of us.
fn find_workspace(verbose_enabled: bool) -> Option<PathBuf> {
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .ok()?;
    let dir = PathBuf::from(home).join(".dotnet-muxer/workspaces");

    // Read all PID files into (pid, workspace) pairs
    let entries: Vec<(u32, PathBuf)> = fs::read_dir(&dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let pid: u32 = e.file_name().to_string_lossy().parse().ok()?;
            let workspace = fs::read_to_string(e.path()).ok()?;
            Some((pid, PathBuf::from(workspace.trim())))
        })
        .collect();

    if entries.is_empty() {
        return None;
    }

    // Walk parent PID chain looking for a match
    let mut pid = std::process::id();
    for _ in 0..20 {
        for (entry_pid, workspace) in &entries {
            if *entry_pid == pid {
                verbose(verbose_enabled, &format!(
                    "Matched PID {pid} → {}", workspace.display()
                ));
                return Some(workspace.clone());
            }
        }
        match platform::getppid_of(pid) {
            Some(parent) if parent > 1 && parent != pid => pid = parent,
            _ => break,
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Platform-specific parent PID lookup
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    extern "C" {
        fn sysctl(name: *const i32, namelen: u32, oldp: *mut u8, oldlenp: *mut usize,
                  newp: *const u8, newlen: usize) -> i32;
    }

    pub fn getppid_of(pid: u32) -> Option<u32> {
        let mut buf = [0u8; 648];
        let mut size = buf.len();
        let mib = [1i32, 14, 1, pid as i32];
        let ret = unsafe {
            sysctl(mib.as_ptr(), 4, buf.as_mut_ptr(), &mut size, std::ptr::null(), 0)
        };
        if ret != 0 || size < 564 { return None; }
        Some(i32::from_ne_bytes([buf[560], buf[561], buf[562], buf[563]]) as u32)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    pub fn getppid_of(pid: u32) -> Option<u32> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = &stat[stat.rfind(')')? + 1..];
        rest.split_whitespace().nth(1)?.parse().ok()
    }
}

#[cfg(target_os = "windows")]
mod platform {
    type HANDLE = *mut std::ffi::c_void;
    const TH32CS_SNAPPROCESS: u32 = 0x2;
    const MAX_PATH: usize = 260;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct PROCESSENTRY32W {
        dwSize: u32, cntUsage: u32, th32ProcessID: u32,
        th32DefaultHeapID: usize, th32ModuleID: u32, cntThreads: u32,
        th32ParentProcessID: u32, pcPriClassBase: i32, dwFlags: u32,
        szExeFile: [u16; MAX_PATH],
    }

    extern "system" {
        fn CloseHandle(h: HANDLE) -> i32;
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> HANDLE;
        fn Process32FirstW(snap: HANDLE, entry: *mut PROCESSENTRY32W) -> i32;
        fn Process32NextW(snap: HANDLE, entry: *mut PROCESSENTRY32W) -> i32;
    }

    pub fn getppid_of(pid: u32) -> Option<u32> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == (-1isize as HANDLE) { return None; }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut result = None;
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    if entry.th32ProcessID == pid {
                        result = Some(entry.th32ParentProcessID);
                        break;
                    }
                    if Process32NextW(snap, &mut entry) == 0 { break; }
                }
            }
            CloseHandle(snap);
            result
        }
    }
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
            .map(|n| n.eq_ignore_ascii_case("testhost.dll"))
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
        let candidate = entry.path().join("dotnet");
        if !candidate.is_file() { continue; }
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
        let candidate = dir.join("dotnet");
        if !candidate.is_file() { continue; }
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
fn exec_dotnet(dotnet_path: &Path, args: &[String], verbose_enabled: bool) -> ! {
    use std::os::unix::process::CommandExt;
    verbose(verbose_enabled, &format!("Dispatching to: {}", dotnet_path.display()));
    let err = process::Command::new(dotnet_path).args(&args[1..]).exec();
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

    // Resolve repo root: env var first, then ~/.dotnet-muxer.d/ PID files
    let repo_root = env::var("DOTNET_MUXER_TARGET")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| {
            verbose(verbose_enabled, &format!("DOTNET_MUXER_TARGET={v}"));
            PathBuf::from(v)
        })
        .or_else(|| find_workspace(verbose_enabled));

    if let Some(repo_root) = repo_root {
        let dotnet_dir = repo_root.join(".dotnet");
        let target_path = dotnet_dir.join("dotnet");

        if target_path.is_file() {
            // Testhost redirection
            if is_testhost_from_sdk(&args, &dotnet_dir) {
                if let Some(testhost) = find_testhost_dotnet(&repo_root) {
                    verbose(verbose_enabled, &format!("Found testhost: {}", testhost.display()));
                    exec_dotnet(&testhost, &args, verbose_enabled);
                }
                verbose(verbose_enabled, "Testhost not found, falling through to target");
            }

            exec_dotnet(&target_path, &args, verbose_enabled);
        }
        verbose(verbose_enabled, &format!("{} not found", target_path.display()));
    }

    // Fallback to next dotnet in PATH
    if let Some(next) = find_next_dotnet_in_path() {
        exec_dotnet(&next, &args, verbose_enabled);
    }

    muxer_eprintln("No workspace in ~/.dotnet-muxer/workspaces/ and no dotnet found in PATH");
    process::exit(127);
}
