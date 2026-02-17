// dotnet-muxer: A smart dispatcher that routes dotnet invocations to the right
// runtime/SDK based on context (repo-local preview SDK, testhost, or system dotnet).
//
// Dispatch priority:
//   1. Testhost — if args reference a testhost .dll, use the repo's built testhost
//   2. Local SDK — walk up from cwd (or VSCode workspace) looking for .dotnet/dotnet
//   3. System — next dotnet found in PATH
//
// Build:   cargo build --release
// Install: place target/release/dotnet in ~/bin/ (early in $PATH)

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

fn verbose(msg: &str) {
    if VERBOSE.load(Ordering::Relaxed) {
        eprintln!("[dotnet-muxer] {msg}");
    }
}

// ---------------------------------------------------------------------------
// JSON helpers (minimal, no dependency)
// ---------------------------------------------------------------------------

/// Extract a string value for a given key from a flat-ish JSON object.
/// Handles simple cases like: "key": "value"
fn json_get_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let pos = json.find(&needle)?;
    let rest = &json[pos + needle.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ---------------------------------------------------------------------------
// Platform constants
// ---------------------------------------------------------------------------

fn os_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "osx"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

fn arch_name() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else {
        "unknown"
    }
}

fn path_separator() -> char {
    if cfg!(windows) { ';' } else { ':' }
}

// ---------------------------------------------------------------------------
// Repo detection (global.json with allowPrerelease)
// ---------------------------------------------------------------------------

struct RepoInfo {
    root: PathBuf,
    sdk_version: String,
    tfm: String,
}

/// Derive TFM from SDK version string: "11.0.100-alpha.1..." → "net11.0"
fn derive_tfm(sdk_version: &str) -> Option<String> {
    let major = &sdk_version[..sdk_version.find('.')?];
    Some(format!("net{major}.0"))
}

fn try_parse_repo(root: PathBuf) -> Option<RepoInfo> {
    let content = fs::read_to_string(root.join("global.json")).ok()?;
    if !content.contains("\"allowPrerelease\"") {
        return None;
    }
    let version = json_get_string(&content, "version")?;
    let tfm = derive_tfm(&version)?;
    Some(RepoInfo { root, sdk_version: version, tfm })
}

fn find_repo_root() -> Option<RepoInfo> {
    // Allow override via environment
    if let Ok(root) = env::var("DOTNET_MUXER_REPO_ROOT") {
        if !root.is_empty() {
            if let Some(info) = try_parse_repo(PathBuf::from(&root)) {
                return Some(info);
            }
        }
    }

    // Walk up from cwd
    let mut dir = env::current_dir().ok()?;
    loop {
        if dir.join("global.json").exists() {
            if let Some(info) = try_parse_repo(dir.clone()) {
                return Some(info);
            }
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Testhost detection
// ---------------------------------------------------------------------------

fn is_testhost_invocation(args: &[String]) -> bool {
    args.iter()
        .skip(1)
        .any(|arg| arg.contains("testhost") && arg.contains(".dll"))
}

fn find_testhost_dotnet(repo: &RepoInfo) -> Option<PathBuf> {
    let os = os_name();
    let arch = arch_name();

    let configs: Vec<String> = match env::var("DOTNET_MUXER_CONFIG") {
        Ok(c) if !c.is_empty() => vec![c],
        _ => vec!["Debug".into(), "Release".into(), "Checked".into()],
    };

    for config in &configs {
        // e.g. artifacts/bin/testhost/net11.0-osx-Debug-arm64/dotnet
        let candidate = repo.root
            .join("artifacts/bin/testhost")
            .join(format!("{}-{os}-{config}-{arch}", repo.tfm))
            .join("dotnet");
        if candidate.exists() {
            verbose(&format!("Found testhost: {}", candidate.display()));
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Local .dotnet/dotnet discovery
// ---------------------------------------------------------------------------

/// Walk up from `start` looking for a `.dotnet/dotnet` executable.
fn find_dotnet_from(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(".dotnet/dotnet");
        if candidate.is_file() {
            verbose(&format!("Found local .dotnet/dotnet: {}", candidate.display()));
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Try cwd first, then fall back to VSCode sibling-process discovery.
fn find_local_dotnet() -> Option<PathBuf> {
    if let Ok(cwd) = env::current_dir() {
        if let Some(dotnet) = find_dotnet_from(&cwd) {
            return Some(dotnet);
        }
    }

    // When spawned by a VSCode extension the cwd is typically "/".
    // Discover the workspace folder by inspecting sibling processes' cwds.
    if env::var_os("VSCODE_CWD").is_some() {
        verbose("VSCode detected, probing sibling process cwds");
        if let Some(workspace) = vscode::find_workspace_from_siblings() {
            verbose(&format!("Workspace via sibling: {}", workspace.display()));
            if let Some(dotnet) = find_dotnet_from(&workspace) {
                return Some(dotnet);
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// PATH scanning
// ---------------------------------------------------------------------------

fn find_next_dotnet_in_path() -> Option<PathBuf> {
    let self_path = env::current_exe()
        .ok()
        .and_then(|p| fs::canonicalize(p).ok());

    for dir in env::var("PATH").ok()?.split(path_separator()) {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join("dotnet");
        if candidate.is_file() {
            if let Ok(resolved) = fs::canonicalize(&candidate) {
                if self_path.as_ref() != Some(&resolved) {
                    verbose(&format!("Next dotnet in PATH: {}", resolved.display()));
                    return Some(resolved);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn exec_dotnet(dotnet_path: &Path, args: &[String]) -> ! {
    use std::os::unix::process::CommandExt;
    verbose(&format!("Dispatching to: {}", dotnet_path.display()));
    let err = process::Command::new(dotnet_path)
        .args(&args[1..])
        .exec();
    eprintln!("[dotnet-muxer] Failed to exec {}: {err}", dotnet_path.display());
    process::exit(127);
}

#[cfg(not(unix))]
fn exec_dotnet(dotnet_path: &Path, args: &[String]) -> ! {
    verbose(&format!("Dispatching to: {}", dotnet_path.display()));
    match process::Command::new(dotnet_path).args(&args[1..]).status() {
        Ok(s) => process::exit(s.code().unwrap_or(127)),
        Err(e) => {
            eprintln!("[dotnet-muxer] Failed to exec {}: {e}", dotnet_path.display());
            process::exit(127);
        }
    }
}

// ---------------------------------------------------------------------------
// VSCode workspace discovery via sibling process cwds
// ---------------------------------------------------------------------------

mod vscode {
    use super::verbose;
    use std::env;
    use std::path::PathBuf;

    /// A cwd is useful if it isn't a root dir or a VSCode-internal path.
    fn is_useful_cwd(path: &std::path::Path) -> bool {
        let s = path.to_string_lossy();
        if s == "/" || s == "\\" || (s.len() <= 3 && s.ends_with(":\\")) {
            return false;
        }
        if s.contains(".vscode") || s.contains("Visual Studio Code") || s.contains("VSCode") {
            return false;
        }
        true
    }

    /// Walk up the parent-PID chain, inspecting sibling processes' cwds.
    pub fn find_workspace_from_siblings() -> Option<PathBuf> {
        let vscode_pid: u32 = env::var("VSCODE_PID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut pid = platform::getpid();

        // Log the full parent chain for diagnostics
        verbose("Process ancestor chain:");
        {
            let mut p = pid;
            loop {
                let name = platform::get_name_of(p).unwrap_or_default();
                let cwd = platform::get_cwd_of(p)
                    .map(|c| c.to_string_lossy().to_string())
                    .unwrap_or_else(|| "?".into());
                verbose(&format!("  PID {p}: {name} (cwd: {cwd})"));
                match platform::getppid_of(p) {
                    Some(parent) if parent > 1 && parent != p => p = parent,
                    _ => break,
                }
            }
        }

        for _ in 0..10 {
            let parent = platform::getppid_of(pid)?;
            if parent <= 1 {
                break;
            }

            for child in platform::list_children(parent) {
                if child == pid {
                    continue;
                }
                if let Some(cwd) = platform::get_cwd_of(child) {
                    if is_useful_cwd(&cwd) {
                        verbose(&format!("Sibling PID {child} cwd: {}", cwd.display()));
                        return Some(cwd);
                    }
                }
            }

            if parent == vscode_pid {
                break;
            }
            pid = parent;
        }
        None
    }

    // --- Platform-specific process introspection -------------------------

    #[cfg(target_os = "macos")]
    mod platform {
        use std::path::PathBuf;

        const PROC_PIDVNODEPATHINFO: i32 = 9;
        const MAXPATHLEN: usize = 1024;

        #[repr(C)]
        struct VnodeInfoPath {
            _vi: [u8; 152], // struct vnode_info
            vip_path: [u8; MAXPATHLEN],
        }

        #[repr(C)]
        struct ProcVnodePathInfo {
            pvi_cdir: VnodeInfoPath,
            _pvi_rdir: VnodeInfoPath,
        }

        extern "C" {
            fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buf: *mut u8, sz: i32) -> i32;
            fn proc_listchildpids(ppid: i32, buf: *mut i32, sz: i32) -> i32;
            fn proc_name(pid: i32, buf: *mut u8, sz: u32) -> i32;
            fn sysctl(name: *const i32, namelen: u32, oldp: *mut u8, oldlenp: *mut usize,
                      newp: *const u8, newlen: usize) -> i32;
        }

        pub fn getpid() -> u32 {
            std::process::id()
        }

        pub fn get_name_of(pid: u32) -> Option<String> {
            let mut buf = [0u8; 256];
            let ret = unsafe { proc_name(pid as i32, buf.as_mut_ptr(), buf.len() as u32) };
            if ret <= 0 { return None; }
            let len = buf.iter().position(|&b| b == 0).unwrap_or(ret as usize);
            std::str::from_utf8(&buf[..len]).ok().map(|s| s.to_string())
        }

        pub fn getppid_of(pid: u32) -> Option<u32> {
            // kp_eproc.e_ppid sits at byte offset 560 in struct kinfo_proc (648 bytes)
            let mut buf = [0u8; 648];
            let mut size = buf.len();
            let mib = [1i32 /*CTL_KERN*/, 14 /*KERN_PROC*/, 1 /*KERN_PROC_PID*/, pid as i32];
            let ret = unsafe {
                sysctl(mib.as_ptr(), 4, buf.as_mut_ptr(), &mut size, std::ptr::null(), 0)
            };
            if ret != 0 || size < 564 {
                return None;
            }
            Some(i32::from_ne_bytes([buf[560], buf[561], buf[562], buf[563]]) as u32)
        }

        pub fn list_children(pid: u32) -> Vec<u32> {
            // proc_listchildpids returns the number of PIDs, not bytes.
            let count = unsafe { proc_listchildpids(pid as i32, std::ptr::null_mut(), 0) };
            if count <= 0 {
                return Vec::new();
            }
            let mut buf = vec![0i32; count as usize];
            let actual = unsafe {
                proc_listchildpids(
                    pid as i32, buf.as_mut_ptr(),
                    (buf.len() * std::mem::size_of::<i32>()) as i32,
                )
            };
            if actual <= 0 {
                return Vec::new();
            }
            buf.truncate(actual as usize);
            buf.into_iter().map(|p| p as u32).collect()
        }

        pub fn get_cwd_of(pid: u32) -> Option<PathBuf> {
            let mut info = unsafe { std::mem::zeroed::<ProcVnodePathInfo>() };
            let ret = unsafe {
                proc_pidinfo(
                    pid as i32, PROC_PIDVNODEPATHINFO, 0,
                    &mut info as *mut _ as *mut u8,
                    std::mem::size_of::<ProcVnodePathInfo>() as i32,
                )
            };
            if ret <= 0 {
                return None;
            }
            let bytes = &info.pvi_cdir.vip_path;
            let len = bytes.iter().position(|&b| b == 0).unwrap_or(MAXPATHLEN);
            let s = std::str::from_utf8(&bytes[..len]).ok()?;
            if s.is_empty() { None } else { Some(PathBuf::from(s)) }
        }
    }

    #[cfg(target_os = "linux")]
    mod platform {
        use std::fs;
        use std::path::PathBuf;

        pub fn getpid() -> u32 {
            std::process::id()
        }

        pub fn get_name_of(pid: u32) -> Option<String> {
            fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|s| s.trim().to_string())
        }

        pub fn getppid_of(pid: u32) -> Option<u32> {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // Format: pid (comm) state ppid ...
            // comm may contain spaces/parens, so find the last ')' first.
            let rest = &stat[stat.rfind(')')? + 1..];
            rest.split_whitespace().nth(1)?.parse().ok()
        }

        pub fn list_children(pid: u32) -> Vec<u32> {
            if let Ok(s) = fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
                return s.split_whitespace().filter_map(|t| t.parse().ok()).collect();
            }
            // Fallback: scan all /proc entries
            let mut out = Vec::new();
            if let Ok(entries) = fs::read_dir("/proc") {
                for e in entries.flatten() {
                    if let Ok(child) = e.file_name().to_string_lossy().parse::<u32>() {
                        if getppid_of(child) == Some(pid) {
                            out.push(child);
                        }
                    }
                }
            }
            out
        }

        pub fn get_cwd_of(pid: u32) -> Option<PathBuf> {
            fs::read_link(format!("/proc/{pid}/cwd")).ok()
        }
    }

    #[cfg(target_os = "windows")]
    mod platform {
        use std::path::PathBuf;

        type HANDLE = *mut std::ffi::c_void;
        const INVALID_HANDLE: HANDLE = -1isize as HANDLE;
        const TH32CS_SNAPPROCESS: u32 = 0x2;
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        const PROCESS_VM_READ: u32 = 0x0010;
        const MAX_PATH: usize = 260;

        #[repr(C)]
        #[allow(non_snake_case)]
        struct PROCESSENTRY32W {
            dwSize: u32, cntUsage: u32, th32ProcessID: u32,
            th32DefaultHeapID: usize, th32ModuleID: u32, cntThreads: u32,
            th32ParentProcessID: u32, pcPriClassBase: i32, dwFlags: u32,
            szExeFile: [u16; MAX_PATH],
        }

        #[repr(C)]
        #[allow(non_snake_case)]
        struct PROCESS_BASIC_INFORMATION {
            Reserved1: usize, PebBaseAddress: usize,
            Reserved2: [usize; 2], UniqueProcessId: usize, Reserved3: usize,
        }

        #[repr(C)]
        #[allow(non_snake_case)]
        struct UNICODE_STRING { Length: u16, MaximumLength: u16, Buffer: usize }

        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> HANDLE;
            fn CloseHandle(h: HANDLE) -> i32;
            fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> HANDLE;
            fn Process32FirstW(snap: HANDLE, entry: *mut PROCESSENTRY32W) -> i32;
            fn Process32NextW(snap: HANDLE, entry: *mut PROCESSENTRY32W) -> i32;
            fn ReadProcessMemory(proc_: HANDLE, addr: usize, buf: *mut u8,
                                 sz: usize, read: *mut usize) -> i32;
            fn NtQueryInformationProcess(proc_: HANDLE, class: u32, info: *mut u8,
                                         len: u32, ret_len: *mut u32) -> i32;
        }

        /// Iterate the toolhelp snapshot, calling `f` for each entry.
        /// Stops early if `f` returns `Some`.
        unsafe fn with_snapshot<T>(mut f: impl FnMut(&PROCESSENTRY32W) -> Option<T>) -> Option<T> {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE { return None; }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut result = None;
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    if let Some(v) = f(&entry) { result = Some(v); break; }
                    if Process32NextW(snap, &mut entry) == 0 { break; }
                }
            }
            CloseHandle(snap);
            result
        }

        pub fn getpid() -> u32 {
            std::process::id()
        }

        pub fn get_name_of(pid: u32) -> Option<String> {
            unsafe {
                with_snapshot(|e| {
                    if e.th32ProcessID == pid {
                        let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(MAX_PATH);
                        Some(String::from_utf16_lossy(&e.szExeFile[..len]))
                    } else {
                        None
                    }
                })
            }
        }

        pub fn getppid_of(pid: u32) -> Option<u32> {
            unsafe {
                with_snapshot(|e| {
                    if e.th32ProcessID == pid { Some(e.th32ParentProcessID) } else { None }
                })
            }
        }

        pub fn list_children(pid: u32) -> Vec<u32> {
            let mut out = Vec::new();
            unsafe {
                with_snapshot(|e| {
                    if e.th32ParentProcessID == pid { out.push(e.th32ProcessID); }
                    None::<()>
                });
            }
            out
        }

        pub fn get_cwd_of(pid: u32) -> Option<PathBuf> {
            unsafe {
                let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
                if h.is_null() { return None; }
                let result = read_cwd(h);
                CloseHandle(h);
                result
            }
        }

        unsafe fn read_remote<T: Copy>(handle: HANDLE, addr: usize) -> Option<T> {
            let mut val: T = std::mem::zeroed();
            let mut n = 0usize;
            if ReadProcessMemory(handle, addr, &mut val as *mut T as *mut u8,
                                 std::mem::size_of::<T>(), &mut n) == 0 { None }
            else { Some(val) }
        }

        unsafe fn read_cwd(handle: HANDLE) -> Option<PathBuf> {
            let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
            if NtQueryInformationProcess(
                handle, 0, &mut pbi as *mut _ as *mut u8,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            ) != 0 || pbi.PebBaseAddress == 0 { return None; }

            // PEB.ProcessParameters is at offset 0x20 (x64)
            let params_ptr: usize = read_remote(handle, pbi.PebBaseAddress + 0x20)?;
            // RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath at offset 0x38
            let dos_path: UNICODE_STRING = read_remote(handle, params_ptr + 0x38)?;
            if dos_path.Buffer == 0 || dos_path.Length == 0 { return None; }

            let len_chars = dos_path.Length as usize / 2;
            let mut buf = vec![0u16; len_chars];
            let mut n = 0usize;
            if ReadProcessMemory(handle, dos_path.Buffer, buf.as_mut_ptr() as *mut u8,
                                 dos_path.Length as usize, &mut n) == 0 { return None; }

            let path = String::from_utf16_lossy(&buf);
            let trimmed = path.trim_end_matches('\\');
            Some(PathBuf::from(if trimmed.len() >= 3 { trimmed } else { &path }))
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    VERBOSE.store(env::var_os("DOTNET_MUXER_VERBOSE").is_some(), Ordering::Relaxed);

    let args: Vec<String> = env::args().collect();
    verbose(&format!("args: {}", args.join(" ")));

    // Rule 1: Testhost invocation inside a recognized repo
    if is_testhost_invocation(&args) {
        if let Some(repo) = find_repo_root() {
            verbose(&format!("Repo: {} (SDK {})", repo.root.display(), repo.sdk_version));
            if let Some(testhost) = find_testhost_dotnet(&repo) {
                exec_dotnet(&testhost, &args);
            }
            verbose("Testhost not found, falling through");
        }
    }

    // Rule 2: Local .dotnet/dotnet (cwd walk, then VSCode sibling fallback)
    if let Some(local) = find_local_dotnet() {
        exec_dotnet(&local, &args);
    }
    verbose("No .dotnet/dotnet found, falling through");

    // Rule 3: Next dotnet in PATH
    if let Some(system) = find_next_dotnet_in_path() {
        exec_dotnet(&system, &args);
    }

    eprintln!("[dotnet-muxer] No dotnet found in PATH");
    process::exit(127);
}
