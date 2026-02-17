// dotnet-muxer: A smart dispatcher that routes dotnet invocations to the right
// runtime/SDK based on context (repo-local preview SDK, testhost, or system dotnet).
//
// Build:   cargo build --release
// Install: place target/release/dotnet in ~/bin/ (early in $PATH)

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

static mut VERBOSE: bool = false;

fn verbose(msg: &str) {
    // SAFETY: VERBOSE is only written once at startup before any threads.
    if unsafe { VERBOSE } {
        eprintln!("[dotnet-muxer] {msg}");
    }
}

// --- JSON helpers (minimal, no dependency) ---

fn read_file_to_string(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

/// Extract a string value for a given key from a flat-ish JSON object.
/// Handles simple cases like: "key": "value"
fn json_get_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let pos = json.find(&needle)?;
    let rest = &json[pos + needle.len()..];

    // Skip whitespace and colon
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?;
    let rest = rest.trim_start();

    // Expect opening quote
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// --- Platform detection ---

fn get_os_name() -> &'static str {
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

fn get_arch_name() -> &'static str {
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

// --- Repo detection ---

struct RepoInfo {
    root: PathBuf,
    sdk_version: String,
    tfm: String,
    #[allow(dead_code)]
    is_preview: bool,
}

/// Derive TFM from SDK version string: "11.0.100-alpha.1..." → "net11.0"
fn derive_tfm(sdk_version: &str) -> Option<String> {
    let dot = sdk_version.find('.')?;
    let major = &sdk_version[..dot];
    Some(format!("net{major}.0"))
}

fn parse_global_json(root: PathBuf, content: &str) -> Option<RepoInfo> {
    let version = json_get_string(content, "version")?;
    let tfm = derive_tfm(&version)?;
    let is_preview = content.contains("allowPrerelease");
    Some(RepoInfo {
        root,
        sdk_version: version,
        tfm,
        is_preview,
    })
}

fn find_repo_root() -> Option<RepoInfo> {
    // Allow override
    if let Ok(override_root) = env::var("DOTNET_MUXER_REPO_ROOT") {
        if !override_root.is_empty() {
            let root = PathBuf::from(&override_root);
            let gj = root.join("global.json");
            if let Some(content) = read_file_to_string(&gj) {
                if let Some(info) = parse_global_json(root, &content) {
                    return Some(info);
                }
            }
        }
    }

    // Walk up from cwd
    let mut dir = env::current_dir().ok()?;

    loop {
        let gj = dir.join("global.json");
        if gj.exists() {
            if let Some(content) = read_file_to_string(&gj) {
                // Only match repos with allowPrerelease (i.e., dotnet/runtime-style repos)
                if content.contains("\"allowPrerelease\"") {
                    if let Some(info) = parse_global_json(dir.clone(), &content) {
                        return Some(info);
                    }
                }
            }
        }

        match dir.parent() {
            Some(parent) if parent != dir => {
                dir = parent.to_path_buf();
            }
            _ => break,
        }
    }

    None
}

// --- Testhost detection ---

fn find_testhost_dotnet(repo: &RepoInfo) -> Option<PathBuf> {
    let os = get_os_name();
    let arch = get_arch_name();

    let configs_to_try: Vec<String> = if let Ok(config) = env::var("DOTNET_MUXER_CONFIG") {
        if !config.is_empty() {
            vec![config]
        } else {
            vec!["Debug".into(), "Release".into(), "Checked".into()]
        }
    } else {
        vec!["Debug".into(), "Release".into(), "Checked".into()]
    };

    for config in &configs_to_try {
        // e.g. artifacts/bin/testhost/net11.0-osx-Debug-arm64/dotnet
        let dirname = format!("{}-{os}-{config}-{arch}", repo.tfm);
        let candidate = repo
            .root
            .join("artifacts")
            .join("bin")
            .join("testhost")
            .join(&dirname)
            .join("dotnet");

        if candidate.exists() {
            verbose(&format!("Found testhost: {}", candidate.display()));
            return Some(candidate);
        }
    }

    None
}

/// Check if the invocation is a testhost exec
fn is_testhost_invocation(args: &[String]) -> bool {
    args.iter()
        .skip(1)
        .any(|arg| arg.contains("testhost") && arg.contains(".dll"))
}

// --- PATH scanning ---

fn find_self_path() -> Option<PathBuf> {
    env::current_exe().ok().and_then(|p| fs::canonicalize(p).ok())
}

fn find_next_dotnet_in_path() -> Option<PathBuf> {
    let self_resolved = find_self_path()
        .and_then(|p| fs::canonicalize(&p).ok())
        .map(|p| p.to_string_lossy().to_string());

    let path_env = env::var("PATH").ok()?;

    for dir in path_env.split(':') {
        if dir.is_empty() {
            continue;
        }

        let candidate = Path::new(dir).join("dotnet");
        if candidate.exists() && candidate.is_file() {
            if let Ok(resolved) = fs::canonicalize(&candidate) {
                let resolved_str = resolved.to_string_lossy().to_string();
                if self_resolved.as_deref() != Some(&resolved_str) {
                    verbose(&format!("Found next dotnet in PATH: {resolved_str}"));
                    return Some(resolved);
                }
            }
        }
    }

    None
}

// --- .dotnet discovery (walk up the tree) ---

fn find_dotnet_from(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(".dotnet").join("dotnet");
        if candidate.exists() && candidate.is_file() {
            verbose(&format!("Found local .dotnet/dotnet: {}", candidate.display()));
            return Some(candidate);
        }
        match dir.parent() {
            Some(parent) if parent != dir => {
                dir = parent.to_path_buf();
            }
            _ => break,
        }
    }
    None
}

fn find_local_dotnet() -> Option<PathBuf> {
    // First, try walking up from cwd (works for terminals and well-behaved spawners)
    if let Some(cwd) = env::current_dir().ok() {
        if let Some(dotnet) = find_dotnet_from(&cwd) {
            return Some(dotnet);
        }
    }

    // Fallback: if we're inside VSCode, discover workspace from sibling processes
    if env::var("VSCODE_CWD").is_ok() {
        verbose("VSCode detected, probing sibling process cwds");
        if let Some(workspace) = vscode::find_workspace_from_siblings() {
            verbose(&format!(
                "Found VSCode workspace via sibling: {}",
                workspace.display()
            ));
            if let Some(dotnet) = find_dotnet_from(&workspace) {
                return Some(dotnet);
            }
        }
    }

    None
}

// --- VSCode workspace discovery via sibling process cwds ---

mod vscode {
    use super::verbose;
    use std::env;
    use std::path::PathBuf;

    /// Check if a cwd path is useful (not root, not an extension dir, etc.)
    fn is_useful_cwd(path: &std::path::Path) -> bool {
        let s = path.to_string_lossy();

        // Skip root directories
        if s == "/" || s == "\\" || s.len() <= 3 && s.ends_with(":\\") {
            return false;
        }

        // Skip VSCode extension/internal paths
        if s.contains(".vscode") || s.contains("Visual Studio Code") || s.contains("VSCode") {
            return false;
        }

        true
    }

    /// Walk up parent PIDs, inspect siblings' cwds, return a useful workspace path.
    pub fn find_workspace_from_siblings() -> Option<PathBuf> {
        let vscode_pid: u32 = env::var("VSCODE_PID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut pid = platform::getpid();
        // Walk up at most 10 levels, stopping at VSCODE_PID
        for _ in 0..10 {
            let parent = platform::getppid_of(pid)?;
            if parent <= 1 {
                break;
            }

            // List children of this parent (our siblings) and check their cwds
            let children = platform::list_children(parent);
            for child in &children {
                if *child == pid {
                    continue;
                }
                if let Some(cwd) = platform::get_cwd_of(*child) {
                    if is_useful_cwd(&cwd) {
                        verbose(&format!(
                            "Sibling PID {} has useful cwd: {}",
                            child,
                            cwd.display()
                        ));
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

    // --- Platform-specific process introspection ---

    #[cfg(target_os = "macos")]
    mod platform {
        use std::path::PathBuf;

        // libproc constants
        const PROC_PIDVNODEPATHINFO: i32 = 9;
        const MAXPATHLEN: usize = 1024;

        #[repr(C)]
        struct VnodeInfo {
            _pad: [u8; 152], // struct vnode_info
        }

        #[repr(C)]
        struct VnodeInfoPath {
            _vi: VnodeInfo,
            vip_path: [u8; MAXPATHLEN],
        }

        #[repr(C)]
        struct ProcVnodePathInfo {
            pvi_cdir: VnodeInfoPath,
            _pvi_rdir: VnodeInfoPath,
        }

        extern "C" {
            fn proc_pidinfo(
                pid: i32,
                flavor: i32,
                arg: u64,
                buffer: *mut std::ffi::c_void,
                buffersize: i32,
            ) -> i32;
            fn proc_listchildpids(ppid: i32, buffer: *mut i32, buffersize: i32) -> i32;
        }

        pub fn getpid() -> u32 {
            std::process::id()
        }

        pub fn getppid_of(pid: u32) -> Option<u32> {
            // Use sysctl KERN_PROC to get parent PID
            use std::mem;

            #[repr(C)]
            #[allow(non_camel_case_types)]
            struct kinfo_proc {
                _data: [u8; 648], // sizeof(struct kinfo_proc) on macOS
            }

            const CTL_KERN: i32 = 1;
            const KERN_PROC: i32 = 14;
            const KERN_PROC_PID: i32 = 1;

            extern "C" {
                fn sysctl(
                    name: *const i32,
                    namelen: u32,
                    oldp: *mut std::ffi::c_void,
                    oldlenp: *mut usize,
                    newp: *const std::ffi::c_void,
                    newlen: usize,
                ) -> i32;
            }

            let mut info: kinfo_proc = unsafe { mem::zeroed() };
            let mut size = mem::size_of::<kinfo_proc>();
            let mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid as i32];

            let ret = unsafe {
                sysctl(
                    mib.as_ptr(),
                    4,
                    &mut info as *mut _ as *mut std::ffi::c_void,
                    &mut size,
                    std::ptr::null(),
                    0,
                )
            };

            if ret != 0 || size == 0 {
                return None;
            }

            // kp_eproc.e_ppid is at offset 560 on both x86_64 and arm64 macOS
            let bytes = unsafe {
                std::slice::from_raw_parts(&info as *const _ as *const u8, size)
            };
            if bytes.len() >= 564 {
                let ppid = i32::from_ne_bytes([bytes[560], bytes[561], bytes[562], bytes[563]]);
                Some(ppid as u32)
            } else {
                None
            }
        }

        pub fn list_children(pid: u32) -> Vec<u32> {
            // proc_listchildpids returns the number of PIDs (not bytes).
            // First call with null buffer to get count.
            let count =
                unsafe { proc_listchildpids(pid as i32, std::ptr::null_mut(), 0) };
            if count <= 0 {
                return Vec::new();
            }

            let mut buf = vec![0i32; count as usize];
            let actual = unsafe {
                proc_listchildpids(
                    pid as i32,
                    buf.as_mut_ptr(),
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
            let mut info: ProcVnodePathInfo = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                proc_pidinfo(
                    pid as i32,
                    PROC_PIDVNODEPATHINFO,
                    0,
                    &mut info as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of::<ProcVnodePathInfo>() as i32,
                )
            };

            if ret <= 0 {
                return None;
            }

            let path_bytes = &info.pvi_cdir.vip_path;
            let len = path_bytes.iter().position(|&b| b == 0).unwrap_or(MAXPATHLEN);
            let path_str = std::str::from_utf8(&path_bytes[..len]).ok()?;
            if path_str.is_empty() {
                return None;
            }
            Some(PathBuf::from(path_str))
        }
    }

    #[cfg(target_os = "linux")]
    mod platform {
        use std::fs;
        use std::path::PathBuf;

        pub fn getpid() -> u32 {
            std::process::id()
        }

        pub fn getppid_of(pid: u32) -> Option<u32> {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // Format: pid (comm) state ppid ...
            // comm can contain spaces/parens, so find last ')' first
            let after_comm = stat.rfind(')')? + 1;
            let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
            // fields[0] = state, fields[1] = ppid
            fields.get(1)?.parse().ok()
        }

        pub fn list_children(pid: u32) -> Vec<u32> {
            // Try /proc/{pid}/task/{pid}/children first (requires CONFIG_PROC_CHILDREN)
            if let Ok(content) =
                fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
            {
                return content
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
            }

            // Fallback: scan /proc for processes with matching ppid
            let mut children = Vec::new();
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if let Ok(child_pid) = name_str.parse::<u32>() {
                        if let Some(ppid) = getppid_of(child_pid) {
                            if ppid == pid {
                                children.push(child_pid);
                            }
                        }
                    }
                }
            }
            children
        }

        pub fn get_cwd_of(pid: u32) -> Option<PathBuf> {
            fs::read_link(format!("/proc/{pid}/cwd")).ok()
        }
    }

    #[cfg(target_os = "windows")]
    mod platform {
        use std::path::PathBuf;

        // Windows API types and constants
        type HANDLE = *mut std::ffi::c_void;
        type DWORD = u32;
        type BOOL = i32;

        const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;
        const PROCESS_VM_READ: DWORD = 0x0010;
        const TH32CS_SNAPPROCESS: DWORD = 0x00000002;
        const MAX_PATH: usize = 260;

        #[repr(C)]
        #[allow(non_snake_case)]
        struct PROCESSENTRY32W {
            dwSize: DWORD,
            cntUsage: DWORD,
            th32ProcessID: DWORD,
            th32DefaultHeapID: usize,
            th32ModuleID: DWORD,
            cntThreads: DWORD,
            th32ParentProcessID: DWORD,
            pcPriClassBase: i32,
            dwFlags: DWORD,
            szExeFile: [u16; MAX_PATH],
        }

        // NtQueryInformationProcess structures
        const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

        #[repr(C)]
        #[allow(non_snake_case)]
        struct PROCESS_BASIC_INFORMATION {
            Reserved1: *mut std::ffi::c_void,
            PebBaseAddress: *mut PEB,
            Reserved2: [*mut std::ffi::c_void; 2],
            UniqueProcessId: usize,
            Reserved3: *mut std::ffi::c_void,
        }

        #[repr(C)]
        #[allow(non_snake_case)]
        struct PEB {
            Reserved1: [u8; 2],
            BeingDebugged: u8,
            Reserved2: [u8; 1],
            Reserved3: [*mut std::ffi::c_void; 2],
            Ldr: *mut std::ffi::c_void,
            ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
        }

        #[repr(C)]
        #[allow(non_snake_case)]
        struct RTL_USER_PROCESS_PARAMETERS {
            Reserved1: [u8; 16],
            Reserved2: [*mut std::ffi::c_void; 10],
            ImagePathName: UNICODE_STRING,
            CommandLine: UNICODE_STRING,
        }

        #[repr(C)]
        #[allow(non_snake_case)]
        struct UNICODE_STRING {
            Length: u16,
            MaximumLength: u16,
            Buffer: *mut u16,
        }

        extern "system" {
            fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;
            fn CloseHandle(hObject: HANDLE) -> BOOL;
            fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE;
            fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
            fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
            fn ReadProcessMemory(
                hProcess: HANDLE,
                lpBaseAddress: *const std::ffi::c_void,
                lpBuffer: *mut std::ffi::c_void,
                nSize: usize,
                lpNumberOfBytesRead: *mut usize,
            ) -> BOOL;
        }

        // ntdll
        extern "system" {
            fn NtQueryInformationProcess(
                ProcessHandle: HANDLE,
                ProcessInformationClass: u32,
                ProcessInformation: *mut std::ffi::c_void,
                ProcessInformationLength: u32,
                ReturnLength: *mut u32,
            ) -> i32;
        }

        const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

        pub fn getpid() -> u32 {
            std::process::id()
        }

        pub fn getppid_of(pid: u32) -> Option<u32> {
            unsafe {
                let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if snap == INVALID_HANDLE_VALUE {
                    return None;
                }

                let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as DWORD;

                if Process32FirstW(snap, &mut entry) != 0 {
                    loop {
                        if entry.th32ProcessID == pid {
                            CloseHandle(snap);
                            return Some(entry.th32ParentProcessID);
                        }
                        if Process32NextW(snap, &mut entry) == 0 {
                            break;
                        }
                    }
                }
                CloseHandle(snap);
            }
            None
        }

        pub fn list_children(pid: u32) -> Vec<u32> {
            let mut children = Vec::new();
            unsafe {
                let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if snap == INVALID_HANDLE_VALUE {
                    return children;
                }

                let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as DWORD;

                if Process32FirstW(snap, &mut entry) != 0 {
                    loop {
                        if entry.th32ParentProcessID == pid {
                            children.push(entry.th32ProcessID);
                        }
                        if Process32NextW(snap, &mut entry) == 0 {
                            break;
                        }
                    }
                }
                CloseHandle(snap);
            }
            children
        }

        pub fn get_cwd_of(pid: u32) -> Option<PathBuf> {
            unsafe {
                let handle = OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                    0,
                    pid,
                );
                if handle.is_null() {
                    return None;
                }

                let result = read_process_cwd(handle);
                CloseHandle(handle);
                result
            }
        }

        unsafe fn read_process_cwd(handle: HANDLE) -> Option<PathBuf> {
            // Get PEB address via NtQueryInformationProcess
            let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
            let status = NtQueryInformationProcess(
                handle,
                PROCESS_BASIC_INFORMATION_CLASS,
                &mut pbi as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            if status != 0 || pbi.PebBaseAddress.is_null() {
                return None;
            }

            // Read PEB from target process
            let mut peb: PEB = std::mem::zeroed();
            let mut bytes_read: usize = 0;
            if ReadProcessMemory(
                handle,
                pbi.PebBaseAddress as *const std::ffi::c_void,
                &mut peb as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<PEB>(),
                &mut bytes_read,
            ) == 0
            {
                return None;
            }

            if peb.ProcessParameters.is_null() {
                return None;
            }

            // Read RTL_USER_PROCESS_PARAMETERS to get CurrentDirectory
            // CurrentDirectory is a CURDIR struct right after the fixed fields.
            // Offset of CurrentDirectory in RTL_USER_PROCESS_PARAMETERS: 0x38 (x64)
            // CURDIR = { UNICODE_STRING DosPath; HANDLE Handle; }
            let params_addr = peb.ProcessParameters as usize;
            let curdir_offset: usize = 0x38;

            let mut dos_path: UNICODE_STRING = std::mem::zeroed();
            if ReadProcessMemory(
                handle,
                (params_addr + curdir_offset) as *const std::ffi::c_void,
                &mut dos_path as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<UNICODE_STRING>(),
                &mut bytes_read,
            ) == 0
            {
                return None;
            }

            if dos_path.Buffer.is_null() || dos_path.Length == 0 {
                return None;
            }

            // Read the actual path string
            let len_chars = dos_path.Length as usize / 2;
            let mut buf = vec![0u16; len_chars];
            if ReadProcessMemory(
                handle,
                dos_path.Buffer as *const std::ffi::c_void,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                dos_path.Length as usize,
                &mut bytes_read,
            ) == 0
            {
                return None;
            }

            let path = String::from_utf16_lossy(&buf);
            // Remove trailing backslash if present (except for root like C:\)
            let trimmed = path.trim_end_matches('\\');
            if trimmed.len() >= 3 {
                Some(PathBuf::from(trimmed))
            } else {
                Some(PathBuf::from(&path))
            }
        }
    }
}

// --- Dispatch ---

#[cfg(unix)]
fn exec_dotnet(dotnet_path: &Path, args: &[String]) -> ! {
    use std::os::unix::process::CommandExt;

    verbose(&format!("Dispatching to: {}", dotnet_path.display()));

    let mut cmd = std::process::Command::new(dotnet_path);
    // Skip args[0] (our own name) and pass the rest
    for arg in args.iter().skip(1) {
        cmd.arg(arg);
    }

    // exec replaces the current process
    let err = cmd.exec();

    eprintln!(
        "[dotnet-muxer] Failed to exec {}: {err}",
        dotnet_path.display()
    );
    process::exit(127);
}

#[cfg(not(unix))]
fn exec_dotnet(dotnet_path: &Path, args: &[String]) -> ! {
    verbose(&format!("Dispatching to: {}", dotnet_path.display()));

    let status = std::process::Command::new(dotnet_path)
        .args(args.iter().skip(1))
        .status();

    match status {
        Ok(s) => process::exit(s.code().unwrap_or(127)),
        Err(e) => {
            eprintln!(
                "[dotnet-muxer] Failed to exec {}: {e}",
                dotnet_path.display()
            );
            process::exit(127);
        }
    }
}

fn main() {
    unsafe {
        VERBOSE = env::var("DOTNET_MUXER_VERBOSE").is_ok();
    }

    let args: Vec<String> = env::args().collect();

    if unsafe { VERBOSE } {
        eprintln!(
            "[dotnet-muxer] args: {}",
            args.iter()
                .map(|a| a.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    let repo = find_repo_root();

    if let Some(ref repo) = repo {
        verbose(&format!("Repo root: {}", repo.root.display()));
        verbose(&format!("SDK version: {}", repo.sdk_version));
        verbose(&format!("TFM: {}", repo.tfm));

        // Rule 1: Testhost invocation
        if is_testhost_invocation(&args) {
            if let Some(testhost) = find_testhost_dotnet(repo) {
                exec_dotnet(&testhost, &args);
            }
            verbose("Testhost not found, falling through");
        }

    }

    // Rule 2: Walk up from cwd looking for .dotnet/dotnet
    if let Some(local_dotnet) = find_local_dotnet() {
        exec_dotnet(&local_dotnet, &args);
    }
    verbose("No .dotnet/dotnet found up the tree, falling through");

    // Rule 3: Fallback to next dotnet in PATH
    if let Some(system_dotnet) = find_next_dotnet_in_path() {
        exec_dotnet(&system_dotnet, &args);
    }

    eprintln!("[dotnet-muxer] No dotnet found in PATH");
    process::exit(127);
}
