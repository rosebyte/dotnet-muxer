use std::env;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
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
    write_field(&mut line, "args", &args_text);
    write_field(&mut line, "target", &target_path.display().to_string());
    write_field(&mut line, "cwd", &cwd);
    write_field(
        &mut line,
        "process",
        &format!("({}) {process_text}", process::id()),
    );
    write_parent_fields(&mut line, process::id());
    write_field(&mut line, "ts", &timestamp());
    line.push('\n');

    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = file.write_all(line.as_bytes());
    }
}

#[cfg(target_os = "linux")]
fn write_parent_fields(line: &mut String, start_pid: u32) {
    let mut visited = HashSet::new();
    let mut pid = start_pid;
    let mut wrote_any = false;

    while pid != 0 {
        if !visited.insert(pid) {
            break;
        }

        let Some((parent_pid, parent_name)) = parent_of_linux(pid) else {
            break;
        };

        write_field(line, "parent", &format!("({parent_pid}) {parent_name}"));
        wrote_any = true;
        pid = parent_pid;
    }

    if !wrote_any {
        write_field(line, "parent", &format!("(0) {UNKNOWN}"));
    }
}

#[cfg(target_os = "linux")]
fn parent_of_linux(pid: u32) -> Option<(u32, String)> {
    let status_path = format!("/proc/{pid}/status");
    let status = fs::read_to_string(status_path).ok()?;

    let mut parent_pid = 0u32;
    for line in status.lines() {
        if let Some(raw) = line.strip_prefix("PPid:") {
            parent_pid = raw.trim().parse::<u32>().ok()?;
            break;
        }
    }

    if parent_pid == 0 || parent_pid == pid {
        return None;
    }

    let comm_path = format!("/proc/{parent_pid}/comm");
    let parent_name = fs::read_to_string(comm_path)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| UNKNOWN.to_string());

    Some((parent_pid, parent_name))
}

#[cfg(target_os = "macos")]
fn write_parent_fields(line: &mut String, start_pid: u32) {
    let mut visited = HashSet::new();
    let mut pid = start_pid;
    let mut wrote_any = false;

    while pid != 0 {
        if !visited.insert(pid) {
            break;
        }

        let Some((parent_pid, parent_name)) = parent_of_macos(pid) else {
            break;
        };

        write_field(line, "parent", &format!("({parent_pid}) {parent_name}"));
        wrote_any = true;
        pid = parent_pid;
    }

    if !wrote_any {
        write_field(line, "parent", &format!("(0) {UNKNOWN}"));
    }
}

#[cfg(target_os = "macos")]
fn parent_of_macos(pid: u32) -> Option<(u32, String)> {
    use std::ffi::{CStr, c_void};
    use std::os::raw::{c_char, c_int, c_uint, c_ulong};

    const PROC_PIDT_BSDINFO: c_int = 3;
    const BSD_INFO_BUFFER_SIZE: c_int = 256;

    unsafe extern "C" {
        fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: c_ulong,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;

        fn proc_name(pid: c_int, buffer: *mut c_void, buffersize: c_uint) -> c_int;
    }

    let mut bsd_info = [0u8; BSD_INFO_BUFFER_SIZE as usize];
    let result = unsafe {
        proc_pidinfo(
            pid as c_int,
            PROC_PIDT_BSDINFO,
            0,
            bsd_info.as_mut_ptr() as *mut c_void,
            BSD_INFO_BUFFER_SIZE,
        )
    };

    if result <= 20 {
        return None;
    }

    let parent_pid = i32::from_ne_bytes([bsd_info[16], bsd_info[17], bsd_info[18], bsd_info[19]]) as u32;
    if parent_pid == 0 || parent_pid == pid {
        return None;
    }

    let mut name_buf = [0i8; 1024];
    let name_len = unsafe {
        proc_name(
            parent_pid as c_int,
            name_buf.as_mut_ptr() as *mut c_void,
            name_buf.len() as c_uint,
        )
    };

    let parent_name = if name_len > 0 {
        let cstr = unsafe { CStr::from_ptr(name_buf.as_ptr() as *const c_char) };
        let value = cstr.to_string_lossy().trim().to_string();
        if value.is_empty() {
            UNKNOWN.to_string()
        } else {
            value
        }
    } else {
        UNKNOWN.to_string()
    };

    Some((parent_pid, parent_name))
}

#[cfg(windows)]
fn write_parent_fields(line: &mut String, start_pid: u32) {
    let mut visited = HashSet::new();
    let mut pid = start_pid;
    let mut wrote_any = false;

    while pid != 0 {
        if !visited.insert(pid) {
            break;
        }

        let Some((parent_pid, parent_name)) = parent_of_windows(pid) else {
            break;
        };

        write_field(line, "parent", &format!("({parent_pid}) {parent_name}"));
        wrote_any = true;
        pid = parent_pid;
    }

    if !wrote_any {
        write_field(line, "parent", &format!("(0) {UNKNOWN}"));
    }
}

#[cfg(windows)]
fn parent_of_windows(pid: u32) -> Option<(u32, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { std::mem::zeroed() }
    };

    let mut parent_pid = 0u32;
    let mut found = false;

    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            if entry.th32ProcessID == pid {
                parent_pid = entry.th32ParentProcessID;
                found = true;
                break;
            }
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    if !found || parent_pid == 0 || parent_pid == pid {
        unsafe {
            CloseHandle(snapshot);
        }
        return None;
    }

    let mut parent_name = UNKNOWN.to_string();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            if entry.th32ProcessID == parent_pid {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|c| *c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let value = String::from_utf16_lossy(&entry.szExeFile[..len]).trim().to_string();
                if !value.is_empty() {
                    parent_name = value;
                }
                break;
            }
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe {
        CloseHandle(snapshot);
    }
    Some((parent_pid, parent_name))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn write_parent_fields(line: &mut String, _start_pid: u32) {
    write_field(line, "parent", &format!("(0) {UNKNOWN}"));
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
