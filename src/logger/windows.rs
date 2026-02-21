use std::collections::HashSet;

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

use crate::logger::{write_field, UNKNOWN};

pub(crate) fn write_parent_fields(line: &mut String, start_pid: u32) {
    let mut visited = HashSet::new();
    let mut pid = start_pid;
    let mut wrote_any = false;

    while pid != 0 {
        if !visited.insert(pid) {
            break;
        }

        let Some((parent_pid, parent_name)) = parent_of(pid) else {
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

fn parent_of(pid: u32) -> Option<(u32, String)> {
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
