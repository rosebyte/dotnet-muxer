use std::collections::HashSet;
use std::fs;

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

    return;
}

fn parent_of(pid: u32) -> Option<(u32, String)> {
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

    return Some((parent_pid, parent_name));
}
