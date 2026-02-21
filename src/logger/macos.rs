use std::collections::HashSet;
use std::ffi::{CStr, c_void};
use std::os::raw::{c_char, c_int, c_uint, c_ulong};

use crate::logger::{write_field, UNKNOWN};

const PROC_PIDT_BSDINFO: c_int = 3;
const BSD_INFO_BUFFER_SIZE: c_int = 256;

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
