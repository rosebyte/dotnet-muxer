use crate::logger::{write_field, UNKNOWN};

pub(crate) fn write_parent_fields(line: &mut String, _start_pid: u32) {
    write_field(line, "parent", &format!("(0) {UNKNOWN}"));
}
