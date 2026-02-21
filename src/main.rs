mod dispatch;
mod logger;
mod resolver;

use std::env;
use std::ffi::OsString;

fn main() {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let target_path = resolver::resolve_dispatch_target(&args);
    dispatch::run(&target_path, &args);
}
