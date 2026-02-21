use std::ffi::OsString;
use std::path::Path;
use std::process;

use crate::logger;

#[cfg(unix)]
pub fn run(dotnet_path: &Path, args: &[OsString]) -> ! {
    use std::os::unix::process::CommandExt;

    logger::run(dotnet_path, args);
    let err = process::Command::new(dotnet_path).args(args).exec();
    eprintln!(
        "[dotnet-muxer] Failed to execute {}: {}",
        dotnet_path.display(),
        err
    );
    process::exit(3);
}

#[cfg(not(unix))]
pub fn run(dotnet_path: &Path, args: &[OsString]) -> ! {
    let exit_code = match process::Command::new(dotnet_path).args(args).status() {
        Ok(status) => status.code().unwrap_or(2),
        Err(error) => {
            eprintln!(
                "[dotnet-muxer] Failed to execute {}: {}",
                dotnet_path.display(),
                error
            );
            3
        }
    };

    logger::run(dotnet_path, args);
    process::exit(exit_code);
}
