use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use directories::BaseDirs;

/// Names the application home, not a .NET SDK root.
pub const HOME_ENV: &str = "DOTNET_SDK_HOME";
/// Tells an extension which home it was discovered in.
pub const EXTENSION_HOME_ENV: &str = "MUXLET_HOME";

/// The application home: an explicit core `--home`, else a nonempty
/// `DOTNET_SDK_HOME`, else `muxlet` in the per-user data directory. A relative
/// path is made absolute against the current directory; nothing is read or
/// created.
pub fn resolve(explicit: Option<&OsStr>) -> Result<PathBuf> {
    if let Some(value) = explicit {
        return absolute_home(value);
    }
    if let Some(value) = env::var_os(HOME_ENV).filter(|value| !value.is_empty()) {
        return absolute_home(&value);
    }

    let directories = BaseDirs::new().context(
        "cannot determine the per-user application home; set DOTNET_SDK_HOME to a writable \
         directory",
    )?;
    absolute_home(directories.data_local_dir().join("muxlet").as_os_str())
}

fn absolute_home(value: &OsStr) -> Result<PathBuf> {
    if value.is_empty() {
        bail!("the application home must not be empty");
    }
    std::path::absolute(Path::new(value)).context("cannot resolve the absolute application home")
}

/// `<home>/configuration.json`.
pub fn configuration(home: &Path) -> PathBuf {
    home.join("configuration.json")
}
