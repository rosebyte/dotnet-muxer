use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::executable::{self, DOTNET_FILE_NAME};

/// The genuine `dotnet` to forward to: a nonempty `DOTNET_ROOT` decides alone,
/// otherwise the first eligible PATH entry which is not a Muxlet dispatcher.
pub(crate) fn resolve() -> Result<PathBuf> {
    match env::var_os("DOTNET_ROOT").filter(|root| !root.is_empty()) {
        Some(root) => explicit_root(Path::new(&root)),
        None => search_path(),
    }
}

/// An invalid explicit selection is an error, never permission to search PATH.
fn explicit_root(root: &Path) -> Result<PathBuf> {
    if !root.is_absolute() {
        bail!("DOTNET_ROOT must be an absolute installation directory; PATH will not be used");
    }
    let target = executable::require_executable(&root.join(DOTNET_FILE_NAME))
        .context("DOTNET_ROOT does not select a usable dotnet executable; PATH will not be used")?;
    if executable::is_dispatcher(&target).context("cannot identify DOTNET_ROOT's executable")? {
        bail!("DOTNET_ROOT points to Muxlet itself; choose a genuine .NET installation");
    }
    Ok(target)
}

/// Only missing and non-executable entries and recognisable Muxlet copies are
/// skipped. Any other eligible entry, an opaque wrapper included, is chosen or
/// is an error: a later installation is never silently selected instead.
fn search_path() -> Result<PathBuf> {
    let path = env::var_os("PATH");
    for directory in path.iter().flat_map(env::split_paths) {
        let candidate = directory.join(DOTNET_FILE_NAME);
        let metadata = match fs::metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if is_absent(&error) => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect PATH candidate '{}'", candidate.display())
                });
            }
        };
        if !executable::executable_metadata(&metadata) {
            continue;
        }
        let target = executable::require_executable(&candidate)?;
        if !executable::is_dispatcher(&target)
            .with_context(|| format!("cannot identify PATH candidate '{}'", candidate.display()))?
        {
            return Ok(target);
        }
    }
    bail!(
        "no genuine dotnet executable found on PATH (Muxlet copies are excluded); \
         set DOTNET_ROOT to an absolute .NET installation directory"
    )
}

/// Whether `path` is a recognised native .NET host, where a nested `dotnet`
/// call starts afresh: a host image beside the standard `host/fxr` directory.
/// The file name is irrelevant, because a launcher can be renamed behind a link.
pub(crate) fn is_known_host(path: &Path) -> Result<bool> {
    let Some(root) = path.parent() else {
        return Ok(false);
    };
    match fs::metadata(root.join("host").join("fxr")) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Ok(false),
        Err(error) if is_absent(&error) => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot inspect host layout at '{}'", root.display()));
        }
    }
    executable::is_host_image(path)
        .with_context(|| format!("cannot inspect host executable '{}'", path.display()))
}

/// A missing entry, or a file where a directory on the way was expected.
fn is_absent(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}
