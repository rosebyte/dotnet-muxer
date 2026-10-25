use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::{executable, home, process, recursion, resolver};

const USAGE: &str = "Usage: dotnet dispatcher [--home PATH] configuration\n\
    Prints the absolute configuration filename without reading or changing it.";

/// File suffixes of applications which genuine `dotnet` runs directly.
const APPLICATION_SUFFIXES: [&str; 8] = ["dll", "exe", "cs", "csx", "fs", "fsx", "vb", "vbx"];

/// Routes one invocation, given the arguments after the program name, and
/// returns the exit status to report.
pub fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<i32> {
    let arguments: Vec<OsString> = arguments.into_iter().collect();
    if let [name, rest @ ..] = arguments.as_slice() {
        if name == "dispatcher" {
            return core_command(rest);
        }
        if is_extension_name(name) {
            let selected_home = home::resolve(None)?;
            if let Some(extension) = find_extension(&selected_home, name)? {
                return run_extension(&extension, &selected_home, rest);
            }
        }
    }
    forward(&arguments)
}

fn core_command(arguments: &[OsString]) -> Result<i32> {
    if arguments == ["--help"] || arguments == ["configuration", "--help"] {
        writeln!(io::stdout().lock(), "{USAGE}").context("cannot write help to stdout")?;
        return Ok(0);
    }

    let mut selected_home = None;
    let mut configuration = false;
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--home" && selected_home.is_none() {
            let value = arguments
                .next()
                .context("--home requires a directory argument")?;
            selected_home = Some(value.as_os_str());
        } else if argument == "configuration" && !configuration {
            configuration = true;
        } else {
            bail!("unrecognised dispatcher arguments\n{USAGE}");
        }
    }
    if !configuration {
        bail!("a dispatcher command is required\n{USAGE}");
    }

    let selected_home = home::resolve(selected_home)?;
    write_path(&home::configuration(&selected_home))?;
    Ok(0)
}

fn write_path(path: &Path) -> Result<()> {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes()
    };
    #[cfg(not(unix))]
    let bytes = path
        .to_str()
        .context("the configuration filename cannot be represented on stdout")?
        .as_bytes();
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .context("cannot write the configuration filename to stdout")
}

/// Whether `name` is an ordinary command name which may select a private
/// extension. Options, hidden names, paths, drives, wildcards, application
/// files and existing files are rejected before any filename is built from it.
fn is_extension_name(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    let ordinary = !matches!(bytes.first(), None | Some(b'-' | b'.'))
        && !bytes.iter().any(|byte| b"/\\:\0<>|*?".contains(byte));
    let path = Path::new(name);
    ordinary
        && !path.extension().is_some_and(|suffix| {
            APPLICATION_SUFFIXES
                .iter()
                .any(|application| suffix.eq_ignore_ascii_case(application))
        })
        && !path.is_file()
}

/// The installed extension for `name`. Discovery is one level deep, solely in
/// the home's `extensions` directory, and an installed entry which cannot run
/// is an error rather than a reason to fall back to genuine `dotnet`.
fn find_extension(selected_home: &Path, name: &OsStr) -> Result<Option<PathBuf>> {
    let mut filename = OsString::from("dotnet-");
    filename.push(name);
    filename.push(env::consts::EXE_SUFFIX);
    let path = selected_home.join("extensions").join(filename);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot inspect private extension '{}'", path.display()));
        }
    }
    let resolved = executable::require_executable(&path)
        .with_context(|| format!("private extension '{}' is broken", path.display()))?;
    if executable::is_dispatcher(&resolved)
        .with_context(|| format!("cannot identify private extension '{}'", path.display()))?
    {
        bail!(
            "private extension '{}' is a Muxlet dispatcher, not an extension executable",
            path.display()
        );
    }
    Ok(Some(resolved))
}

/// Hands over to an extension with the documented contract variables; the
/// private forwarding context is not passed on.
fn run_extension(extension: &Path, selected_home: &Path, arguments: &[OsString]) -> Result<i32> {
    let dispatcher = env::current_exe().context("cannot locate the running Muxlet executable")?;
    let dispatcher =
        fs::canonicalize(dispatcher).context("cannot resolve the running Muxlet executable")?;
    let mut command = Command::new(extension);
    command
        .args(arguments)
        .env(home::EXTENSION_HOME_ENV, selected_home)
        .env("MUXLET_CONTRACT_VERSION", "1")
        .env("MUXLET_DISPATCHER", dispatcher)
        .env_remove(recursion::CHAIN_ENV);
    process::execute(command, extension)
}

/// Hands every argument, unchanged, to the genuine `dotnet`.
fn forward(arguments: &[OsString]) -> Result<i32> {
    let target = resolver::resolve()?;
    let mut command = Command::new(&target);
    command.args(arguments);
    recursion::prepare(&mut command, &target)?;
    process::execute(command, &target)
}

#[cfg(test)]
mod tests {
    use super::is_extension_name;
    use std::ffi::OsStr;

    #[test]
    fn only_ordinary_commands_are_extension_candidates() {
        for command in ["build", "sdks", "foo-bar", "foo.bar", "tool_1", "a..b"] {
            assert!(is_extension_name(OsStr::new(command)), "{command}");
        }
        for command in [
            "",
            "--info",
            "-h",
            "../foo",
            "foo/bar",
            r"foo\bar",
            r"C:\app",
            "..",
            ".hidden",
            "app.dll",
            "app.EXE",
            "program.cs",
            "program.csx",
            "program.fs",
            "program.fsx",
            "file.vb",
            "file.Vbx",
            "foo:bar",
            "foo*",
            "foo?",
            "a|b",
            "<a>",
            "nul\0byte",
        ] {
            assert!(!is_extension_name(OsStr::new(command)), "{command:?}");
        }
    }
}
