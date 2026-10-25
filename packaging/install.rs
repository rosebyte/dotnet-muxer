//! `muxlet-install`: places the Muxlet dispatcher in a per-user application home.
//!
//! This is a separate bootstrap helper, not a dispatcher command. The semantics
//! of placement, backups and refusals live in `muxlet::placement` and are
//! described in `packaging/README.md`.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use muxlet::home;
use muxlet::placement::{self, Outcome, Previous, Request};

const USAGE: &str = "\
muxlet-install: install or update the Muxlet dispatcher for the current user

Usage: muxlet-install [OPTIONS]

Options:
  --source FILE        Dispatcher to install
                       (default: dotnet[.exe] beside this helper)
  --home PATH          Application home
                       (default: DOTNET_SDK_HOME, otherwise the per-user default)
  --destination FILE   Complete file name to create or replace
                       (default: <home>/bin/dotnet[.exe])
  --backup FILE        Save the entry being replaced at exactly this path,
                       overwriting an older backup file or link
  --wait-pid PID       Windows only: wait for this process to exit, then replace
  --lock-timeout SECS  Seconds to wait for another Muxlet process (default: 30)
  -h, --help           Print this help

An existing file or symbolic link at the destination is replaced; a link is
replaced itself, never its target. If there was no old destination, an existing
backup is left alone. Directories, protected system locations and the launcher
of any .NET installation are refused before anything is written.

Only the application home's own directories are created. Configuration,
extensions, extension data and recovery data are never touched, PATH and shell
profiles are never edited, and nothing is elevated.
";

#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    source: Option<PathBuf>,
    home: Option<OsString>,
    destination: Option<PathBuf>,
    backup: Option<PathBuf>,
    wait_pid: Option<u32>,
    lock_timeout: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Install(Options),
}

fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut options = Options::default();
    let mut remaining = arguments.into_iter();
    while let Some(argument) = remaining.next() {
        let name = argument
            .to_str()
            .ok_or_else(|| format!("unrecognised argument {argument:?}"))?;
        match name {
            "-h" | "--help" => return Ok(Command::Help),
            "--source" => set(
                &mut options.source,
                name,
                value(name, &mut remaining)?.into(),
            )?,
            "--home" => set(&mut options.home, name, value(name, &mut remaining)?)?,
            "--destination" => {
                set(
                    &mut options.destination,
                    name,
                    value(name, &mut remaining)?.into(),
                )?;
            }
            "--backup" => set(
                &mut options.backup,
                name,
                value(name, &mut remaining)?.into(),
            )?,
            "--wait-pid" => {
                let pid = number(name, &value(name, &mut remaining)?)?;
                set(&mut options.wait_pid, name, pid)?;
            }
            "--lock-timeout" => {
                let seconds = number(name, &value(name, &mut remaining)?)?;
                set(&mut options.lock_timeout, name, seconds)?;
            }
            _ => return Err(format!("unrecognised argument '{name}'")),
        }
    }
    Ok(Command::Install(options))
}

fn value(name: &str, arguments: &mut impl Iterator<Item = OsString>) -> Result<OsString, String> {
    arguments
        .next()
        .ok_or_else(|| format!("option '{name}' needs a value"))
}

fn set<T>(slot: &mut Option<T>, name: &str, value: T) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("option '{name}' was given more than once"));
    }
    *slot = Some(value);
    Ok(())
}

fn number<T: FromStr>(name: &str, value: &OsStr) -> Result<T, String> {
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| format!("option '{name}' needs a whole number, not {value:?}"))
}

fn main() -> ExitCode {
    let result = match parse(std::env::args_os().skip(1)) {
        Ok(Command::Help) => {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(USAGE.as_bytes())
                .and_then(|()| stdout.flush())
                .context("cannot write installer help to stdout")
        }
        Ok(Command::Install(options)) => {
            if options.wait_pid.is_some() && !cfg!(windows) {
                return usage_error("option '--wait-pid' is supported only on Windows");
            }
            run(options)
        }
        Err(message) => return usage_error(&message),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("muxlet-install: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("muxlet-install: {message}\nTry 'muxlet-install --help' for usage.");
    ExitCode::from(2)
}

fn run(options: Options) -> anyhow::Result<()> {
    let selected_home = home::resolve(options.home.as_deref())?;
    let explicit_source = options.source.is_some();
    let source = match options.source {
        Some(source) => source,
        None => placement::default_source()?,
    };

    let mut request = Request::new(source, &selected_home);
    if let Some(destination) = options.destination {
        request.destination = destination;
    }
    request.backup = options.backup;
    request.wait_pid = options.wait_pid;
    if let Some(seconds) = options.lock_timeout {
        request.lock_timeout = Duration::from_secs(seconds);
    }

    let outcome = placement::install(&request).map_err(|error| {
        if explicit_source {
            error
        } else {
            error.context(
                "no --source was given, so the dotnet beside this helper was used; pass --source \
                 FILE if the dispatcher is elsewhere",
            )
        }
    })?;
    report(
        io::stdout().lock(),
        &outcome,
        &selected_home,
        options.home.is_some(),
    )
    .context("installation completed, but its result could not be written to stdout")
}

fn report(
    mut output: impl Write,
    outcome: &Outcome,
    selected_home: &Path,
    explicit_home: bool,
) -> io::Result<()> {
    writeln!(output, "Installed {}", outcome.destination.display())?;
    let kind = match outcome.previous {
        Previous::Absent => None,
        Previous::File => Some("file"),
        Previous::Symlink => Some("symbolic link"),
    };
    match (kind, &outcome.backup) {
        (Some(kind), Some(backup)) => {
            writeln!(output, "Saved the previous {kind} at {}", backup.display())?;
        }
        (Some(kind), None) => {
            writeln!(
                output,
                "Replaced the previous {kind}; no backup was requested"
            )?;
        }
        (None, _) => {}
    }

    let directory = outcome
        .destination
        .parent()
        .unwrap_or(selected_home)
        .display();
    writeln!(
        output,
        "Put '{directory}' on your user PATH yourself; Muxlet never edits PATH or shell profiles."
    )?;
    let home_notice = if explicit_home {
        match home::resolve(None) {
            Ok(usual) if usual == selected_home => None,
            Ok(_) => Some("This is not the default application home.".to_owned()),
            Err(error) => Some(format!(
                "The default application home could not be resolved: {error:#}."
            )),
        }
    } else {
        None
    };
    if let Some(notice) = home_notice {
        writeln!(
            output,
            "{notice} Set DOTNET_SDK_HOME to '{}' in the \
             environment of every dotnet invocation so routing, extensions and configuration use \
             it; DOTNET_SDK_HOME names this home, not a .NET SDK root.",
            selected_home.display()
        )?;
    }
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(arguments: &[&str]) -> Result<Command, String> {
        parse(arguments.iter().map(OsString::from))
    }

    #[test]
    fn every_option_takes_the_next_argument_as_its_value() {
        let command = parsed(&[
            "--source",
            "a dispatcher",
            "--home",
            "h",
            "--destination",
            "d",
            "--backup",
            "b",
            "--wait-pid",
            "42",
            "--lock-timeout",
            "7",
        ])
        .unwrap();
        assert_eq!(
            command,
            Command::Install(Options {
                source: Some("a dispatcher".into()),
                home: Some("h".into()),
                destination: Some("d".into()),
                backup: Some("b".into()),
                wait_pid: Some(42),
                lock_timeout: Some(7),
            })
        );
        assert_eq!(parsed(&[]).unwrap(), Command::Install(Options::default()));
    }

    #[test]
    fn help_is_an_option_but_option_values_are_literal() {
        assert_eq!(parsed(&["--help"]).unwrap(), Command::Help);
        assert_eq!(parsed(&["--home", "x", "-h"]).unwrap(), Command::Help);
        assert!(parsed(&["--bogus", "--help"]).is_err());
        assert_eq!(
            parsed(&["--home", "--help"]).unwrap(),
            Command::Install(Options {
                home: Some("--help".into()),
                ..Options::default()
            })
        );
    }

    #[test]
    fn help_does_not_read_the_rest_of_the_argument_iterator() {
        let arguments =
            std::iter::once(OsString::from("--help")).chain(std::iter::once_with(|| {
                panic!("arguments after help must not be consumed")
            }));
        assert_eq!(parse(arguments).unwrap(), Command::Help);
    }

    #[test]
    fn duplicate_options_leave_the_original_value_in_place() {
        let mut slot = Some("original");
        assert!(set(&mut slot, "--home", "duplicate").is_err());
        assert_eq!(slot, Some("original"));
    }

    #[test]
    fn reports_keep_native_paths_and_backup_details() {
        let home = Path::new("application home");
        let outcome = Outcome {
            destination: home.join("bin").join(muxlet::executable::DOTNET_FILE_NAME),
            previous: Previous::Symlink,
            backup: Some(home.join("staging/previous core")),
        };
        let mut output = Vec::new();
        report(&mut output, &outcome, home, false).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!(
                "Installed {}\nSaved the previous symbolic link at {}\n\
                 Put '{}' on your user PATH yourself; Muxlet never edits PATH or shell profiles.\n",
                outcome.destination.display(),
                outcome.backup.unwrap().display(),
                outcome.destination.parent().unwrap().display()
            )
        );
    }

    #[test]
    fn reports_propagate_final_flush_errors() {
        #[derive(Default)]
        struct FlushError(Vec<u8>);

        impl Write for FlushError {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.write(bytes)
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }

        let home = Path::new("application home");
        let outcome = Outcome {
            destination: home.join("bin").join(muxlet::executable::DOTNET_FILE_NAME),
            previous: Previous::Absent,
            backup: None,
        };
        let mut output = FlushError::default();
        let error = report(&mut output, &outcome, home, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(output.0.starts_with(b"Installed "));
    }

    #[test]
    fn malformed_command_lines_are_usage_errors() {
        for (arguments, expected) in [
            (&["--bogus"][..], "unrecognised argument '--bogus'"),
            (&["positional"], "unrecognised argument 'positional'"),
            (&["--source"], "needs a value"),
            (&["--home", "a", "--home", "b"], "more than once"),
            (&["--wait-pid", "soon"], "whole number"),
            (&["--wait-pid", "-1"], "whole number"),
            (&["--lock-timeout", ""], "whole number"),
            (&["--source=file"], "unrecognised argument '--source=file'"),
        ] {
            let error = parsed(arguments).unwrap_err();
            assert!(error.contains(expected), "{arguments:?}: {error}");
        }
    }
}
