use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

/// Runs `command` for the resolved `target` with the caller's streams. Unix
/// replaces this process, so this returns only on failure; Windows waits in the
/// shared console and returns the child's full exit code.
pub(crate) fn execute(mut command: Command, target: &Path) -> Result<i32> {
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    #[cfg(unix)]
    {
        replace_process(&command).with_context(|| format!("cannot execute '{}'", target.display()))
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE;
        use windows_sys::Win32::System::Console::{
            CTRL_BREAK_EVENT, CTRL_C_EVENT, GetConsoleProcessList, SetConsoleCtrlHandler,
        };

        unsafe extern "system" fn control_handler(event: u32) -> i32 {
            i32::from(matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT))
        }

        // Both processes share the console; let the child handle Ctrl+C/Ctrl+Break
        // while the dispatcher stays alive to return its actual exit status.
        let mut console_pid = 0;
        if unsafe { GetConsoleProcessList(&mut console_pid, 1) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_INVALID_HANDLE as i32) {
                return Err(error).context("cannot inspect the inherited console");
            }
        } else if unsafe { SetConsoleCtrlHandler(Some(control_handler), 1) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("cannot install the dispatcher console control handler");
        }
        let status = command
            .spawn()
            .with_context(|| format!("cannot launch '{}'", target.display()))?
            .wait()
            .with_context(|| format!("cannot wait for '{}'", target.display()))?;
        status
            .code()
            .context("the child terminated without a Windows exit status")
    }
}

/// The router sets only arguments and environment changes; cwd and streams
/// are inherited. `CommandExt::exec` uses execvp, whose ENOEXEC fallback can
/// interpret a rejected native image as a shell script. Use execve instead.
#[cfg(unix)]
fn replace_process(command: &Command) -> Result<i32> {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;

    let arguments = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|argument| CString::new(argument.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("the executable path or an argument contains a NUL byte")?;

    let mut environment = std::env::vars_os().collect::<BTreeMap<_, _>>();
    for (name, value) in command.get_envs() {
        match value {
            Some(value) => {
                environment.insert(name.to_owned(), value.to_owned());
            }
            None => {
                environment.remove(name);
            }
        }
    }
    let environment = environment
        .into_iter()
        .map(|(mut name, value)| {
            name.push("=");
            name.push(value);
            CString::new(name.as_bytes())
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("an environment variable contains a NUL byte")?;

    let argv = pointers(&arguments);
    let envp = pointers(&environment);
    // Rust ignores SIGPIPE at startup; external programs expect its default,
    // just as when launched through std::process::Command.
    let previous = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    if previous == libc::SIG_ERR {
        return Err(io::Error::last_os_error()).context("cannot restore default SIGPIPE handling");
    }

    // Both pointer lists are NUL-terminated and their CStrings outlive the call.
    unsafe { libc::execve(arguments[0].as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    let error = io::Error::last_os_error();
    if unsafe { libc::signal(libc::SIGPIPE, previous) } == libc::SIG_ERR {
        return Err(error).with_context(|| {
            format!(
                "execution failed, and SIGPIPE handling could not be restored: {}",
                io::Error::last_os_error()
            )
        });
    }
    Err(error.into())
}

#[cfg(unix)]
fn pointers(strings: &[std::ffi::CString]) -> Vec<*const libc::c_char> {
    strings
        .iter()
        .map(|string| string.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}
