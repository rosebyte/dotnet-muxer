use std::env;
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::process::Command;
#[cfg(windows)]
use std::process::Stdio;

fn hex(value: &OsStr) -> String {
    value
        .as_encoded_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn finish(mut command: Command, replace: bool) -> ! {
    #[cfg(unix)]
    if replace {
        use std::os::unix::process::CommandExt;
        panic!("fixture exec failed: {}", command.exec());
    }
    let _ = replace;
    let status = command.status().unwrap();
    std::process::exit(status.code().expect("fixture child exited without a code"));
}

fn main() {
    std::hint::black_box(b"hostfxr");
    std::hint::black_box(b"h\0o\0s\0t\0f\0x\0r\0");
    let action = env::var("MUXLET_FIXTURE_ACTION").unwrap_or_default();
    match action.as_str() {
        "cargo-stub" => {
            let mut log = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(env::var_os("MUXLET_RUNNER_LOG").unwrap())
                .unwrap();
            writeln!(log, "begin").unwrap();
            writeln!(
                log,
                "cwd:{}",
                hex(env::current_dir()
                    .unwrap()
                    .canonicalize()
                    .unwrap()
                    .as_os_str())
            )
            .unwrap();
            for argument in env::args_os().skip(1) {
                writeln!(log, "arg:{}", hex(&argument)).unwrap();
            }
            writeln!(log, "end").unwrap();
            return;
        }
        "reenter-spawn" | "reenter-exec" => {
            let mut command = Command::new(env::var_os("MUXLET_TEST_DISPATCHER").unwrap());
            command
                .args(env::args_os().skip(1))
                .env_remove("MUXLET_FIXTURE_ACTION");
            finish(command, action == "reenter-exec");
        }
        "chain-spawn" | "chain-exec" => {
            let sequence = env::var_os("MUXLET_FIXTURE_ROOT_SEQUENCE").unwrap();
            let mut roots = env::split_paths(&sequence);
            let root = roots.next().unwrap();
            let remaining: Vec<_> = roots.collect();
            let mut command = Command::new(env::var_os("MUXLET_TEST_DISPATCHER").unwrap());
            command
                .args(env::args_os().skip(1))
                .env("DOTNET_ROOT", root)
                .env(
                    "MUXLET_FIXTURE_ROOT_SEQUENCE",
                    env::join_paths(&remaining).unwrap(),
                );
            if remaining.is_empty() {
                command.env_remove("MUXLET_FIXTURE_ACTION");
            }
            finish(command, action == "chain-exec");
        }
        "nested" => {
            let mut command = Command::new(env::var_os("MUXLET_TEST_DISPATCHER").unwrap());
            command
                .args(["--nested", "nested value"])
                .env_remove("MUXLET_FIXTURE_ACTION");
            finish(command, false);
        }
        "wrapper-to-host" | "exec-wrapper-to-host" => {
            let mut command = Command::new(env::var_os("MUXLET_TEST_HOST").unwrap());
            command
                .args(env::args_os().skip(1))
                .env("MUXLET_FIXTURE_ACTION", "nested");
            finish(command, action == "exec-wrapper-to-host");
        }
        #[cfg(unix)]
        "signal" => {
            unsafe extern "C" {
                fn raise(signal: i32) -> i32;
            }
            assert_eq!(unsafe { raise(15) }, 0);
            panic!("SIGTERM was not delivered");
        }
        #[cfg(windows)]
        "console-controller" => windows_console::controller(),
        #[cfg(windows)]
        "console-child" => windows_console::child(),
        _ => {}
    }

    println!("pid:{}", std::process::id());
    println!(
        "exe:{}",
        hex(env::current_exe()
            .unwrap()
            .canonicalize()
            .unwrap()
            .as_os_str())
    );
    println!(
        "cwd:{}",
        hex(env::current_dir()
            .unwrap()
            .canonicalize()
            .unwrap()
            .as_os_str())
    );
    for argument in env::args_os().skip(1) {
        println!("arg:{}", hex(&argument));
    }
    for name in [
        "MUXLET_TEST_VALUE",
        "DOTNET_ROOT",
        "DOTNET_ROOT_X64",
        "DOTNET_ROOT_ARM64",
        "DOTNET_ROOT(x86)",
        "PATH",
        "MUXLET_HOME",
        "MUXLET_DISPATCHER",
        "MUXLET_CONTRACT_VERSION",
        "MUXLET_FORWARD_CHAIN",
    ] {
        if let Some(value) = env::var_os(name) {
            println!("env:{name}:{}", hex(&value));
        }
    }
    if env::var_os("MUXLET_FIXTURE_READ_STDIN").is_some() {
        let mut input = Vec::new();
        io::stdin().read_to_end(&mut input).unwrap();
        let value: String = input.iter().map(|byte| format!("{byte:02x}")).collect();
        println!("stdin:{value}");
    }
    if let Some(message) = env::var_os("MUXLET_FIXTURE_STDERR") {
        io::stderr().write_all(message.as_encoded_bytes()).unwrap();
    }
    if let Ok(code) = env::var("MUXLET_FIXTURE_EXIT_CODE") {
        std::process::exit(code.parse().unwrap());
    }
}

#[cfg(windows)]
mod windows_console {
    use super::*;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
        fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
        fn ExitProcess(code: u32) -> !;
    }

    unsafe extern "system" fn ignore(event: u32) -> i32 {
        i32::from(event == 0 || event == 1)
    }

    unsafe extern "system" fn exit_on_control(event: u32) -> i32 {
        if event == 0 || event == 1 {
            unsafe { ExitProcess(73) }
        }
        0
    }

    pub fn child() -> ! {
        assert_ne!(
            unsafe { SetConsoleCtrlHandler(Some(exit_on_control), 1) },
            0
        );
        println!("ready");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_to_string(&mut input).unwrap();
        std::process::exit(0);
    }

    pub fn controller() -> ! {
        use std::io::{BufRead, BufReader};
        assert_ne!(unsafe { SetConsoleCtrlHandler(Some(ignore), 1) }, 0);
        let mut child = Command::new(env::var_os("MUXLET_TEST_DISPATCHER").unwrap())
            .arg("--console")
            .env("MUXLET_FIXTURE_ACTION", "console-child")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        output.read_line(&mut ready).unwrap();
        assert_eq!(ready.trim(), "ready");
        let event = env::var("MUXLET_TEST_CONTROL_EVENT")
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(unsafe { GenerateConsoleCtrlEvent(event, 0) }, 0);
        let status = child.wait().unwrap();
        std::process::exit(status.code().unwrap());
    }
}
