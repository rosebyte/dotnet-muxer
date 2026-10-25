mod common;

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

use common::*;

#[test]
fn runners_keep_the_callers_directory_and_literal_installation_arguments() {
    let directory = temp_dir();
    let working = directory.path().join("caller directory");
    fs::create_dir(&working).unwrap();
    let bin = directory.path().join("bin");
    install_fixture(&bin, format!("cargo{}", env::consts::EXE_SUFFIX));
    let log = directory.path().join("cargo calls");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = vec![bin];
    paths.extend(env::split_paths(&env::var_os("PATH").unwrap()));

    #[cfg(unix)]
    let mut runner = {
        let mut command = Command::new("/bin/bash");
        command.arg(root.join("run.sh"));
        command
    };
    #[cfg(windows)]
    let mut runner = {
        let mut command = Command::new("pwsh");
        command
            .args(["-NoProfile", "-File"])
            .arg(root.join("run.ps1"));
        command
    };
    let output = runner
        .current_dir(&working)
        .env("PATH", env::join_paths(paths).unwrap())
        .env("MUXLET_FIXTURE_ACTION", "cargo-stub")
        .env("MUXLET_RUNNER_LOG", &log)
        .args([
            "install",
            "--home",
            "relative home",
            "--backup",
            "relative backup",
        ])
        .output()
        .unwrap();
    assert_success(&output);

    let contents = fs::read_to_string(log).unwrap();
    let calls: Vec<_> = contents
        .split("begin\n")
        .filter(|call| !call.is_empty())
        .collect();
    assert_eq!(calls.len(), 2);
    for call in &calls {
        assert!(call.contains(&format!(
            "cwd:{}\n",
            hex(fs::canonicalize(&working).unwrap())
        )));
        assert!(call.contains(&format!(
            "arg:{}\narg:{}\n",
            hex("--manifest-path"),
            hex(root.join("Cargo.toml"))
        )));
        assert!(call.contains(&format!(
            "arg:{}\narg:{}\n",
            hex("--config"),
            hex(root.join(".cargo/config.toml"))
        )));
    }
    let tail = [
        "--",
        "--home",
        "relative home",
        "--backup",
        "relative backup",
    ]
    .iter()
    .map(|argument| format!("arg:{}\n", hex(argument)))
    .collect::<String>();
    assert!(calls[1].ends_with(&format!("{tail}end\n")));
}
