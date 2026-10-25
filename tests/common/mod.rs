#![allow(dead_code)]

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use tempfile::{Builder, TempDir};

pub fn temp_dir() -> TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-work");
    fs::create_dir_all(&root).unwrap();
    Builder::new()
        .prefix("muxlet space \u{00e9}-")
        .tempdir_in(root)
        .unwrap()
}

pub fn dispatcher() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_dotnet"))
}

pub fn installer() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_muxlet-install"))
}

pub fn command(home: &Path) -> Command {
    let mut command = Command::new(dispatcher());
    command
        .env("DOTNET_SDK_HOME", home)
        .env("PATH", home.join("empty-path"))
        .env_remove("DOTNET_ROOT")
        .env_remove("MUXLET_FORWARD_CHAIN")
        .env_remove("MUXLET_FIXTURE_ACTION")
        .env_remove("MUXLET_FIXTURE_EXIT_CODE")
        .env_remove("MUXLET_FIXTURE_READ_STDIN")
        .env_remove("MUXLET_FIXTURE_STDERR");
    command
}

pub fn fixture() -> &'static Path {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/child.rs");
        let digest = format!("{:x}", Sha256::digest(fs::read(&source).unwrap()));
        let output_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-fixtures");
        fs::create_dir_all(&output_directory).unwrap();
        let binary = output_directory.join(format!(
            "child-{}-{}-{digest}{}",
            env::consts::OS,
            env::consts::ARCH,
            env::consts::EXE_SUFFIX,
        ));
        if !binary.is_file() {
            let directory = temp_dir();
            let staged = directory
                .path()
                .join(format!("fixture{}", env::consts::EXE_SUFFIX));
            let output = Command::new(env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
                .arg("--edition=2024")
                .arg(&source)
                .arg("-o")
                .arg(&staged)
                .output()
                .expect("cannot compile the native fixture");
            assert_success(&output);
            match fs::rename(&staged, &binary) {
                Ok(()) => {}
                Err(_) if binary.is_file() => {
                    assert_eq!(fs::read(staged).unwrap(), fs::read(&binary).unwrap());
                }
                Err(error) => panic!("cannot publish the native fixture: {error}"),
            }
        }
        binary
    })
}

pub fn install_fixture(directory: &Path, filename: impl AsRef<Path>) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let binary = directory.join(filename);
    fs::copy(fixture(), &binary).unwrap();
    binary
}

pub fn host(root: &Path) -> PathBuf {
    fs::create_dir_all(root.join("host/fxr")).unwrap();
    install_fixture(root, muxlet::executable::DOTNET_FILE_NAME)
}

pub fn extension(home: &Path, name: impl AsRef<OsStr>) -> PathBuf {
    let mut filename = std::ffi::OsString::from("dotnet-");
    filename.push(name);
    filename.push(env::consts::EXE_SUFFIX);
    install_fixture(&home.join("extensions"), Path::new(&filename))
}

pub fn hex(value: impl AsRef<OsStr>) -> String {
    hex_bytes(value.as_ref().as_encoded_bytes())
}

pub fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn report(output: &Output) -> Vec<String> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

pub fn reported_arguments(output: &Output) -> Vec<String> {
    report(output)
        .into_iter()
        .filter_map(|line| line.strip_prefix("arg:").map(str::to_owned))
        .collect()
}
