mod common;

use std::fs;
use std::process::{Command, Stdio};

use common::*;
use muxlet::executable::DOTNET_FILE_NAME;

fn broken_stdout() -> Stdio {
    #[cfg(unix)]
    {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        let (writer, reader) = UnixStream::pair().unwrap();
        drop(reader);
        Stdio::from(OwnedFd::from(writer))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Pipes::CreatePipe;
        let mut reader = std::ptr::null_mut();
        let mut writer = std::ptr::null_mut();
        assert_ne!(
            unsafe { CreatePipe(&mut reader, &mut writer, std::ptr::null(), 0) },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        let writer = unsafe { OwnedHandle::from_raw_handle(writer) };
        assert_ne!(unsafe { CloseHandle(reader) }, 0);
        Stdio::from(writer)
    }
}

#[test]
fn installer_output_failures_are_reported_without_claiming_rollback() {
    let directory = temp_dir();
    let output = Command::new(installer())
        .arg("--help")
        .stdout(broken_stdout())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot write installer help"));

    let home = directory.path().join("home");
    let output = Command::new(installer())
        .arg("--source")
        .arg(dispatcher())
        .arg("--home")
        .arg(&home)
        .env_remove("DOTNET_ROOT")
        .stdout(broken_stdout())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("installation completed"));
    assert!(home.join("bin").join(DOTNET_FILE_NAME).is_file());
}

#[test]
fn the_configuration_query_reports_a_broken_output_stream() {
    let directory = temp_dir();
    let home = directory.path().join("missing home");
    let output = command(&home)
        .args(["dispatcher", "configuration"])
        .stdout(broken_stdout())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot write the configuration filename")
    );
    assert!(!home.exists());
}

#[test]
fn installed_core_starts_without_dotnet_and_upgrades_without_touching_extensions_or_configuration()
{
    let directory = temp_dir();
    let home = directory.path().join("application home \u{00e9}");
    let install = || {
        let mut command = Command::new(installer());
        command
            .arg("--source")
            .arg(dispatcher())
            .arg("--home")
            .arg(&home)
            .env_remove("DOTNET_ROOT");
        command
    };
    assert_success(&install().output().unwrap());
    let installed = home.join("bin").join(DOTNET_FILE_NAME);
    assert!(installed.is_file());
    assert_eq!(fs::read_dir(home.join("extensions")).unwrap().count(), 0);

    let invoke = || {
        let mut command = Command::new(&installed);
        command
            .env("DOTNET_SDK_HOME", &home)
            .env("PATH", home.join("bin"))
            .env_remove("DOTNET_ROOT")
            .env_remove("MUXLET_FORWARD_CHAIN");
        command
    };
    let output = invoke()
        .args(["dispatcher", "configuration"])
        .output()
        .unwrap();
    assert_success(&output);
    let mut expected = home
        .join("configuration.json")
        .as_os_str()
        .as_encoded_bytes()
        .to_vec();
    expected.push(b'\n');
    assert_eq!(output.stdout, expected);
    assert!(!home.join("configuration.json").exists());

    let configuration = br#"{"schemaVersion":999,"extensions":{"sdks":{"version":"independent"}}}"#;
    fs::write(home.join("configuration.json"), configuration).unwrap();
    let private_extension = extension(&home, "build");
    let extension_bytes = fs::read(&private_extension).unwrap();
    fs::write(
        home.join("extensions/supporting data"),
        b"owned by extension",
    )
    .unwrap();
    fs::write(home.join("metadata/extension record"), b"keep metadata").unwrap();
    fs::write(home.join("journal/extension recovery"), b"keep recovery").unwrap();

    let backup = home.join("staging/previous core");
    assert_success(&install().arg("--backup").arg(&backup).output().unwrap());
    assert_eq!(
        fs::read(home.join("configuration.json")).unwrap(),
        configuration
    );
    assert_eq!(fs::read(&private_extension).unwrap(), extension_bytes);
    assert_eq!(
        fs::read(home.join("extensions/supporting data")).unwrap(),
        b"owned by extension"
    );
    assert_eq!(
        fs::read(home.join("metadata/extension record")).unwrap(),
        b"keep metadata"
    );
    assert_eq!(
        fs::read(home.join("journal/extension recovery")).unwrap(),
        b"keep recovery"
    );
    assert!(muxlet::executable::is_dispatcher(&backup).unwrap());

    let output = invoke()
        .env("DOTNET_ROOT", "invalid but unused")
        .args([
            "build",
            "argument with spaces",
            "--home",
            "extension option",
        ])
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        reported_arguments(&output),
        [
            hex("argument with spaces"),
            hex("--home"),
            hex("extension option"),
        ]
    );
    assert!(report(&output).contains(&format!("env:MUXLET_HOME:{}", hex(&home))));

    let output = invoke().arg("--info").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no genuine dotnet"));
}
