mod common;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};

use common::*;
use muxlet::executable::DOTNET_FILE_NAME;

fn path_line(path: &Path) -> Vec<u8> {
    let mut bytes = path.as_os_str().as_encoded_bytes().to_vec();
    bytes.push(b'\n');
    bytes
}

/// The hops a wrapper fixture received in its private forwarding context.
fn forwarded_hops(output: &Output) -> Vec<serde_json::Value> {
    let encoded = report(output)
        .into_iter()
        .find_map(|line| {
            line.strip_prefix("env:MUXLET_FORWARD_CHAIN:")
                .map(str::to_owned)
        })
        .expect("the wrapper received no forwarding context");
    let bytes: Vec<u8> = (0..encoded.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&encoded[index..index + 2], 16).unwrap())
        .collect();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn configuration_query_needs_neither_sdk_nor_files_nor_valid_root() {
    let directory = temp_dir();
    let home = directory.path().join("missing home");
    let output = command(&home)
        .args(["dispatcher", "configuration"])
        .env("DOTNET_ROOT", "invalid relative root")
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(output.stdout, path_line(&home.join("configuration.json")));
    assert!(output.stderr.is_empty());
    assert!(!home.exists());
}

#[test]
fn configuration_query_does_not_read_repair_or_migrate_configuration() {
    let directory = temp_dir();
    let home = directory.path();
    let configuration = home.join("configuration.json");
    for contents in [
        b"not valid JSON".as_slice(),
        br#"{"schemaVersion":999, "extensions":{"unknown":false}}"#,
    ] {
        fs::write(&configuration, contents).unwrap();
        let output = command(home)
            .args(["dispatcher", "configuration"])
            .output()
            .unwrap();
        assert_success(&output);
        assert_eq!(output.stdout, path_line(&configuration));
        assert_eq!(fs::read(&configuration).unwrap(), contents);
    }
    assert_eq!(fs::read_dir(home).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn configuration_query_does_not_require_read_or_write_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let directory = temp_dir();
    let home = directory.path().join("inaccessible");
    fs::create_dir(&home).unwrap();
    fs::write(home.join("configuration.json"), b"unreadable").unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o000)).unwrap();
    let output = command(&home)
        .args(["dispatcher", "configuration"])
        .output()
        .unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    assert_success(&output);
    assert_eq!(output.stdout, path_line(&home.join("configuration.json")));
}

#[test]
fn explicit_core_home_takes_precedence_and_supports_both_positions() {
    let directory = temp_dir();
    let env_home = directory.path().join("environment");
    let selected_home = directory.path().join("explicit home \u{00e9}");
    for before in [false, true] {
        let mut arguments: Vec<OsString> = vec!["dispatcher".into()];
        if !before {
            arguments.push("configuration".into());
        }
        arguments.extend(["--home".into(), selected_home.clone().into_os_string()]);
        if before {
            arguments.push("configuration".into());
        }
        let output = command(&env_home).args(arguments).output().unwrap();
        assert_success(&output);
        assert_eq!(
            output.stdout,
            path_line(&selected_home.join("configuration.json"))
        );
    }
    let output = command(&env_home)
        .current_dir(directory.path())
        .args(["dispatcher", "configuration", "--home", "relative home"])
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        output.stdout,
        path_line(&directory.path().join("relative home/configuration.json"))
    );
    assert!(!env_home.exists());
    assert!(!selected_home.exists());
}

#[cfg(unix)]
#[test]
fn platform_home_uses_native_user_and_xdg_locations() {
    let directory = temp_dir();
    let output = command(directory.path())
        .env_remove("DOTNET_SDK_HOME")
        .env("HOME", directory.path())
        .env("XDG_DATA_HOME", directory.path().join("xdg data"))
        .args(["dispatcher", "configuration"])
        .output()
        .unwrap();
    assert_success(&output);
    #[cfg(target_os = "macos")]
    let expected = directory
        .path()
        .join("Library/Application Support/muxlet/configuration.json");
    #[cfg(not(target_os = "macos"))]
    let expected = directory.path().join("xdg data/muxlet/configuration.json");
    assert_eq!(output.stdout, path_line(&expected));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn core_namespace_cannot_be_overridden_or_fall_through() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    extension(&home, "dispatcher");
    let sdk = directory.path().join("sdk");
    host(&sdk);
    for arguments in [
        vec!["dispatcher"],
        vec!["dispatcher", "root"],
        vec!["dispatcher", "configuration", "extra"],
        vec!["dispatcher", "configuration", "configuration"],
        vec!["dispatcher", "configuration", "--home"],
        vec!["dispatcher", "configuration", "--home", ""],
        vec!["dispatcher", "--home", "one"],
        vec!["dispatcher", "--help", "extra"],
        vec![
            "dispatcher",
            "--home",
            "one",
            "configuration",
            "--home",
            "two",
        ],
    ] {
        let output = command(&home)
            .env("DOTNET_ROOT", &sdk)
            .args(arguments)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    let output = command(&home)
        .args(["dispatcher", "configuration"])
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(output.stdout, path_line(&home.join("configuration.json")));
}

#[test]
fn core_help_needs_no_home_root_or_extension() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    for arguments in [
        &["dispatcher", "--help"][..],
        &["dispatcher", "configuration", "--help"],
    ] {
        let output = command(&home)
            .env("DOTNET_ROOT", "invalid relative root")
            .args(arguments)
            .output()
            .unwrap();
        assert_success(&output);
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.starts_with("Usage: dotnet dispatcher [--home PATH] configuration\n"),
            "{text}"
        );
        assert!(output.stderr.is_empty());
    }
    assert!(!home.exists());
}

#[test]
fn extensions_preserve_native_process_context_and_only_receive_remaining_arguments() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let extension = extension(&home, "foo");
    let working = directory.path().join("working directory \u{00e9}");
    fs::create_dir(&working).unwrap();
    let arguments = [
        "a b",
        "",
        "--home",
        "extension-specific",
        "--",
        "$(not evaluated); 'quoted' \"value\"",
    ];
    let mut child = command(&home)
        .current_dir(&working)
        .arg("foo")
        .args(arguments)
        .env("DOTNET_ROOT", "invalid but irrelevant")
        .env("MUXLET_TEST_VALUE", "inherited value \u{00e9}")
        .env("MUXLET_FIXTURE_READ_STDIN", "1")
        .env("MUXLET_FIXTURE_STDERR", "fixture stderr")
        .env("MUXLET_FIXTURE_EXIT_CODE", "37")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let input = b"input with spaces\0and native bytes\xff\n";
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(37));
    assert_eq!(output.stderr, b"fixture stderr");
    assert_eq!(
        reported_arguments(&output),
        arguments.iter().map(hex).collect::<Vec<_>>()
    );
    let report = report(&output);
    assert!(report.contains(&format!(
        "exe:{}",
        hex(fs::canonicalize(extension).unwrap())
    )));
    assert!(report.contains(&format!("cwd:{}", hex(fs::canonicalize(working).unwrap()))));
    assert!(report.contains(&format!(
        "env:MUXLET_TEST_VALUE:{}",
        hex("inherited value \u{00e9}")
    )));
    assert!(report.contains(&format!("env:MUXLET_HOME:{}", hex(&home))));
    assert!(report.contains(&format!("env:MUXLET_CONTRACT_VERSION:{}", hex("1"))));
    assert!(report.contains(&format!(
        "env:MUXLET_DISPATCHER:{}",
        hex(fs::canonicalize(dispatcher()).unwrap())
    )));
    assert!(report.contains(&format!("stdin:{}", hex_bytes(input))));
    #[cfg(unix)]
    assert!(report.contains(&format!("pid:{pid}")));
    #[cfg(windows)]
    let _ = pid;
}

#[test]
fn extensions_override_native_commands_and_sdks_has_no_special_status() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let sdk = directory.path().join("sdk");
    let genuine = host(&sdk);
    for name in ["build", "sdks", "sdk", "foo"] {
        let extension = extension(&home, name);
        let output = command(&home)
            .env("DOTNET_ROOT", &sdk)
            .args([name, "update", "--prune"])
            .output()
            .unwrap();
        assert_success(&output);
        assert_eq!(reported_arguments(&output), [hex("update"), hex("--prune")]);
        assert!(report(&output).contains(&format!(
            "exe:{}",
            hex(fs::canonicalize(&extension).unwrap())
        )));
        fs::remove_file(extension).unwrap();
        let output = command(&home)
            .env("DOTNET_ROOT", &sdk)
            .args([name, "update", "--prune"])
            .output()
            .unwrap();
        assert_success(&output);
        assert_eq!(
            reported_arguments(&output),
            [hex(name), hex("update"), hex("--prune")]
        );
        assert!(
            report(&output).contains(&format!("exe:{}", hex(fs::canonicalize(&genuine).unwrap())))
        );
    }
}

#[test]
fn forwarding_preserves_arguments_root_overrides_environment_and_exit_status() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let sdk = directory.path().join("explicit sdk");
    host(&sdk);
    let other = directory.path().join("other sdk");
    host(&other);
    let arguments = ["build", "--home", "literal path", "", "--property:a=b c"];
    let path = env::join_paths([&other]).unwrap();
    let output = command(&home)
        .env("DOTNET_ROOT", &sdk)
        .env("DOTNET_ROOT_X64", "x64 untouched")
        .env("DOTNET_ROOT_ARM64", "arm64 untouched")
        .env("DOTNET_ROOT(x86)", "x86 untouched")
        .env("PATH", &path)
        .env("MUXLET_FIXTURE_EXIT_CODE", "43")
        .args(arguments)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(43));
    assert_eq!(
        reported_arguments(&output),
        arguments.iter().map(hex).collect::<Vec<_>>()
    );
    let report = report(&output);
    for (name, value) in [
        ("DOTNET_ROOT", sdk.as_os_str()),
        ("DOTNET_ROOT_X64", "x64 untouched".as_ref()),
        ("DOTNET_ROOT_ARM64", "arm64 untouched".as_ref()),
        ("DOTNET_ROOT(x86)", "x86 untouched".as_ref()),
        ("PATH", path.as_os_str()),
    ] {
        assert!(report.contains(&format!("env:{name}:{}", hex(value))));
    }
    assert!(
        !report
            .iter()
            .any(|line| line.starts_with("env:MUXLET_HOME:"))
    );
}

#[test]
fn empty_invocations_inventory_options_and_native_sdk_groups_forward_unchanged() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let sdk = directory.path().join("sdk");
    host(&sdk);
    for arguments in [
        vec![],
        vec!["--help"],
        vec!["--list-sdks"],
        vec!["--list-runtimes"],
        vec!["sdk", "check"],
    ] {
        let output = command(&home)
            .env("DOTNET_ROOT", &sdk)
            .args(&arguments)
            .output()
            .unwrap();
        assert_success(&output);
        assert_eq!(
            reported_arguments(&output),
            arguments.iter().map(hex).collect::<Vec<_>>()
        );
    }
    assert!(!home.exists());
}

#[test]
fn private_discovery_never_searches_path_cwd_or_subdirectories() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let sdk = directory.path().join("sdk");
    host(&sdk);
    let elsewhere = directory.path().join("elsewhere");
    install_fixture(&elsewhere, format!("dotnet-foo{}", env::consts::EXE_SUFFIX));
    install_fixture(
        &home.join("extensions/nested"),
        format!("dotnet-foo{}", env::consts::EXE_SUFFIX),
    );
    let output = command(&home)
        .current_dir(&elsewhere)
        .env("PATH", &elsewhere)
        .env("DOTNET_ROOT", &sdk)
        .arg("foo")
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(reported_arguments(&output), [hex("foo")]);
}

#[test]
fn options_paths_and_file_based_apps_are_not_extension_names() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let sdk = directory.path().join("sdk");
    host(&sdk);
    for name in [
        "--info",
        "app.dll",
        "program.cs",
        "program.csx",
        "program.fsx",
        ".hidden",
    ] {
        extension(&home, name);
        let output = command(&home)
            .env("DOTNET_ROOT", &sdk)
            .args([name, "an argument"])
            .output()
            .unwrap();
        assert_success(&output);
        assert_eq!(reported_arguments(&output), [hex(name), hex("an argument")]);
    }
    let working = directory.path().join("working");
    fs::create_dir(&working).unwrap();
    fs::write(working.join("application"), b"file based application").unwrap();
    extension(&home, "application");
    for name in [
        "application",
        "../escape",
        r"..\escape",
        "./app.dll",
        r"C:\app.dll",
    ] {
        let output = command(&home)
            .current_dir(&working)
            .env("DOTNET_ROOT", &sdk)
            .arg(name)
            .output()
            .unwrap();
        assert_success(&output);
        assert_eq!(reported_arguments(&output), [hex(name)]);
    }
}

#[test]
fn a_broken_private_extension_is_an_error_without_genuine_fallback() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let sdk = directory.path().join("sdk");
    host(&sdk);
    let path = home
        .join("extensions")
        .join(format!("dotnet-foo{}", env::consts::EXE_SUFFIX));
    fs::create_dir_all(&path).unwrap();
    let output = command(&home)
        .env("DOTNET_ROOT", &sdk)
        .arg("foo")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("extension"));
    fs::remove_dir(&path).unwrap();
    fs::copy(dispatcher(), &path).unwrap();
    let output = command(&home)
        .env("DOTNET_ROOT", &sdk)
        .arg("foo")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not an extension"));
}

#[cfg(unix)]
#[test]
fn non_executable_and_dangling_extensions_do_not_fall_through() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = temp_dir();
    let home = directory.path().join("home");
    let sdk = directory.path().join("sdk");
    host(&sdk);
    let path = extension(&home, "foo");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let output = command(&home)
        .env("DOTNET_ROOT", &sdk)
        .arg("foo")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_file(&path).unwrap();
    symlink("missing", &path).unwrap();
    let output = command(&home)
        .env("DOTNET_ROOT", &sdk)
        .arg("foo")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn executable_scripts_keep_boundaries_but_invalid_formats_do_not_invoke_a_shell() {
    use std::os::unix::fs::PermissionsExt;
    let directory = temp_dir();
    let home = directory.path().join("home");
    let path = home.join("extensions/dotnet-foo");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"#!/bin/sh\nprintf '<%s>\\n' \"$@\"\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let output = command(&home)
        .args(["foo", "a b", "", "$(not evaluated)"])
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(output.stdout, b"<a b>\n<>\n<$(not evaluated)>\n");

    fs::write(&path, b"printf 'must not run without a shebang'").unwrap();
    let output = command(&home).arg("foo").output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("shebang"));
}

#[cfg(unix)]
#[test]
fn native_looking_files_rejected_by_the_kernel_never_fall_back_to_a_shell() {
    use std::os::unix::fs::PermissionsExt;

    let directory = temp_dir();
    let home = directory.path().join("home");
    let extension = home.join("extensions/dotnet-foo");
    let root = directory.path().join("invalid host");
    let host = root.join(DOTNET_FILE_NAME);
    for path in [&extension, &host] {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            b"\x7fELF\nprintf 'must not execute as a shell script'\n",
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    for arguments in [vec!["foo", "a b"], vec!["--info"]] {
        let output = command(&home)
            .env("DOTNET_ROOT", &root)
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot execute"));
    }
}

#[cfg(unix)]
#[test]
fn recursive_shebang_wrappers_are_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let directory = temp_dir();
    let home = directory.path().join("home");
    let root = directory.path().join("script wrapper");
    let path = root.join(DOTNET_FILE_NAME);
    fs::create_dir_all(&root).unwrap();
    for script in [
        "exec \"$MUXLET_TEST_DISPATCHER\" \"$@\"\n",
        "\"$MUXLET_TEST_DISPATCHER\" \"$@\"\nstatus=$?\nexit \"$status\"\n",
    ] {
        let script = format!(
            "#!/bin/sh\n\
             if [ \"$MUXLET_TEST_REENTERED\" = 1 ]; then exit 95; fi\n\
             export MUXLET_TEST_REENTERED=1\n{script}"
        );
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let output = command(&home)
            .env("DOTNET_ROOT", &root)
            .env("MUXLET_TEST_DISPATCHER", dispatcher())
            .env("MUXLET_TEST_REENTERED", "0")
            .arg("--info")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("recursive dotnet forwarding"));
    }
}

#[test]
fn invalid_explicit_root_does_not_authorise_path_fallback() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let sdk = directory.path().join("sdk");
    host(&sdk);
    for root in [
        OsString::from("relative sdk"),
        directory.path().join("missing sdk").into_os_string(),
    ] {
        let output = command(&home)
            .env("DOTNET_ROOT", root)
            .env("PATH", &sdk)
            .arg("--info")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("DOTNET_ROOT"));
    }
}

#[test]
fn path_order_skips_copied_and_hard_linked_dispatchers() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let copy = directory.path().join("copy");
    let hard_link = directory.path().join("hard link");
    let first = directory.path().join("first sdk");
    let second = directory.path().join("second sdk");
    fs::create_dir_all(&copy).unwrap();
    fs::create_dir_all(&hard_link).unwrap();
    fs::copy(dispatcher(), copy.join(DOTNET_FILE_NAME)).unwrap();
    fs::hard_link(dispatcher(), hard_link.join(DOTNET_FILE_NAME)).unwrap();
    let genuine = host(&first);
    host(&second);
    let path = env::join_paths([
        dispatcher().parent().unwrap(),
        &copy,
        &hard_link,
        &first,
        &second,
    ])
    .unwrap();
    for empty_root in [false, true] {
        let mut command = command(&home);
        command.env("PATH", &path).args(["--list-sdks", "a b"]);
        if empty_root {
            command.env("DOTNET_ROOT", "");
        }
        let output = command.output().unwrap();
        assert_success(&output);
        assert_eq!(
            reported_arguments(&output),
            [hex("--list-sdks"), hex("a b")]
        );
        assert!(
            report(&output).contains(&format!("exe:{}", hex(fs::canonicalize(&genuine).unwrap())))
        );
        assert!(
            !report(&output)
                .iter()
                .any(|line| line.starts_with("env:DOTNET_ROOT:") && !line.ends_with(':'))
        );
    }
}

#[cfg(unix)]
#[test]
fn launcher_links_are_followed_and_self_links_are_excluded() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = temp_dir();
    let home = directory.path().join("home");
    let self_link = directory.path().join("self-link");
    let non_executable = directory.path().join("not executable");
    let bin = directory.path().join("links/bin");
    fs::create_dir_all(&self_link).unwrap();
    fs::create_dir_all(&bin).unwrap();
    symlink(dispatcher(), self_link.join(DOTNET_FILE_NAME)).unwrap();
    let unusable = install_fixture(&non_executable, DOTNET_FILE_NAME);
    fs::set_permissions(unusable, fs::Permissions::from_mode(0o600)).unwrap();
    let root = directory.path().join("actual-sdk");
    let genuine = host(&root);
    symlink("../../actual-sdk/dotnet", bin.join(DOTNET_FILE_NAME)).unwrap();
    let output = command(&home)
        .env(
            "PATH",
            env::join_paths([&self_link, &non_executable, &bin]).unwrap(),
        )
        .arg("--version")
        .output()
        .unwrap();
    assert_success(&output);
    assert!(report(&output).contains(&format!("exe:{}", hex(fs::canonicalize(genuine).unwrap()))));
}

#[cfg(unix)]
#[test]
fn a_renamed_genuine_launcher_is_still_a_nested_host_boundary() {
    use std::os::unix::fs::symlink;
    let directory = temp_dir();
    let home = directory.path().join("home");
    let sdk = directory.path().join("sdk");
    fs::create_dir_all(sdk.join("host/fxr")).unwrap();
    let genuine = install_fixture(&sdk, "renamed-host");
    let bin = directory.path().join("bin");
    fs::create_dir(&bin).unwrap();
    symlink(&genuine, bin.join(DOTNET_FILE_NAME)).unwrap();
    let output = command(&home)
        .env("PATH", &bin)
        .env("MUXLET_TEST_DISPATCHER", dispatcher())
        .env("MUXLET_FIXTURE_ACTION", "nested")
        .arg("--info")
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        reported_arguments(&output),
        [hex("--nested"), hex("nested value")]
    );
}

#[test]
fn no_genuine_host_and_explicit_self_selection_are_clear_errors() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let copied = directory.path().join("only-dispatcher");
    fs::create_dir(&copied).unwrap();
    fs::copy(dispatcher(), copied.join(DOTNET_FILE_NAME)).unwrap();
    let output = command(&home)
        .env("PATH", &copied)
        .arg("--info")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no genuine dotnet"));
    let output = command(&home)
        .env("DOTNET_ROOT", &copied)
        .arg("--info")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Muxlet itself"));

    // Without PATH nothing is searched, not even the working directory.
    let sdk = directory.path().join("sdk");
    host(&sdk);
    let output = command(&home)
        .env_remove("PATH")
        .current_dir(&sdk)
        .arg("--info")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no genuine dotnet"));
}

#[cfg(unix)]
#[test]
fn an_eligible_path_entry_that_cannot_launch_is_an_error_not_skipped() {
    use std::os::unix::fs::PermissionsExt;
    let directory = temp_dir();
    let home = directory.path().join("home");
    let wrapper = directory.path().join("invalid wrapper");
    fs::create_dir(&wrapper).unwrap();
    let path = wrapper.join(DOTNET_FILE_NAME);
    fs::write(&path, b"printf 'must not run without a shebang'").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let sdk = directory.path().join("sdk");
    host(&sdk);
    let output = command(&home)
        .env("PATH", env::join_paths([&wrapper, &sdk]).unwrap())
        .arg("--info")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("shebang"));
}

#[test]
fn dispatcher_identity_does_not_mark_the_installer_or_native_fixtures() {
    assert!(muxlet::executable::is_dispatcher(dispatcher()).unwrap());
    assert!(!muxlet::executable::is_dispatcher(installer()).unwrap());
    assert!(!muxlet::executable::is_dispatcher(fixture()).unwrap());
}

#[test]
fn recursive_native_wrappers_are_rejected_without_a_blanket_inherited_guard() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let wrapper = directory.path().join("opaque wrapper");
    install_fixture(&wrapper, DOTNET_FILE_NAME);
    #[cfg(unix)]
    let actions = ["reenter-spawn", "reenter-exec"];
    #[cfg(windows)]
    let actions = ["reenter-spawn"];
    for action in actions {
        let output = command(&home)
            .env("DOTNET_ROOT", &wrapper)
            .env("MUXLET_TEST_DISPATCHER", dispatcher())
            .env("MUXLET_FIXTURE_ACTION", action)
            .arg("--info")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("recursive dotnet forwarding"));
    }
    let output = command(&home)
        .env("DOTNET_ROOT", &wrapper)
        .env(
            "MUXLET_FORWARD_CHAIN",
            r#"[{"pid":4294967295,"started":0,"target":[]}]"#,
        )
        .arg("--info")
        .output()
        .unwrap();
    assert_success(&output);
    // The stale hop is dropped and only this dispatcher's own is passed on.
    let hops = forwarded_hops(&output);
    assert_eq!(hops.len(), 1, "{hops:?}");
    let target = fs::canonicalize(wrapper.join(DOTNET_FILE_NAME)).unwrap();
    assert_eq!(
        hops[0]["target"],
        serde_json::json!(target.as_os_str().as_encoded_bytes())
    );
    #[cfg(unix)]
    assert_eq!(
        hops[0]["pid"].to_string(),
        report(&output)
            .iter()
            .find_map(|line| line.strip_prefix("pid:"))
            .unwrap()
    );
}

#[test]
fn live_ancestor_hops_are_kept_but_reused_process_ids_are_not() {
    use serde_json::json;
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    let directory = temp_dir();
    let home = directory.path().join("home");
    let wrapper = directory.path().join("opaque wrapper");
    let target = fs::canonicalize(install_fixture(&wrapper, DOTNET_FILE_NAME)).unwrap();
    let target = target.as_os_str().as_encoded_bytes();
    // This test process is the parent of every dispatcher it starts.
    let pid = Pid::from_u32(std::process::id());
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    let started = system.process(pid).unwrap().start_time();
    let hop = |started: u64, target: &[u8]| {
        json!({
            "pid": pid.as_u32(),
            "started": started,
            "target": target,
        })
    };
    let forward = |hops: serde_json::Value| {
        command(&home)
            .env("DOTNET_ROOT", &wrapper)
            .env("MUXLET_FORWARD_CHAIN", hops.to_string())
            .arg("--info")
            .output()
            .unwrap()
    };

    let earlier = hop(started, b"another wrapper");
    let output = forward(json!([earlier]));
    assert_success(&output);
    let hops = forwarded_hops(&output);
    assert_eq!(hops.len(), 2, "{hops:?}");
    assert_eq!(hops[0], earlier);
    assert_eq!(hops[1]["target"], json!(target));

    // The same process ID with another start time belonged to another process.
    let output = forward(json!([hop(started + 1, target)]));
    assert_success(&output);
    assert_eq!(forwarded_hops(&output).len(), 1);

    let output = forward(json!([hop(started, target)]));
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("recursive dotnet forwarding"));
}

#[test]
fn malformed_or_excessive_forwarding_contexts_are_errors_for_opaque_wrappers() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let wrapper = directory.path().join("opaque wrapper");
    install_fixture(&wrapper, DOTNET_FILE_NAME);
    let stale = |count: usize| {
        let hops = vec![r#"{"pid":4294967295,"started":0,"target":[]}"#; count];
        format!("[{}]", hops.join(","))
    };
    let forward = |context: &OsStr| {
        command(&home)
            .env("DOTNET_ROOT", &wrapper)
            .env("MUXLET_FORWARD_CHAIN", context)
            .arg("--info")
            .output()
            .unwrap()
    };
    let refused = |context: &OsStr, expected: &str| {
        let output = forward(context);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains(expected), "{message}");
    };
    refused(
        "not JSON".as_ref(),
        "invalid internal Muxlet forwarding context",
    );
    refused(stale(65).as_ref(), "too many unresolved dotnet wrappers");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        // Windows limits one environment variable to 32,767 characters.
        refused(" ".repeat(64 * 1024 + 1).as_ref(), "too large");
        refused(OsStr::from_bytes(b"[\xff]"), "encoding");
    }

    let output = forward(stale(64).as_ref());
    assert_success(&output);
    assert_eq!(forwarded_hops(&output).len(), 1);
}

#[test]
fn wrapper_cycles_with_intermediate_processes_are_detected() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let first = directory.path().join("wrapper one");
    let second = directory.path().join("wrapper two");
    install_fixture(&first, DOTNET_FILE_NAME);
    install_fixture(&second, DOTNET_FILE_NAME);
    #[cfg(unix)]
    let actions = ["chain-spawn", "chain-exec"];
    #[cfg(windows)]
    let actions = ["chain-spawn"];
    for action in actions {
        let output = command(&home)
            .env("DOTNET_ROOT", &first)
            .env("MUXLET_TEST_DISPATCHER", dispatcher())
            .env("MUXLET_FIXTURE_ACTION", action)
            .env(
                "MUXLET_FIXTURE_ROOT_SEQUENCE",
                env::join_paths([&second, &first]).unwrap(),
            )
            .arg("--info")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("recursive dotnet forwarding"));
    }
}

#[test]
fn real_host_boundaries_allow_nested_sdk_invocations_including_through_opaque_wrappers() {
    let directory = temp_dir();
    let home = directory.path().join("home");
    let sdk = directory.path().join("sdk");
    let genuine = host(&sdk);
    let output = command(&home)
        .env("DOTNET_ROOT", &sdk)
        .env("MUXLET_TEST_DISPATCHER", dispatcher())
        .env("MUXLET_FIXTURE_ACTION", "nested")
        .env("MUXLET_FORWARD_CHAIN", "stale inherited context")
        .arg("--info")
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        reported_arguments(&output),
        [hex("--nested"), hex("nested value")]
    );

    let wrapper = directory.path().join("opaque wrapper");
    install_fixture(&wrapper, DOTNET_FILE_NAME);
    #[cfg(unix)]
    let actions = ["wrapper-to-host", "exec-wrapper-to-host"];
    #[cfg(windows)]
    let actions = ["wrapper-to-host"];
    for action in actions {
        let output = command(&home)
            .env("PATH", &wrapper)
            .env("MUXLET_TEST_DISPATCHER", dispatcher())
            .env("MUXLET_TEST_HOST", &genuine)
            .env("MUXLET_FIXTURE_ACTION", action)
            .arg("--info")
            .output()
            .unwrap();
        assert_success(&output);
        assert_eq!(
            reported_arguments(&output),
            [hex("--nested"), hex("nested value")]
        );
    }
}

#[cfg(unix)]
#[test]
fn unix_exec_preserves_signals_as_well_as_exit_codes() {
    use std::os::unix::process::ExitStatusExt;
    let directory = temp_dir();
    let home = directory.path().join("home");
    extension(&home, "foo");
    let output = command(&home)
        .env("MUXLET_FIXTURE_ACTION", "signal")
        .arg("foo")
        .output()
        .unwrap();
    assert_eq!(output.status.signal(), Some(15));
}

#[cfg(unix)]
#[test]
fn unix_exec_restores_default_sigpipe_handling_for_external_programs() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;

    let directory = temp_dir();
    let home = directory.path().join("home");
    let path = home.join("extensions/dotnet-foo");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        b"#!/bin/sh\nkill -PIPE \"$$\"\nprintf 'SIGPIPE was incorrectly ignored'\n",
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let output = command(&home).arg("foo").output().unwrap();
    assert_eq!(output.status.signal(), Some(libc::SIGPIPE));
    assert!(output.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn native_non_utf8_arguments_and_environment_are_lossless() {
    use std::os::unix::ffi::OsStringExt;
    let directory = temp_dir();
    let home = directory.path().join("home");
    extension(&home, "foo");
    let argument = OsString::from_vec(b"value with \xff and spaces".to_vec());
    let value = OsString::from_vec(b"environment \xfe".to_vec());
    let output = command(&home)
        .arg("foo")
        .arg(&argument)
        .env("MUXLET_TEST_VALUE", &value)
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(reported_arguments(&output), [hex(&argument)]);
    assert!(report(&output).contains(&format!("env:MUXLET_TEST_VALUE:{}", hex(value))));
}

#[cfg(unix)]
#[test]
fn non_utf8_configuration_filenames_need_no_filesystem_access() {
    use std::os::unix::ffi::OsStringExt;
    let directory = temp_dir();
    let home = directory
        .path()
        .join(OsString::from_vec(b"home-\xff".to_vec()));
    let output = command(&home)
        .args(["dispatcher", "configuration"])
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(output.stdout, path_line(&home.join("configuration.json")));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_supports_native_non_utf8_home_and_extension_filenames() {
    use std::os::unix::ffi::OsStringExt;
    let directory = temp_dir();
    let home = directory
        .path()
        .join(OsString::from_vec(b"home-\xff".to_vec()));
    let name = OsString::from_vec(b"foo-\xfe".to_vec());
    extension(&home, &name);
    let output = command(&home).arg(name).arg("a b").output().unwrap();
    assert_success(&output);
    assert_eq!(reported_arguments(&output), [hex("a b")]);
}

#[cfg(windows)]
#[test]
fn windows_native_exit_results_preserve_all_bits_without_a_console() {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
    let directory = temp_dir();
    let home = directory.path().join("home");
    extension(&home, "foo");
    let output = command(&home)
        .creation_flags(CREATE_NO_WINDOW)
        .env("MUXLET_FIXTURE_EXIT_CODE", "-1073741510")
        .arg("foo")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(-1073741510));
}

#[cfg(windows)]
#[test]
fn windows_console_controls_reach_the_child_and_preserve_its_exit_result() {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE;
    let directory = temp_dir();
    let home = directory.path().join("home");
    let sdk = directory.path().join("sdk");
    host(&sdk);
    for event in ["0", "1"] {
        let mut child = Command::new(fixture())
            .creation_flags(CREATE_NEW_CONSOLE)
            .env("DOTNET_SDK_HOME", &home)
            .env("DOTNET_ROOT", &sdk)
            .env("MUXLET_TEST_DISPATCHER", dispatcher())
            .env("MUXLET_FIXTURE_ACTION", "console-controller")
            .env("MUXLET_TEST_CONTROL_EVENT", event)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if child.try_wait().unwrap().is_some() {
                let output = child.wait_with_output().unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(73),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                panic!("console event {event} was not delivered within 20 seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
