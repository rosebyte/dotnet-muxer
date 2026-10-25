//! Tests of safe core placement: the library service and the `muxlet-install` helper.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::{assert_success, dispatcher, installer, temp_dir};
use muxlet::config::{self, Fingerprint, HomeLock};
use muxlet::executable::{self, DOTNET_FILE_NAME};
use muxlet::home;
use muxlet::placement::{self, Outcome, Previous, Request};

const LAYOUT: [&str; 6] = [
    "bin",
    "extensions",
    "metadata",
    "journal",
    "cache",
    "staging",
];

struct World {
    _directory: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

fn world() -> World {
    let directory = temp_dir();
    let root = directory.path().to_owned();
    let home = root.join("application home");
    World {
        _directory: directory,
        root,
        home,
    }
}

impl World {
    fn request(&self, source: &Path) -> Request {
        request(source, &self.home)
    }

    fn installed(&self) -> PathBuf {
        placement::default_destination(&self.home)
    }
}

/// A request that cannot be influenced by the environment of the test run.
fn request(source: &Path, home: &Path) -> Request {
    let mut request = Request::new(source, home);
    request.managed_roots.clear();
    request.lock_timeout = Duration::from_secs(10);
    request
}

/// A file that the installer accepts as a dispatcher: a native header, a
/// distinguishing label and the identity marker.
fn dispatcher_image(label: &str) -> Vec<u8> {
    let mut bytes = if cfg!(windows) {
        b"MZ\x90\x00".to_vec()
    } else {
        b"\x7fELF".to_vec()
    };
    bytes.extend_from_slice(label.as_bytes());
    bytes.extend_from_slice(&executable::dispatcher_marker());
    bytes.extend_from_slice(b"\0end");
    bytes
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) -> PathBuf {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    path.to_owned()
}

fn chmod(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

fn mode_of(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        0
    }
}

fn write_dispatcher(path: &Path, label: &str) -> PathBuf {
    let path = write(path, dispatcher_image(label));
    chmod(&path, 0o755);
    path
}

fn symlink(original: &impl AsRef<Path>, link: &Path) -> bool {
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(original.as_ref(), link).unwrap();
        true
    }
    #[cfg(windows)]
    {
        // Creating links needs Developer Mode or elevation; skip without it.
        std::os::windows::fs::symlink_file(original.as_ref(), link).is_ok()
    }
}

#[cfg(unix)]
fn symlink_dir(original: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(original, link).unwrap();
    true
}

#[cfg(unix)]
fn fifo(path: &Path) -> bool {
    Command::new("mkfifo")
        .arg(path)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Every entry below `root` with its kind, link text, mode and content identity.
fn tree(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, directory: &Path, entries: &mut BTreeMap<String, String>) {
        let Ok(children) = fs::read_dir(directory) else {
            return;
        };
        for child in children {
            let path = child.unwrap().path();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let kind = fs::symlink_metadata(&path).unwrap().file_type();
            if kind.is_symlink() {
                let text = fs::read_link(&path).unwrap();
                entries.insert(relative, format!("link {}", text.display()));
            } else if kind.is_dir() {
                entries.insert(relative, "directory".to_owned());
                walk(root, &path, entries);
            } else if kind.is_file() {
                let content = Fingerprint::of(&fs::read(&path).unwrap());
                entries.insert(relative, format!("file {:o} {content}", mode_of(&path)));
            } else {
                entries.insert(relative, "special".to_owned());
            }
        }
    }
    let mut entries = BTreeMap::new();
    walk(root, root, &mut entries);
    entries
}

fn stage_leftovers(root: &Path) -> Vec<String> {
    tree(root)
        .into_keys()
        .filter(|name| name.ends_with(".muxlet-stage"))
        .collect()
}

/// What a path currently is, for checking that a refusal left it as it was
/// even when the path (such as `/usr/bin/dotnet`) may legitimately exist.
#[cfg(unix)]
fn state(path: &Path) -> String {
    match fs::symlink_metadata(path) {
        Ok(metadata) => format!(
            "{:?} {} {:?}",
            metadata.file_type(),
            metadata.len(),
            metadata.modified().ok()
        ),
        Err(error) => format!("{:?}", error.kind()),
    }
}

fn failure(result: anyhow::Result<Outcome>) -> String {
    format!(
        "{:#}",
        result.expect_err("the installation should have been refused")
    )
}

fn assert_refused(world: &World, request: &Request, expected: &str) {
    let before = tree(&world.root);
    let message = failure(placement::install(request));
    assert!(
        message.contains(expected),
        "expected '{expected}' in: {message}"
    );
    assert_eq!(
        tree(&world.root),
        before,
        "a refusal must not change anything"
    );
}

/// Freshly copied executables can briefly be "text file busy" on Linux while
/// another test thread still holds the copy's descriptor across a fork.
fn retrying<T>(mut attempt: impl FnMut() -> std::io::Result<T>) -> T {
    for _ in 0..50 {
        match attempt() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                thread::sleep(Duration::from_millis(100));
            }
            result => return result.unwrap(),
        }
    }
    attempt().unwrap()
}

fn run(command: &mut Command) -> Output {
    retrying(|| command.output())
}

fn spawn(command: &mut Command) -> Child {
    retrying(|| command.spawn())
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The helper in a hermetic environment: no inherited DOTNET_ROOT, and a HOME
/// that is not the real one even if something wrongly consulted it.
fn helper(world: &World) -> Command {
    let mut command = Command::new(installer());
    command
        .env_remove("DOTNET_ROOT")
        .env_remove("DOTNET_ROOT_X64")
        .env_remove("DOTNET_ROOT_X86")
        .env_remove("DOTNET_ROOT_ARM64")
        .env_remove("DOTNET_ROOT(x86)")
        .env("DOTNET_SDK_HOME", &world.home)
        .env("HOME", world.root.join("fake user profile"))
        .env_remove("XDG_DATA_HOME");
    command
}

// ---------------------------------------------------------------------------
// Placement semantics (library)
// ---------------------------------------------------------------------------

#[test]
fn installation_creates_only_the_layout_and_places_an_executable_core() {
    let world = world();
    let source = write_dispatcher(&world.root.join("build output/dotnet"), "version one");

    let outcome = placement::install(&world.request(&source)).unwrap();

    assert_eq!(
        outcome,
        Outcome {
            destination: world.installed(),
            previous: Previous::Absent,
            backup: None,
        }
    );
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("version one")
    );
    assert!(executable::is_dispatcher(&world.installed()).unwrap());
    #[cfg(unix)]
    assert_eq!(mode_of(&world.installed()), 0o755);

    for name in LAYOUT {
        assert!(world.home.join(name).is_dir(), "{name}");
    }
    assert!(config::lock_path(&world.home).is_file());
    assert!(!home::configuration(&world.home).exists());
    assert_eq!(
        fs::read_dir(world.home.join("extensions")).unwrap().count(),
        0
    );
    assert_eq!(fs::read_dir(world.home.join("journal")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(world.home.join("staging")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(world.home.join("bin")).unwrap().count(), 1);
    assert_eq!(stage_leftovers(&world.root), Vec::<String>::new());
}

#[cfg(unix)]
#[test]
fn the_installed_mode_follows_the_source_without_special_bits() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "restricted");
    chmod(&source, 0o750);
    placement::install(&world.request(&source)).unwrap();
    assert_eq!(mode_of(&world.installed()), 0o750);

    let source = write_dispatcher(&world.root.join("other/dotnet"), "special bits");
    chmod(&source, 0o4755);
    placement::install(&world.request(&source)).unwrap();
    assert_eq!(mode_of(&world.installed()), 0o755);
}

#[test]
fn an_existing_file_is_replaced_without_a_backup_by_default() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    write(&world.installed(), "old dispatcher");

    let outcome = placement::install(&world.request(&source)).unwrap();

    assert_eq!(outcome.previous, Previous::File);
    assert_eq!(outcome.backup, None);
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("new")
    );
    let names: Vec<_> = fs::read_dir(world.home.join("bin"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        [DOTNET_FILE_NAME],
        "no backup or staging file may remain"
    );
    assert_eq!(stage_leftovers(&world.root), Vec::<String>::new());
}

#[test]
fn a_backup_saves_the_old_file_at_exactly_the_requested_path_overwriting_an_older_backup() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    write(&world.installed(), "old dispatcher");
    chmod(&world.installed(), 0o750);
    let backup = write(&world.home.join("staging/previous core"), "an older backup");

    let mut request = world.request(&source);
    request.backup = Some(backup.clone());
    let outcome = placement::install(&request).unwrap();

    assert_eq!(outcome.previous, Previous::File);
    assert_eq!(outcome.backup, Some(backup.clone()));
    assert_eq!(fs::read(&backup).unwrap(), b"old dispatcher");
    #[cfg(unix)]
    assert_eq!(mode_of(&backup), 0o750);
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("new")
    );
    let staged: Vec<_> = fs::read_dir(world.home.join("staging"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(staged, ["previous core"]);

    // A backup outside the home works the same way and needs no numbering.
    let outside = write(&world.root.join("backups/dotnet.old"), "unrelated");
    write(&world.installed(), "second old");
    let mut request = world.request(&source);
    request.backup = Some(outside.clone());
    placement::install(&request).unwrap();
    assert_eq!(fs::read(&outside).unwrap(), b"second old");
    assert_eq!(
        fs::read_dir(world.root.join("backups")).unwrap().count(),
        1,
        "no numbered or staged siblings"
    );
}

#[test]
fn an_existing_backup_is_left_untouched_when_there_was_no_destination() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let backup = write(&world.root.join("backups/previous"), "precious backup");
    let modified = fs::metadata(&backup).unwrap().modified().unwrap();

    let mut request = world.request(&source);
    request.backup = Some(backup.clone());
    let outcome = placement::install(&request).unwrap();

    assert_eq!(outcome.previous, Previous::Absent);
    assert_eq!(outcome.backup, None, "nothing was saved");
    assert_eq!(fs::read(&backup).unwrap(), b"precious backup");
    assert_eq!(fs::metadata(&backup).unwrap().modified().unwrap(), modified);
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("new")
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_destination_is_an_entry_replaced_without_touching_its_target() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let target = write(&world.root.join("targets/real-dotnet"), "precious target");
    assert!(symlink(&"../../targets/real-dotnet", &world.installed()));
    assert_eq!(fs::read(world.installed()).unwrap(), b"precious target");

    let outcome = placement::install(&world.request(&source)).unwrap();

    assert_eq!(outcome.previous, Previous::Symlink);
    assert!(fs::symlink_metadata(world.installed()).unwrap().is_file());
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("new")
    );
    assert_eq!(fs::read(&target).unwrap(), b"precious target");
}

#[cfg(unix)]
#[test]
fn a_symlink_destination_is_backed_up_as_a_link_with_its_stored_text() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let target = write(&world.root.join("targets/real-dotnet"), "precious target");
    assert!(symlink(&"../../targets/real-dotnet", &world.installed()));
    let backup = world.root.join("backups elsewhere/previous link");
    fs::create_dir_all(backup.parent().unwrap()).unwrap();

    let mut request = world.request(&source);
    request.backup = Some(backup.clone());
    let outcome = placement::install(&request).unwrap();

    assert_eq!(outcome.previous, Previous::Symlink);
    assert_eq!(outcome.backup, Some(backup.clone()));
    // The link text is preserved verbatim, so it now resolves relative to the
    // backup's own directory, exactly as the stored text says.
    assert!(
        fs::symlink_metadata(&backup)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_link(&backup).unwrap(),
        Path::new("../../targets/real-dotnet")
    );
    assert_eq!(fs::read(&target).unwrap(), b"precious target");
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("new")
    );
}

#[cfg(unix)]
#[test]
fn a_dangling_symlink_destination_can_be_replaced_and_backed_up() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    assert!(symlink(&"nowhere/at all", &world.installed()));
    let backup = world.root.join("old link");

    let mut request = world.request(&source);
    request.backup = Some(backup.clone());
    placement::install(&request).unwrap();

    assert_eq!(fs::read_link(&backup).unwrap(), Path::new("nowhere/at all"));
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("new")
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_at_the_backup_path_is_replaced_not_followed() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    write(&world.installed(), "old dispatcher");
    let precious = write(&world.root.join("precious file"), "do not touch");
    let backup = world.root.join("backups/previous");
    assert!(symlink(&precious, &backup));

    let mut request = world.request(&source);
    request.backup = Some(backup.clone());
    placement::install(&request).unwrap();

    assert!(fs::symlink_metadata(&backup).unwrap().is_file());
    assert_eq!(fs::read(&backup).unwrap(), b"old dispatcher");
    assert_eq!(fs::read(&precious).unwrap(), b"do not touch");

    // A dangling link there is replaced too.
    write(&world.installed(), "another old one");
    fs::remove_file(&backup).unwrap();
    assert!(symlink(&world.root.join("gone"), &backup));
    placement::install(&request).unwrap();
    assert_eq!(fs::read(&backup).unwrap(), b"another old one");
    assert!(!world.root.join("gone").exists());
}

#[cfg(unix)]
#[test]
fn a_link_to_a_genuine_launcher_is_replaced_but_the_launcher_is_untouched() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let root = world.root.join("genuine root");
    fs::create_dir_all(root.join("host/fxr/9.0.0")).unwrap();
    let launcher = write(&root.join(DOTNET_FILE_NAME), "genuine launcher");
    assert!(symlink(&launcher, &world.installed()));

    placement::install(&world.request(&source)).unwrap();

    assert_eq!(fs::read(&launcher).unwrap(), b"genuine launcher");
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("new")
    );
}

#[test]
fn directories_are_refused_for_the_destination_and_the_backup() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");

    // The destination is an actual directory.
    fs::create_dir_all(world.installed().join("inside")).unwrap();
    assert_refused(&world, &world.request(&source), "is a directory");

    // The backup is an actual directory.
    fs::remove_dir_all(world.installed()).unwrap();
    write(&world.installed(), "old");
    let backups = world.root.join("backups");
    fs::create_dir_all(backups.join("kept")).unwrap();
    let mut request = world.request(&source);
    request.backup = Some(backups.clone());
    assert_refused(&world, &request, "is a directory");
    assert_eq!(fs::read(world.installed()).unwrap(), b"old");

    // Even when no backup would be needed.
    fs::remove_file(world.installed()).unwrap();
    assert_refused(&world, &request, "is a directory");
}

#[cfg(unix)]
#[test]
fn special_files_are_refused_for_the_destination_and_the_backup() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    fs::create_dir_all(world.home.join("bin")).unwrap();
    if !fifo(&world.installed()) {
        return;
    }
    assert_refused(&world, &world.request(&source), "special file");

    fs::remove_file(world.installed()).unwrap();
    write(&world.installed(), "old");
    let backup = world.root.join("a fifo");
    assert!(fifo(&backup));
    let mut request = world.request(&source);
    request.backup = Some(backup);
    assert_refused(&world, &request, "special file");
}

#[test]
fn directory_names_are_not_complete_file_names() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let directory = world.home.join("bin");
    for destination in [
        format!("{}/", directory.display()),
        format!("{}/.", directory.display()),
        format!("{}/..", directory.display()),
    ] {
        let mut request = world.request(&source);
        request.destination = PathBuf::from(&destination);
        let message = failure(placement::install(&request));
        assert!(
            message.contains("complete file name"),
            "{destination}: {message}"
        );
        assert!(
            !world.home.exists(),
            "{destination}: nothing may be created"
        );
    }

    write(&world.installed(), "old");
    let mut request = world.request(&source);
    request.backup = Some(PathBuf::from(format!(
        "{}/",
        world.root.join("backups").display()
    )));
    assert_refused(&world, &request, "complete file name");
}

#[test]
fn the_destination_and_the_backup_must_be_different_entries() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    write(&world.installed(), "old");

    // The same path, with or without an old destination.
    let mut request = world.request(&source);
    request.backup = Some(world.installed());
    assert_refused(&world, &request, "same entry");
    fs::remove_file(world.installed()).unwrap();
    assert_refused(&world, &request, "same entry");
    write(&world.installed(), "old");

    // The same path spelled differently.
    let mut request = world.request(&source);
    request.backup = Some(world.home.join("bin/../bin/./").join(DOTNET_FILE_NAME));
    assert_refused(&world, &request, "same entry");
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn names_that_differ_only_by_case_are_the_same_entry_on_case_insensitive_systems() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    write(&world.installed(), "old");
    let mut request = world.request(&source);
    request.backup = Some(world.home.join("bin").join(DOTNET_FILE_NAME.to_uppercase()));
    assert_refused(&world, &request, "same entry");
}

#[cfg(unix)]
#[test]
fn a_parent_directory_alias_cannot_hide_that_destination_and_backup_collide() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    write(&world.installed(), "old");
    let alias = world.root.join("alias to bin");
    assert!(symlink_dir(&world.home.join("bin"), &alias));

    let mut request = world.request(&source);
    request.destination = alias.join(DOTNET_FILE_NAME);
    request.backup = Some(world.installed());
    assert_refused(&world, &request, "same entry");

    let mut request = world.request(&source);
    request.backup = Some(alias.join(DOTNET_FILE_NAME));
    assert_refused(&world, &request, "same entry");

    // A hard link is the same file under another name.
    let linked = world.root.join("hard link");
    fs::hard_link(world.installed(), &linked).unwrap();
    let mut request = world.request(&source);
    request.backup = Some(linked);
    assert_refused(&world, &request, "same entry");
}

#[test]
fn the_source_cannot_be_the_destination_or_the_backup() {
    let world = world();
    let installed = write_dispatcher(&world.installed(), "already installed");

    // Installing the installed file onto itself.
    assert_refused(&world, &world.request(&installed), "is the destination");

    // Installing onto the source through a differently spelled path.
    let mut request = world.request(&installed);
    request.destination = world.home.join("bin/../bin").join(DOTNET_FILE_NAME);
    assert_refused(&world, &request, "is the destination");

    // Saving the old entry over the source.
    let source = write_dispatcher(&world.root.join("source/dotnet"), "other");
    let mut request = world.request(&source);
    request.backup = Some(source.clone());
    assert_refused(&world, &request, "is the source");
    assert_eq!(fs::read(&source).unwrap(), dispatcher_image("other"));
}

#[cfg(unix)]
#[test]
fn hard_links_and_links_to_the_backup_are_collisions_too() {
    let world = world();
    let source = write_dispatcher(&world.root.join("source/dotnet"), "other");

    // A destination that is a hard link of the source.
    fs::create_dir_all(world.home.join("bin")).unwrap();
    fs::hard_link(&source, world.installed()).unwrap();
    assert_refused(&world, &world.request(&source), "is the destination");
    fs::remove_file(world.installed()).unwrap();

    // A backup that is a hard link of the source.
    write(&world.installed(), "old");
    let linked = world.root.join("backups/linked source");
    fs::create_dir_all(linked.parent().unwrap()).unwrap();
    fs::hard_link(&source, &linked).unwrap();
    let mut request = world.request(&source);
    request.backup = Some(linked);
    assert_refused(&world, &request, "is the source");
    fs::remove_file(world.installed()).unwrap();

    // A destination link whose target is the backup file.
    let target = write(&world.root.join("backups/target"), "target");
    assert!(symlink(&target, &world.installed()));
    let mut request = world.request(&source);
    request.backup = Some(target.clone());
    assert_refused(&world, &request, "points to");
    assert_eq!(fs::read(&target).unwrap(), b"target");
}

#[cfg(unix)]
#[test]
fn protected_system_locations_are_refused_before_anything_is_written() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");

    for destination in [
        "/usr/bin/dotnet",
        "/bin/dotnet",
        "/sbin/dotnet",
        "/usr/lib/dotnet",
        "/etc/muxlet/dotnet",
        "/System/dotnet",
        "/dotnet",
    ] {
        let before = state(Path::new(destination));
        let mut request = world.request(&source);
        request.destination = PathBuf::from(destination);
        let message = failure(placement::install(&request));
        assert!(
            message.contains("protected system location"),
            "{destination}: {message}"
        );
        assert_eq!(state(Path::new(destination)), before, "{destination}");
        assert!(
            !world.home.exists(),
            "{destination}: the home must not be created"
        );
    }

    // A backup in a protected place is refused even when the destination is fine.
    write(&world.installed(), "old");
    let mut request = world.request(&source);
    request.backup = Some(PathBuf::from("/usr/bin/dotnet.old"));
    assert_refused(&world, &request, "protected system location");

    // An application home in a protected place is refused.
    let mut request = world.request(&source);
    request.home = PathBuf::from("/etc/muxlet-test-home");
    request.destination = world.root.join("elsewhere/dotnet");
    fs::create_dir_all(world.root.join("elsewhere")).unwrap();
    assert_refused(&world, &request, "application home");
    assert!(!Path::new("/etc/muxlet-test-home").exists());
}

#[cfg(unix)]
#[test]
fn a_directory_alias_to_a_protected_location_is_still_protected() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let alias = world.root.join("innocent looking");
    assert!(symlink_dir(Path::new("/usr/bin"), &alias));
    let before = state(Path::new("/usr/bin/dotnet"));

    let mut request = world.request(&source);
    request.destination = alias.join("dotnet");
    assert_refused(&world, &request, "protected system location");
    assert_eq!(state(Path::new("/usr/bin/dotnet")), before);

    write(&world.installed(), "old");
    let mut request = world.request(&source);
    request.backup = Some(alias.join("dotnet.old"));
    assert_refused(&world, &request, "protected system location");
}

#[cfg(target_os = "macos")]
#[test]
fn protection_ignores_case_on_case_insensitive_volumes() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let before = state(Path::new("/usr/bin/dotnet"));
    let mut request = world.request(&source);
    request.destination = PathBuf::from("/USR/BIN/dotnet");
    assert_refused(&world, &request, "protected system location");
    assert_eq!(state(Path::new("/usr/bin/dotnet")), before);
}

#[cfg(windows)]
#[test]
fn windows_system_locations_are_refused_before_anything_is_written() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet.exe"), "new");
    for variable in ["SystemRoot", "ProgramFiles", "ProgramData"] {
        let Some(area) = std::env::var_os(variable) else {
            continue;
        };
        let mut request = world.request(&source);
        request.destination = PathBuf::from(area).join("muxlet-test-dotnet.exe");
        let message = failure(placement::install(&request));
        assert!(
            message.contains("protected system location"),
            "{variable}: {message}"
        );
        assert!(!request.destination.exists());
        assert!(!world.home.exists());
    }
}

fn genuine_root(path: &Path) -> PathBuf {
    fs::create_dir_all(path.join("host/fxr/9.0.0")).unwrap();
    write(&path.join(DOTNET_FILE_NAME), "genuine launcher")
}

#[test]
fn the_launcher_of_a_genuine_root_is_never_replaced() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let root = world.root.join("genuine root");
    let launcher = genuine_root(&root);

    let mut request = world.request(&source);
    request.destination = launcher.clone();
    assert_refused(&world, &request, "installation root");
    assert_eq!(fs::read(&launcher).unwrap(), b"genuine launcher");

    // Neither is anything else placed beside it, nor a backup written there.
    let mut request = world.request(&source);
    request.destination = root.join("dotnet-muxlet");
    assert_refused(&world, &request, "installation root");

    write(&world.installed(), "old");
    let mut request = world.request(&source);
    request.backup = Some(root.join("dotnet.old"));
    assert_refused(&world, &request, "installation root");
    assert_eq!(fs::read(&launcher).unwrap(), b"genuine launcher");
}

#[test]
fn every_recognisable_runtime_or_sdk_layout_protects_its_directory() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    for (name, directories) in [
        ("host layout", &["host/fxr"][..]),
        ("runtime layout", &["shared/Microsoft.NETCore.App/9.0.0"]),
        ("sdk layout", &["sdk/9.0.100", "shared"]),
    ] {
        let root = world.root.join(name);
        for directory in directories {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        let launcher = write(&root.join(DOTNET_FILE_NAME), name);
        let mut request = world.request(&source);
        request.destination = launcher.clone();
        assert_refused(&world, &request, "installation root");
        assert_eq!(fs::read(&launcher).unwrap(), name.as_bytes());
    }

    // An ordinary directory that merely contains an sdk folder is not a root.
    let ordinary = world.root.join("my tools");
    fs::create_dir_all(ordinary.join("sdk")).unwrap();
    let mut request = world.request(&source);
    request.destination = ordinary.join(DOTNET_FILE_NAME);
    placement::install(&request).unwrap();
}

#[cfg(unix)]
#[test]
fn an_alias_of_a_genuine_root_does_not_hide_it() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let root = world.root.join("genuine root");
    let launcher = genuine_root(&root);
    let alias = world.root.join("friendly alias");
    assert!(symlink_dir(&root, &alias));

    let mut request = world.request(&source);
    request.destination = alias.join(DOTNET_FILE_NAME);
    assert_refused(&world, &request, "installation root");
    assert_eq!(fs::read(&launcher).unwrap(), b"genuine launcher");
}

#[test]
fn an_explicit_dotnet_root_is_protected_even_without_a_recognisable_layout() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let plain = world.root.join("explicit root");
    let launcher = write(
        &plain.join(DOTNET_FILE_NAME),
        "wrapper script or partial root",
    );

    let mut request = world.request(&source);
    request.managed_roots = vec![plain.clone()];
    request.destination = launcher.clone();
    assert_refused(&world, &request, "selected by the environment");
    assert_eq!(
        fs::read(&launcher).unwrap(),
        b"wrapper script or partial root"
    );

    // Any selected root counts, and it protects a backup location too.
    write(&world.installed(), "old");
    let mut request = world.request(&source);
    request.managed_roots = vec![
        PathBuf::from("relative root"),
        world.root.join("missing"),
        plain.clone(),
    ];
    request.backup = Some(plain.join("dotnet.old"));
    assert_refused(&world, &request, "selected by the environment");

    // Unusable selections (relative or missing) protect nothing and do not fail.
    let mut request = world.request(&source);
    request.managed_roots = vec![PathBuf::from("relative root"), world.root.join("missing")];
    placement::install(&request).unwrap();
}

#[test]
fn a_future_managed_root_is_protected_before_creating_the_home() {
    let world = world();
    let source = write_dispatcher(&world.root.join("source"), "new");
    let mut request = world.request(&source);
    request.managed_roots = vec![world.home.join("bin")];
    let error = placement::install(&request).unwrap_err();
    assert!(format!("{error:#}").contains("selected by the environment"));
    assert!(!world.home.exists());
}

#[test]
fn the_source_must_be_a_verified_dispatcher() {
    let world = world();
    write(&world.installed(), "old");

    // Native code that is not a dispatcher, an empty file, a directory, nothing.
    let mut native = b"\x7fELF".to_vec();
    if cfg!(windows) {
        native = b"MZ\x90\x00".to_vec();
    }
    native.extend_from_slice(b"some other program");
    let not_dispatcher = write(&world.root.join("other program"), native);
    chmod(&not_dispatcher, 0o755);
    let empty = write(&world.root.join("empty"), "");
    chmod(&empty, 0o755);
    let directory = world.root.join("a directory");
    fs::create_dir_all(&directory).unwrap();

    for (source, expected) in [
        (not_dispatcher, "not a Muxlet dispatcher"),
        (PathBuf::from(installer()), "not a Muxlet dispatcher"),
        (empty, "usable executable"),
        (directory, "usable executable"),
        (world.root.join("missing"), "usable executable"),
    ] {
        assert_refused(&world, &world.request(&source), expected);
    }
    assert_eq!(fs::read(world.installed()).unwrap(), b"old");
}

#[cfg(unix)]
#[test]
fn scripts_and_non_executable_files_are_not_accepted_as_the_source() {
    let world = world();
    write(&world.installed(), "old");
    let script = write(&world.root.join("script"), "#!/bin/sh\nexit 0\n");
    chmod(&script, 0o755);
    assert_refused(&world, &world.request(&script), "not a Muxlet dispatcher");

    let plain = write(&world.root.join("plain dispatcher"), dispatcher_image("x"));
    chmod(&plain, 0o644);
    assert_refused(&world, &world.request(&plain), "usable executable");
}

#[test]
fn a_linked_source_is_copied_by_content_and_the_real_dispatcher_is_accepted() {
    let world = world();
    let real = write_dispatcher(&world.root.join("real/dotnet"), "through a link");
    let link = world.root.join("linked source");
    if symlink(&real, &link) {
        placement::install(&world.request(&link)).unwrap();
        assert!(fs::symlink_metadata(world.installed()).unwrap().is_file());
        assert_eq!(
            fs::read(world.installed()).unwrap(),
            dispatcher_image("through a link")
        );
    }

    let outcome = placement::install(&world.request(dispatcher())).unwrap();
    assert_eq!(outcome.previous, Previous::File);
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        fs::read(dispatcher()).unwrap()
    );
    assert!(executable::is_dispatcher(&world.installed()).unwrap());
}

#[test]
fn inside_the_home_only_bin_and_staging_may_receive_files() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    placement::install(&world.request(&source)).unwrap();
    let configuration = write(&home::configuration(&world.home), r#"{"schemaVersion":9}"#);
    let extension = write(&world.home.join("extensions/dotnet-sdks"), "an extension");
    let metadata = write(&world.home.join("metadata/state"), "metadata");
    let journal = write(&world.home.join("journal/recovery"), "recovery");
    let cache = write(&world.home.join("cache/download"), "cache");
    let before = tree(&world.root);

    for protected in [
        &configuration,
        &extension,
        &metadata,
        &journal,
        &cache,
        &world.home.join("extensions/dotnet-new"),
        &world.home.join("dotnet"),
    ] {
        let mut request = world.request(&source);
        request.destination = protected.clone();
        let message = failure(placement::install(&request));
        assert!(
            message.contains("application home"),
            "{}: {message}",
            protected.display()
        );

        // Nor may an old destination be saved over an extension or user data.
        let mut request = world.request(&source);
        request.backup = Some(protected.clone());
        let message = failure(placement::install(&request));
        assert!(
            message.contains("application home"),
            "{}: {message}",
            protected.display()
        );
    }
    assert_eq!(tree(&world.root), before);

    // bin and staging are the places core owns.
    let mut request = world.request(&source);
    request.backup = Some(world.home.join("staging/previous core"));
    placement::install(&request).unwrap();
    request.backup = Some(world.home.join("bin/dotnet.previous"));
    placement::install(&request).unwrap();
    assert!(world.home.join("staging/previous core").is_file());
    assert!(world.home.join("bin/dotnet.previous").is_file());
}

#[cfg(unix)]
#[test]
fn links_inside_the_home_cannot_redirect_a_backup_onto_extension_files() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let real_extensions = world.root.join("real extensions");
    let extension = write(&real_extensions.join("dotnet-sdks"), "an extension");
    fs::create_dir_all(&world.home).unwrap();
    assert!(symlink_dir(
        &real_extensions,
        &world.home.join("extensions")
    ));
    write(&world.installed(), "old");

    let mut request = world.request(&source);
    request.backup = Some(extension.clone());
    assert_refused(&world, &request, "application home");
    assert_eq!(fs::read(&extension).unwrap(), b"an extension");

    let mut request = world.request(&source);
    request.backup = Some(world.home.join("extensions/dotnet-sdks"));
    assert_refused(&world, &request, "application home");
}

#[test]
fn only_the_applications_own_directories_are_created() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");

    // A missing destination directory elsewhere is the user's to create.
    let mut request = world.request(&source);
    request.destination = world.root.join("not there/dotnet");
    let message = failure(placement::install(&request));
    assert!(message.contains("does not exist"), "{message}");
    assert!(
        message.contains("only the application home's own directories"),
        "{message}"
    );
    assert!(!world.root.join("not there").exists());
    assert!(!world.home.exists());

    // Likewise for the backup directory.
    write(&world.installed(), "old");
    let mut request = world.request(&source);
    request.backup = Some(world.root.join("not there/old"));
    assert_refused(&world, &request, "does not exist");

    // The home itself, with its missing parents, is created.
    let nested = world.root.join("a/b/c/home");
    placement::install(&crate::request(&source, &nested)).unwrap();
    assert!(nested.join("bin").join(DOTNET_FILE_NAME).is_file());
}

#[test]
fn the_layout_directories_themselves_are_not_file_names_for_core() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    for name in ["bin", "staging"] {
        let mut request = world.request(&source);
        request.destination = world.home.join(name);
        let message = failure(placement::install(&request));
        assert!(
            message.contains("not under its bin or staging directory"),
            "{name}: {message}"
        );
        assert!(!world.home.exists(), "{name}: nothing may be created");
    }

    write(&world.installed(), "old");
    let mut request = world.request(&source);
    request.backup = Some(world.home.join("staging"));
    assert_refused(&world, &request, "not under its bin or staging directory");
}

#[cfg(unix)]
#[test]
fn a_layout_directory_may_be_a_link_to_another_directory() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let real_bin = world.root.join("real bin");
    fs::create_dir_all(&real_bin).unwrap();
    fs::create_dir_all(&world.home).unwrap();
    assert!(symlink_dir(&real_bin, &world.home.join("bin")));

    placement::install(&world.request(&source)).unwrap();

    assert_eq!(
        fs::read(real_bin.join(DOTNET_FILE_NAME)).unwrap(),
        dispatcher_image("new")
    );
    assert!(
        fs::symlink_metadata(world.home.join("bin"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(stage_leftovers(&world.root), Vec::<String>::new());
}

/// Run with `--ignored` and a directory on another filesystem (for example
/// `/dev/shm`, or another drive on Windows) to exercise real cross-device
/// placement. A directory on the same filesystem is not a substitute.
#[test]
#[ignore = "set MUXLET_TEST_FOREIGN_DIRECTORY to a writable directory on another filesystem"]
fn artefacts_are_staged_on_the_filesystem_they_end_up_on() {
    let base = std::env::var_os("MUXLET_TEST_FOREIGN_DIRECTORY")
        .expect("MUXLET_TEST_FOREIGN_DIRECTORY must name a writable directory");
    let foreign = tempfile::Builder::new()
        .prefix("muxlet foreign \u{00e9}-")
        .tempdir_in(base)
        .unwrap();
    let world = world();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            fs::metadata(foreign.path()).unwrap().dev(),
            fs::metadata(&world.root).unwrap().dev(),
            "MUXLET_TEST_FOREIGN_DIRECTORY must be on another filesystem"
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, GetFileInformationByHandle,
        };
        let volume = |path: &Path| {
            let handle = fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(path)
                .unwrap();
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            assert_ne!(
                unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &mut info) },
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            info.dwVolumeSerialNumber
        };
        assert_ne!(
            volume(foreign.path()),
            volume(&world.root),
            "MUXLET_TEST_FOREIGN_DIRECTORY must be on another filesystem"
        );
    }
    let source = write_dispatcher(&world.root.join("dotnet"), "new");

    // The backup lives on another filesystem than the destination.
    write(&world.installed(), "old");
    let backup = foreign.path().join("previous core");
    let mut request = world.request(&source);
    request.backup = Some(backup.clone());
    placement::install(&request).unwrap();
    assert_eq!(fs::read(&backup).unwrap(), b"old");
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("new")
    );
    assert_eq!(tree(foreign.path()).len(), 1, "no staging file may remain");

    // The destination lives on another filesystem than the source and the home.
    let destination = foreign.path().join("dotnet copy");
    let mut request = world.request(&source);
    request.destination = destination.clone();
    request.backup = Some(world.root.join("backups/previous"));
    fs::create_dir_all(world.root.join("backups")).unwrap();
    write(&destination, "old on the foreign filesystem");
    placement::install(&request).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), dispatcher_image("new"));
    assert_eq!(
        fs::read(world.root.join("backups/previous")).unwrap(),
        b"old on the foreign filesystem"
    );
    assert_eq!(stage_leftovers(&world.root), Vec::<String>::new());
    assert_eq!(stage_leftovers(foreign.path()), Vec::<String>::new());

    // A link is recreated, not copied, across filesystems.
    #[cfg(unix)]
    {
        fs::remove_file(&destination).unwrap();
        assert!(symlink(&"relative/target", &destination));
        let backup = world.root.join("backups/link backup");
        let mut request = world.request(&source);
        request.destination = destination.clone();
        request.backup = Some(backup.clone());
        placement::install(&request).unwrap();
        assert_eq!(
            fs::read_link(&backup).unwrap(),
            Path::new("relative/target")
        );
        assert_eq!(fs::read(&destination).unwrap(), dispatcher_image("new"));
    }
}

#[test]
fn installation_works_with_spaces_and_non_ascii_characters_everywhere() {
    let world = world();
    let source = write_dispatcher(
        &world.root.join("b\u{00fc}ild \u{65e5}\u{672c}/dotnet"),
        "unicode",
    );
    let home = world.root.join("h\u{00f3}me \u{1f980} with spaces");
    let mut request = request(&source, &home);
    let backup = world.root.join("b\u{00e4}ckups/\u{00e9}ld version");
    fs::create_dir_all(backup.parent().unwrap()).unwrap();
    write(&request.destination, "old");
    request.backup = Some(backup.clone());
    placement::install(&request).unwrap();
    assert_eq!(fs::read(&backup).unwrap(), b"old");
    assert_eq!(
        fs::read(placement::default_destination(&home)).unwrap(),
        dispatcher_image("unicode")
    );
}

#[test]
fn an_upgrade_replaces_only_the_core_executable() {
    let world = world();
    let first = write_dispatcher(&world.root.join("v1/dotnet"), "version one");
    let second = write_dispatcher(&world.root.join("v2/dotnet"), "version two");
    placement::install(&world.request(&first)).unwrap();

    // Everything the user, extensions and earlier writes own.
    write(
        &home::configuration(&world.home),
        r#"{"schemaVersion":999,"extensions":{"sdks":{"independent":1}}}"#,
    );
    write(
        &world.home.join("extensions/dotnet-sdks"),
        "independently released SDKs extension",
    );
    write(
        &world.home.join("extensions/supporting data/file"),
        "extension-owned",
    );
    write(&world.home.join("metadata/state.json"), "metadata");
    write(
        &world
            .home
            .join("journal/configuration-20260101T000000Z-aaaaaaaaaaaa.json"),
        "recovery",
    );
    write(&world.home.join("cache/download.bin"), "cache");
    write(
        &world.home.join("bin/supporting file"),
        "core supporting file",
    );
    let before = tree(&world.home);

    let backup = world.home.join("staging/previous core");
    let mut request = world.request(&second);
    request.backup = Some(backup.clone());
    placement::install(&request).unwrap();

    let mut expected = before;
    let installed = format!("bin/{DOTNET_FILE_NAME}");
    expected.insert(
        installed.clone(),
        tree(&world.home).remove(&installed).unwrap(),
    );
    expected.insert(
        "staging/previous core".to_owned(),
        tree(&world.home).remove("staging/previous core").unwrap(),
    );
    assert_eq!(tree(&world.home), expected);
    assert_eq!(fs::read(&backup).unwrap(), dispatcher_image("version one"));
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("version two")
    );
    assert_eq!(
        fs::read_to_string(home::configuration(&world.home)).unwrap(),
        r#"{"schemaVersion":999,"extensions":{"sdks":{"independent":1}}}"#
    );
}

#[test]
fn reinstalling_the_same_dispatcher_is_idempotent() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "same");
    placement::install(&world.request(&source)).unwrap();
    let outcome = placement::install(&world.request(&source)).unwrap();
    assert_eq!(outcome.previous, Previous::File);
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("same")
    );
    assert_eq!(stage_leftovers(&world.root), Vec::<String>::new());
}

#[test]
fn installation_serialises_with_other_writers_through_the_shared_lock() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    write(&world.installed(), "old");

    let holder = HomeLock::acquire(&world.home).unwrap();
    let mut request = world.request(&source);
    request.lock_timeout = Duration::from_millis(100);
    let message = failure(placement::install(&request));
    assert!(message.contains("another Muxlet process"), "{message}");
    assert!(message.contains("application.lock"), "{message}");
    assert_eq!(fs::read(world.installed()).unwrap(), b"old");
    assert_eq!(stage_leftovers(&world.root), Vec::<String>::new());

    drop(holder);
    placement::install(&request).unwrap();
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("new")
    );
}

#[cfg(not(windows))]
#[test]
fn waiting_for_a_process_is_a_windows_only_mechanism() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let mut request = world.request(&source);
    request.wait_pid = Some(std::process::id());
    assert_refused(&world, &request, "only on Windows");
}

#[cfg(unix)]
mod permissions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Mode(PathBuf, u32);

    impl Drop for Mode {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
        }
    }

    fn restrict(path: &Path) -> Mode {
        let original = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        chmod(path, 0o555);
        Mode(path.to_owned(), original)
    }

    fn modes_are_enforced(directory: &Path) -> bool {
        let probe = directory.join("probe");
        match fs::write(&probe, b"") {
            Ok(()) => {
                fs::remove_file(probe).unwrap();
                false
            }
            Err(_) => true,
        }
    }

    #[test]
    fn an_unwritable_destination_directory_is_an_actionable_error_that_changes_nothing() {
        let world = world();
        let source = write_dispatcher(&world.root.join("dotnet"), "new");
        let bin = world.home.join("bin");
        write(&world.installed(), "old");
        let _restore = restrict(&bin);
        if !modes_are_enforced(&bin) {
            return;
        }

        let message = failure(placement::install(&world.request(&source)));
        assert!(message.contains("create a staging file in"), "{message}");
        assert!(message.contains(bin.to_str().unwrap()), "{message}");
        assert!(message.contains("never elevates"), "{message}");
        assert_eq!(fs::read(world.installed()).unwrap(), b"old");
        assert_eq!(stage_leftovers(&world.root), Vec::<String>::new());
    }

    #[test]
    fn a_failed_backup_leaves_the_old_destination_in_place_and_cleans_up() {
        let world = world();
        let source = write_dispatcher(&world.root.join("dotnet"), "new");
        write(&world.installed(), "old");
        let backups = world.root.join("backups");
        fs::create_dir_all(&backups).unwrap();
        let existing = write(&backups.join("previous"), "older backup");
        let _restore = restrict(&backups);
        if !modes_are_enforced(&backups) {
            return;
        }

        let mut request = world.request(&source);
        request.backup = Some(existing.clone());
        let message = failure(placement::install(&request));
        assert!(message.contains(backups.to_str().unwrap()), "{message}");
        assert!(message.contains("never elevates"), "{message}");
        assert_eq!(fs::read(world.installed()).unwrap(), b"old");
        assert_eq!(fs::read(&existing).unwrap(), b"older backup");
        assert_eq!(stage_leftovers(&world.root), Vec::<String>::new());
    }

    #[test]
    fn an_unreadable_old_destination_cannot_be_backed_up_and_is_not_discarded() {
        let world = world();
        let source = write_dispatcher(&world.root.join("dotnet"), "new");
        write(&world.installed(), "unreadable old");
        chmod(&world.installed(), 0o000);
        if fs::read(world.installed()).is_ok() {
            chmod(&world.installed(), 0o644);
            return;
        }
        let backup = world.root.join("backup");

        let mut request = world.request(&source);
        request.backup = Some(backup.clone());
        let message = failure(placement::install(&request));
        assert!(message.contains("cannot read"), "{message}");
        assert!(!backup.exists(), "a failed backup must not look successful");
        chmod(&world.installed(), 0o644);
        assert_eq!(fs::read(world.installed()).unwrap(), b"unreadable old");
        assert_eq!(stage_leftovers(&world.root), Vec::<String>::new());
    }

    #[test]
    fn a_running_program_is_replaced_atomically_on_unix() {
        let world = world();
        let source = write_dispatcher(&world.root.join("dotnet"), "new");
        let running = common::install_fixture(&world.home.join("bin"), DOTNET_FILE_NAME);
        let mut child = spawn(
            Command::new(&running)
                .env("MUXLET_FIXTURE_READ_STDIN", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped()),
        );
        // Wait until the program is certainly running its image.
        let mut first = [0u8; 4];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut first)
            .unwrap();

        placement::install(&world.request(&source)).unwrap();
        assert_eq!(
            fs::read(world.installed()).unwrap(),
            dispatcher_image("new")
        );

        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
    }
}

// ---------------------------------------------------------------------------
// The muxlet-install helper (process level)
// ---------------------------------------------------------------------------

#[test]
fn help_describes_every_option_and_succeeds() {
    let world = world();
    for flag in ["--help", "-h"] {
        let output = run(helper(&world).arg(flag));
        assert_success(&output);
        let text = stdout(&output);
        for option in [
            "--source",
            "--home",
            "--destination",
            "--backup",
            "--wait-pid",
            "--lock-timeout",
            "--help",
            "Complete file name",
            "nothing is elevated",
            "PATH and shell\nprofiles are never edited",
        ] {
            assert!(text.contains(option), "{option} is missing from:\n{text}");
        }
    }
    assert!(!world.home.exists());
}

#[test]
fn bad_command_lines_are_usage_errors_with_status_two_and_no_writes() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    for arguments in [
        vec!["--bogus"],
        vec!["positional"],
        vec!["--home"],
        vec!["--backup", "a", "--backup", "b"],
        vec!["--lock-timeout", "soon"],
        vec!["--source=whatever"],
    ] {
        let output = run(helper(&world).arg("--source").arg(&source).args(&arguments));
        assert_eq!(
            output.status.code(),
            Some(2),
            "{arguments:?}: {}",
            stderr(&output)
        );
        assert!(stderr(&output).contains("--help"), "{}", stderr(&output));
        assert!(output.stdout.is_empty());
        assert!(!world.home.exists(), "{arguments:?}");
    }
}

#[cfg(not(windows))]
#[test]
fn the_wait_option_is_rejected_where_it_cannot_work() {
    let world = world();
    let output = run(helper(&world).args(["--wait-pid", "1"]));
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("only on Windows"),
        "{}",
        stderr(&output)
    );
    assert!(!world.home.exists());
}

#[test]
fn the_default_source_is_the_dotnet_beside_the_helper_not_the_working_directory() {
    let world = world();
    let tools = world.root.join("tools with spaces");
    fs::create_dir_all(&tools).unwrap();
    let copy = tools.join(format!("muxlet-install{}", std::env::consts::EXE_SUFFIX));
    fs::copy(installer(), &copy).unwrap();
    write_dispatcher(&tools.join(DOTNET_FILE_NAME), "beside the helper");
    let decoy = world.root.join("working directory");
    write_dispatcher(&decoy.join(DOTNET_FILE_NAME), "in the working directory");

    let mut command = Command::new(&copy);
    command
        .current_dir(&decoy)
        .env_remove("DOTNET_ROOT")
        .env("DOTNET_SDK_HOME", &world.home)
        .arg("--home")
        .arg(&world.home);
    let output = run(&mut command);
    assert_success(&output);
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("beside the helper")
    );
}

#[cfg(unix)]
#[test]
fn the_default_source_is_resolved_from_the_real_helper_location_through_links() {
    let world = world();
    let tools = world.root.join("real tools");
    fs::create_dir_all(&tools).unwrap();
    let real = tools.join("muxlet-install");
    fs::copy(installer(), &real).unwrap();
    write_dispatcher(&tools.join("dotnet"), "beside the real helper");
    let links = world.root.join("links");
    write_dispatcher(&links.join("dotnet"), "beside the link");
    assert!(symlink(&real, &links.join("muxlet-install")));

    let mut command = Command::new(links.join("muxlet-install"));
    command
        .env_remove("DOTNET_ROOT")
        .env("DOTNET_SDK_HOME", &world.home);
    let output = run(&mut command);
    assert_success(&output);
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("beside the real helper")
    );
}

#[test]
fn a_missing_default_source_explains_how_to_choose_one() {
    let world = world();
    let tools = world.root.join("tools");
    fs::create_dir_all(&tools).unwrap();
    let copy = tools.join(format!("muxlet-install{}", std::env::consts::EXE_SUFFIX));
    fs::copy(installer(), &copy).unwrap();

    let mut command = Command::new(&copy);
    command
        .env_remove("DOTNET_ROOT")
        .env("DOTNET_SDK_HOME", &world.home);
    let output = run(&mut command);
    assert_eq!(output.status.code(), Some(1));
    let message = stderr(&output);
    assert!(message.starts_with("muxlet-install: "), "{message}");
    assert!(message.contains("--source"), "{message}");
    assert!(!world.home.exists());
}

#[test]
fn the_home_follows_the_documented_precedence_and_relative_paths_are_made_absolute() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");

    // An explicit --home beats DOTNET_SDK_HOME.
    let from_environment = world.root.join("from environment");
    let output = run(helper(&world)
        .env("DOTNET_SDK_HOME", &from_environment)
        .arg("--source")
        .arg(&source)
        .arg("--home")
        .arg(&world.home));
    assert_success(&output);
    assert!(world.installed().is_file());
    assert!(!from_environment.exists());

    // Without --home, DOTNET_SDK_HOME is used.
    let output = run(helper(&world)
        .env("DOTNET_SDK_HOME", &from_environment)
        .arg("--source")
        .arg(&source));
    assert_success(&output);
    assert!(placement::default_destination(&from_environment).is_file());

    // Relative paths mean relative to the working directory.
    let output = run(helper(&world)
        .current_dir(&world.root)
        .arg("--source")
        .arg("dotnet")
        .arg("--home")
        .arg("relative home")
        .arg("--destination")
        .arg(Path::new("relative home/bin").join("renamed dotnet"))
        .arg("--backup")
        .arg("relative home/staging/previous"));
    assert_success(&output);
    assert!(
        world
            .root
            .join("relative home/bin/renamed dotnet")
            .is_file()
    );
}

#[cfg(unix)]
#[test]
fn without_any_setting_the_per_user_default_home_is_used() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let user = world.root.join("pretend user profile");
    fs::create_dir_all(&user).unwrap();
    let expected = if cfg!(target_os = "macos") {
        user.join("Library/Application Support/muxlet")
    } else {
        user.join(".local/share/muxlet")
    };

    let mut command = Command::new(installer());
    command
        .env_remove("DOTNET_ROOT")
        .env_remove("DOTNET_SDK_HOME")
        .env_remove("XDG_DATA_HOME")
        .env("HOME", &user)
        .arg("--source")
        .arg(&source);
    let output = run(&mut command);
    assert_success(&output);
    assert!(placement::default_destination(&expected).is_file());
    assert!(
        !stdout(&output).contains("DOTNET_SDK_HOME"),
        "the default home needs no reminder:\n{}",
        stdout(&output)
    );
}

#[test]
fn the_report_names_what_happened_and_the_manual_next_steps() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let custom = world.root.join("custom home");

    let output = run(helper(&world)
        .env("DOTNET_SDK_HOME", world.root.join("another"))
        .arg("--source")
        .arg(&source)
        .arg("--home")
        .arg(&custom));
    assert_success(&output);
    let text = stdout(&output);
    assert!(text.contains("Installed"), "{text}");
    assert!(
        text.contains(custom.join("bin").to_str().unwrap()),
        "{text}"
    );
    assert!(text.contains("on your user PATH yourself"), "{text}");
    assert!(
        text.contains("never edits PATH or shell profiles"),
        "{text}"
    );
    assert!(
        text.contains("DOTNET_SDK_HOME"),
        "a custom home needs a reminder:\n{text}"
    );
    assert!(text.contains("not a .NET SDK root"), "{text}");

    // The same home as the environment's needs no reminder.
    let output = run(helper(&world)
        .arg("--source")
        .arg(&source)
        .arg("--home")
        .arg(&world.home));
    assert_success(&output);
    assert!(
        !stdout(&output).contains("not the default"),
        "{}",
        stdout(&output)
    );

    // Replacing with and without a backup is reported accurately.
    assert!(stdout(&output).contains("Installed"));
    let backup = world.root.join("old core");
    let with_backup = run(helper(&world)
        .arg("--source")
        .arg(&source)
        .arg("--backup")
        .arg(&backup));
    assert_success(&with_backup);
    assert!(
        stdout(&with_backup).contains(&format!("Saved the previous file at {}", backup.display()))
    );
    let without = run(helper(&world).arg("--source").arg(&source));
    assert!(
        stdout(&without).contains("no backup was requested"),
        "{}",
        stdout(&without)
    );
}

#[test]
fn the_helper_never_edits_profiles_or_anything_outside_the_requested_places() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let user = world.root.join("fake user profile");
    for profile in [
        ".profile",
        ".bashrc",
        ".bash_profile",
        ".zshrc",
        ".zprofile",
        ".config/fish/config.fish",
        "Documents/PowerShell/profile.ps1",
    ] {
        write(&user.join(profile), "# my own settings\n");
    }
    let before = tree(&user);

    let output = run(helper(&world).arg("--source").arg(&source));
    assert_success(&output);
    assert_eq!(
        tree(&user),
        before,
        "profiles and the user's files must stay untouched"
    );

    // Everything created lives in the home.
    let mut created: Vec<String> = tree(&world.root)
        .into_keys()
        .filter(|name| {
            !name.starts_with("application home") && !name.starts_with("fake user profile")
        })
        .collect();
    created.sort();
    assert_eq!(
        created,
        ["dotnet"],
        "only the pre-existing source may be outside"
    );
}

#[test]
fn refusals_are_reported_on_stderr_with_status_one_and_leave_everything_alone() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let launcher = genuine_root(&world.root.join("genuine root"));
    let before = tree(&world.root);

    let output = run(helper(&world)
        .arg("--source")
        .arg(&source)
        .arg("--destination")
        .arg(&launcher));
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let message = stderr(&output);
    assert!(message.starts_with("muxlet-install: "), "{message}");
    assert!(message.contains("installation root"), "{message}");
    assert_eq!(tree(&world.root), before);

    let output = run(helper(&world)
        .arg("--source")
        .arg(installer())
        .arg("--home")
        .arg(&world.home));
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("not a Muxlet dispatcher"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_explicit_dotnet_root_in_the_environment_protects_its_launcher() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    let plain = world.root.join("explicit root");
    let launcher = write(&plain.join(DOTNET_FILE_NAME), "a partial root");

    let output = run(helper(&world)
        .env("DOTNET_ROOT", &plain)
        .arg("--source")
        .arg(&source)
        .arg("--destination")
        .arg(&launcher));
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("selected by the environment"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fs::read(&launcher).unwrap(), b"a partial root");

    // The same root does not stop installation into the home.
    let output = run(helper(&world)
        .env("DOTNET_ROOT", &plain)
        .arg("--source")
        .arg(&source));
    assert_success(&output);
}

#[test]
fn destination_and_backup_options_follow_the_documented_semantics_end_to_end() {
    let world = world();
    let old = write_dispatcher(&world.root.join("old/dotnet"), "old");
    let new = write_dispatcher(&world.root.join("new/dotnet"), "new");
    let bin = world.root.join("user bin");
    fs::create_dir_all(&bin).unwrap();
    let destination = bin.join(format!("dotnet-copy{}", std::env::consts::EXE_SUFFIX));
    let backup = world.root.join("backups/dotnet.previous");
    fs::create_dir_all(backup.parent().unwrap()).unwrap();
    write(&backup, "an earlier backup");

    // No old destination: the existing backup is untouched.
    let output = run(helper(&world)
        .arg("--source")
        .arg(&old)
        .arg("--destination")
        .arg(&destination)
        .arg("--backup")
        .arg(&backup));
    assert_success(&output);
    assert_eq!(fs::read(&backup).unwrap(), b"an earlier backup");
    assert_eq!(fs::read(&destination).unwrap(), dispatcher_image("old"));

    // Now the old destination is saved, overwriting the earlier backup.
    let output = run(helper(&world)
        .arg("--source")
        .arg(&new)
        .arg("--destination")
        .arg(&destination)
        .arg("--backup")
        .arg(&backup));
    assert_success(&output);
    assert_eq!(fs::read(&backup).unwrap(), dispatcher_image("old"));
    assert_eq!(fs::read(&destination).unwrap(), dispatcher_image("new"));
    assert!(
        stdout(&output).contains(&format!("Put '{}' on your user PATH", bin.display())),
        "{}",
        stdout(&output)
    );
}

#[test]
fn the_helper_waits_for_the_shared_lock_and_fails_clearly_when_it_stays_busy() {
    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "new");
    fs::create_dir_all(&world.home).unwrap();
    let holder = HomeLock::acquire(&world.home).unwrap();

    // With no patience, the other process is reported immediately.
    let started = Instant::now();
    let output = run(helper(&world)
        .arg("--source")
        .arg(&source)
        .args(["--lock-timeout", "0"]));
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("another Muxlet process"),
        "{}",
        stderr(&output)
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(!world.installed().exists());

    // With patience, it waits for the holder and then proceeds.
    let mut waiting: Child = spawn(
        helper(&world)
            .arg("--source")
            .arg(&source)
            .args(["--lock-timeout", "60"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    );
    thread::sleep(Duration::from_millis(600));
    assert!(
        waiting.try_wait().unwrap().is_none(),
        "it must still be waiting for the lock"
    );
    assert!(!world.installed().exists());
    drop(holder);

    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = waiting.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the helper never finished");
        thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success());
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        dispatcher_image("new")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn paths_that_are_not_valid_unicode_are_passed_through_unchanged() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let world = world();
    let source = write_dispatcher(&world.root.join("dotnet"), "bytes");
    let home = world.root.join(OsStr::from_bytes(b"home-\xff\xfe-bytes"));
    let output = run(helper(&world)
        .arg("--source")
        .arg(&source)
        .arg("--home")
        .arg(&home));
    assert_success(&output);
    assert_eq!(
        fs::read(placement::default_destination(&home)).unwrap(),
        dispatcher_image("bytes")
    );
}

#[test]
fn the_real_dispatcher_installs_and_then_answers_the_configuration_query() {
    let world = world();
    let output = run(helper(&world).arg("--source").arg(dispatcher()));
    assert_success(&output);
    assert_eq!(
        fs::read(world.installed()).unwrap(),
        fs::read(dispatcher()).unwrap()
    );

    let mut query = Command::new(world.installed());
    query
        .env("DOTNET_SDK_HOME", &world.home)
        .env_remove("DOTNET_ROOT")
        .args(["dispatcher", "configuration"]);
    let output = run(&mut query);
    assert_success(&output);
    let mut expected = home::configuration(&world.home)
        .into_os_string()
        .into_encoded_bytes();
    expected.push(b'\n');
    assert_eq!(output.stdout, expected);
    assert!(!home::configuration(&world.home).exists());
}

// ---------------------------------------------------------------------------
// Windows: running programs, and replacement after they exit
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod windows {
    use super::*;

    /// A running program whose image is the destination file.
    fn start_running_destination(world: &World) -> (Child, PathBuf) {
        let destination = common::install_fixture(&world.home.join("bin"), DOTNET_FILE_NAME);
        let mut child = spawn(
            Command::new(&destination)
                .env("MUXLET_FIXTURE_READ_STDIN", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped()),
        );
        let mut first = [0u8; 4];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut first)
            .unwrap();
        (child, destination)
    }

    struct Reaper(Option<Child>);

    impl Drop for Reaper {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[test]
    fn a_running_destination_is_preserved_and_the_error_explains_what_to_do() {
        let world = world();
        let source = write_dispatcher(&world.root.join("dotnet.exe"), "new");
        let (child, destination) = start_running_destination(&world);
        let mut child = Reaper(Some(child));
        let original = fs::read(&destination).unwrap();

        let output = run(helper(&world).arg("--source").arg(&source));
        assert_eq!(output.status.code(), Some(1));
        let message = stderr(&output);
        assert!(message.contains("in use"), "{message}");
        assert!(message.contains("--wait-pid"), "{message}");
        assert_eq!(
            fs::read(&destination).unwrap(),
            original,
            "the original must survive"
        );
        assert_eq!(stage_leftovers(&world.root), Vec::<String>::new());

        // Even with a backup, a failed replacement leaves the destination alone.
        let backup = world.root.join("backup.exe");
        let output = run(helper(&world)
            .arg("--source")
            .arg(&source)
            .arg("--backup")
            .arg(&backup));
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(fs::read(&destination).unwrap(), original);
        assert_eq!(fs::read(&backup).unwrap(), original, "the copy is complete");

        let running = child.0.as_mut().unwrap();
        drop(running.stdin.take());
        assert!(running.wait().unwrap().success());
    }

    #[test]
    fn replacement_happens_after_the_named_process_exits() {
        let world = world();
        let source = write_dispatcher(&world.root.join("dotnet.exe"), "after exit");
        let (child, destination) = start_running_destination(&world);
        let mut child = Reaper(Some(child));
        let original = fs::read(&destination).unwrap();

        let mut waiting = Reaper(Some(spawn(
            helper(&world)
                .arg("--source")
                .arg(&source)
                .arg("--wait-pid")
                .arg(child.0.as_ref().unwrap().id().to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::piped()),
        )));
        thread::sleep(Duration::from_millis(1000));
        assert!(
            waiting.0.as_mut().unwrap().try_wait().unwrap().is_none(),
            "the helper must still be waiting"
        );
        assert_eq!(fs::read(&destination).unwrap(), original);

        let running = child.0.as_mut().unwrap();
        drop(running.stdin.take());
        assert!(running.wait().unwrap().success());

        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = waiting.0.as_mut().unwrap().try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "the helper never finished");
            thread::sleep(Duration::from_millis(50));
        };
        assert!(status.success());
        assert_eq!(
            fs::read(&destination).unwrap(),
            dispatcher_image("after exit")
        );
    }

    #[test]
    fn waiting_for_a_process_that_already_exited_proceeds_immediately() {
        let world = world();
        let source = write_dispatcher(&world.root.join("dotnet.exe"), "new");
        let mut finished = Command::new(std::env::var_os("COMSPEC").unwrap())
            .args(["/C", "exit 0"])
            .spawn()
            .unwrap();
        let pid = finished.id();
        finished.wait().unwrap();

        let output = run(helper(&world)
            .arg("--source")
            .arg(&source)
            .arg("--wait-pid")
            .arg(pid.to_string()));
        assert_success(&output);
        assert_eq!(
            fs::read(world.installed()).unwrap(),
            dispatcher_image("new")
        );
    }

    #[test]
    fn a_process_cannot_wait_for_itself_or_for_process_zero() {
        let world = world();
        let source = write_dispatcher(&world.root.join("dotnet.exe"), "new");
        let mut request = world.request(&source);
        request.wait_pid = Some(0);
        assert_refused(&world, &request, "--wait-pid");
    }
}
