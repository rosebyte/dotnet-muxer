//! Safe placement of the Muxlet dispatcher, used by the `muxlet-install` helper.
//!
//! [`install`] copies a verified dispatcher to a destination file and, on
//! request, saves whatever it replaces. It never edits PATH or shell profiles,
//! installs SDKs, elevates, or changes permissions. It creates only the
//! application home's own directories (`bin`, `extensions`, `metadata`,
//! `journal`, `cache`, `staging`) and replaces only the core executable; it
//! never writes configuration, extension executables or data, or recovery data.
//!
//! # Semantics
//!
//! * The destination and the backup are **complete file names**, never
//!   directories. The default destination is `<HOME>/bin/dotnet[.exe]`.
//! * An existing regular file or symbolic link at the destination is replaced
//!   without a backup. A link is an entry: the link is replaced and its target
//!   is untouched.
//! * With a backup, the old entry is saved at exactly the backup path first: a
//!   regular file as a copy of its bytes and permission bits, a link as a new
//!   link with the identical stored text (a relative link may resolve elsewhere
//!   from another directory). An old backup file or link is overwritten without
//!   prompting; a link there is replaced, not followed. If there was no old
//!   destination, an existing backup is left untouched.
//! * Directories, FIFOs, sockets and devices are refused for both paths. So are
//!   a destination and backup that are the same entry (including through
//!   parent-directory links or hard links), a source that is the destination or
//!   the backup, protected system locations, anything inside the application
//!   home except under `bin` and `staging`, and the directory of any managed
//!   .NET root (a `host/fxr` or `shared/Microsoft.NETCore.App` layout, or an
//!   explicit `DOTNET_ROOT`), whose genuine launcher must never become a
//!   dispatcher forwarding to itself. Refusals happen before anything is
//!   written.
//! * The source must be a native Muxlet dispatcher (the identity marker). Each
//!   artefact is staged next to where it will live (so every rename stays on
//!   its own filesystem), hashed, re-read and verified, and only then
//!   published by an atomic rename. The backup is published before the
//!   destination is touched; a failure leaves the old destination in place, and
//!   an interrupted run can leave only `.muxlet-stage` files beside the
//!   destination or backup, which are safe to delete.
//! * All of this happens under the shared application-home lock, so it
//!   serialises with configuration writers and other installers.
//!
//! On Windows a running or locked destination cannot be replaced. The original
//! is preserved and the error says so; `wait_pid` waits for a process to exit
//! first, with ordinary-user APIs, and then replaces the file.

use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempPath};

use crate::config::{self, DEFAULT_LOCK_TIMEOUT, HomeLock};
use crate::executable::{self, DOTNET_FILE_NAME};
use crate::home;

/// The directories installation may create inside the application home.
const LAYOUT: [&str; 6] = [
    "bin",
    "extensions",
    "metadata",
    "journal",
    "cache",
    "staging",
];
/// Inside the home only these may receive the core executable or its backup.
const WRITABLE_INSIDE_HOME: [&str; 2] = ["bin", "staging"];
/// Directories of the home whose contents installation must never touch.
const RESERVED_INSIDE_HOME: [&str; 4] = ["extensions", "metadata", "journal", "cache"];
const ROOT_VARIABLES: [&str; 5] = [
    "DOTNET_ROOT",
    "DOTNET_ROOT_X64",
    "DOTNET_ROOT_X86",
    "DOTNET_ROOT_ARM64",
    "DOTNET_ROOT(x86)",
];
const RETRY_DELAY: Duration = Duration::from_millis(100);

/// Everything [`install`] needs; build one with [`Request::new`].
#[derive(Clone, Debug)]
pub struct Request {
    /// The dispatcher to install. A link is resolved and its bytes are copied.
    pub source: PathBuf,
    /// The application home. Relative paths are made absolute.
    pub home: PathBuf,
    /// The complete file name to create or replace.
    pub destination: PathBuf,
    /// A complete file name at which to save the entry being replaced.
    pub backup: Option<PathBuf>,
    /// Windows only: wait for this process to exit before replacing.
    pub wait_pid: Option<u32>,
    /// How long to wait for another process holding the application lock.
    pub lock_timeout: Duration,
    /// Genuine .NET roots (such as `DOTNET_ROOT`) whose directories are
    /// protected; [`Request::new`] reads them from the environment.
    pub managed_roots: Vec<PathBuf>,
}

impl Request {
    /// A request for the default destination, no backup and no waiting.
    pub fn new(source: impl Into<PathBuf>, home: impl Into<PathBuf>) -> Request {
        let home = home.into();
        Request {
            source: source.into(),
            destination: default_destination(&home),
            home,
            backup: None,
            wait_pid: None,
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
            managed_roots: managed_roots_from_environment(),
        }
    }
}

/// `<HOME>/bin/dotnet[.exe]`.
pub fn default_destination(home: &Path) -> PathBuf {
    home.join("bin").join(DOTNET_FILE_NAME)
}

/// The `dotnet[.exe]` beside the running helper, resolved from the helper's
/// real location (links followed), not the working directory.
pub fn default_source() -> Result<PathBuf> {
    let helper =
        fs::canonicalize(env::current_exe().context("cannot locate the running installer")?)
            .context("cannot resolve the running installer's location")?;
    let directory = helper
        .parent()
        .context("the installer has no containing directory")?;
    Ok(directory.join(DOTNET_FILE_NAME))
}

/// The absolute, nonempty `DOTNET_ROOT` family of environment variables.
pub fn managed_roots_from_environment() -> Vec<PathBuf> {
    ROOT_VARIABLES
        .iter()
        .filter_map(env::var_os)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|root| root.is_absolute())
        .collect()
}

/// What was at the destination before installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Previous {
    Absent,
    File,
    Symlink,
}

/// What [`install`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The absolute destination that now holds the dispatcher.
    pub destination: PathBuf,
    /// The kind of entry that was replaced.
    pub previous: Previous,
    /// Where the replaced entry was saved; `None` unless a backup was both
    /// requested and needed.
    pub backup: Option<PathBuf>,
}

/// Installs the dispatcher as described in the module documentation.
pub fn install(request: &Request) -> Result<Outcome> {
    if request.wait_pid.is_some() && !cfg!(windows) {
        bail!(
            "--wait-pid is supported only on Windows, where a running program cannot be \
             replaced; on this platform the running file is replaced atomically instead"
        );
    }
    let source = Source::open(&request.source)?;
    // Refuse anything unsafe before waiting, locking or creating a single file.
    prepare(request, &source)?;

    if let Some(pid) = request.wait_pid {
        wait_for_exit(pid)?;
    }
    let layout = Layout::new(&request.home)?;
    layout.create()?;
    let _lock = HomeLock::acquire_timeout(&layout.home, request.lock_timeout)?;
    // The state may have changed while waiting, so decide again under the lock.
    let plan = prepare(request, &source)?;
    let retries = if request.wait_pid.is_some() { 100 } else { 5 };
    plan.execute(&source, retries)
}

struct Source {
    /// The resolved regular file whose bytes are copied.
    path: PathBuf,
    display: PathBuf,
    #[cfg(unix)]
    mode: u32,
}

impl Source {
    fn open(requested: &Path) -> Result<Source> {
        let display = std::path::absolute(requested).with_context(|| {
            format!("cannot make the source '{}' absolute", requested.display())
        })?;
        let path = executable::require_executable(&display).with_context(|| {
            format!(
                "the source '{}' is not a usable executable",
                display.display()
            )
        })?;
        if !executable::is_dispatcher(&path)
            .with_context(|| format!("cannot read the source '{}'", display.display()))?
        {
            bail!(
                "the source '{}' is not a Muxlet dispatcher (its identity marker is missing); \
                 pass the dotnet executable built from this repository, not another program or \
                 the installer",
                display.display()
            );
        }
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(&path)
                .with_context(|| format!("cannot inspect the source '{}'", display.display()))?
                .permissions()
                .mode()
        };
        Ok(Source {
            path,
            display,
            #[cfg(unix)]
            mode,
        })
    }
}

/// The application home's directories as they will be after creation, with
/// every existing component resolved through links.
struct Layout {
    home: PathBuf,
    /// Home first, then the layout directories: the only ones installation
    /// may create.
    directories: Vec<PathBuf>,
    /// Resolved locations that must never receive a destination or backup.
    reserved: Vec<PathBuf>,
}

impl Layout {
    fn new(requested: &Path) -> Result<Layout> {
        let absolute = std::path::absolute(requested).with_context(|| {
            format!(
                "cannot make the application home '{}' absolute",
                requested.display()
            )
        })?;
        let home = real_path(&absolute).with_context(|| {
            format!(
                "cannot resolve the application home '{}'",
                absolute.display()
            )
        })?;
        let mut directories = vec![home.clone()];
        directories.extend(LAYOUT.iter().map(|name| home.join(name)));
        let reserved = RESERVED_INSIDE_HOME
            .iter()
            .map(|name| home.join(name))
            .chain([home::configuration(&home)])
            .map(|path| {
                real_path(&path).with_context(|| {
                    format!(
                        "cannot identify protected application data '{}'",
                        path.display()
                    )
                })
            })
            .collect::<Result<_>>()?;
        Ok(Layout {
            home,
            directories,
            reserved,
        })
    }

    fn create(&self) -> Result<()> {
        for directory in &self.directories {
            fs::create_dir_all(directory).map_err(|error| {
                config::Error::io("create the application directory", directory, error)
            })?;
        }
        Ok(())
    }

    fn will_exist(&self, directory: &Path) -> bool {
        self.directories
            .iter()
            .any(|known| same_path(known, directory))
    }
}

/// A destination or backup: where it is, and what is there now.
struct Slot {
    role: &'static str,
    /// As requested, made absolute, for messages.
    display: PathBuf,
    /// The directory with links resolved; it may not exist yet when it is part
    /// of the application layout.
    parent: PathBuf,
    /// `parent` plus the file name, used for every operation.
    path: PathBuf,
    entry: Entry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    Absent,
    File {
        len: u64,
        modified: SystemTime,
        #[cfg(unix)]
        identity: (u64, u64),
    },
    Symlink(PathBuf),
}

impl Entry {
    fn inspect(path: &Path) -> Result<Entry> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Entry::Absent),
            Err(error) => return Err(error).context("it cannot be inspected"),
        };
        let kind = metadata.file_type();
        if kind.is_symlink() {
            #[cfg(windows)]
            {
                use std::os::windows::fs::FileTypeExt;
                if kind.is_symlink_dir() {
                    bail!("it is a directory link, which cannot be replaced on Windows");
                }
            }
            let text = fs::read_link(path).context("its link text cannot be read")?;
            Ok(Entry::Symlink(text))
        } else if kind.is_file() {
            #[cfg(unix)]
            let identity = {
                use std::os::unix::fs::MetadataExt;
                (metadata.dev(), metadata.ino())
            };
            Ok(Entry::File {
                len: metadata.len(),
                modified: metadata
                    .modified()
                    .context("its modification time cannot be read")?,
                #[cfg(unix)]
                identity,
            })
        } else if kind.is_dir() {
            bail!(
                "it is a directory, but installation replaces only a file or a symbolic link; \
                 give a complete file name"
            )
        } else {
            bail!("it is a special file (a FIFO, socket or device), which is never replaced")
        }
    }

    fn previous(&self) -> Previous {
        match self {
            Entry::Absent => Previous::Absent,
            Entry::File { .. } => Previous::File,
            Entry::Symlink(_) => Previous::Symlink,
        }
    }
}

impl Slot {
    fn new(role: &'static str, requested: &Path) -> Result<Slot> {
        if names_directory(requested) {
            bail!(
                "the {role} '{}' must be a complete file name, not a directory path",
                requested.display()
            );
        }
        let display = std::path::absolute(requested).with_context(|| {
            format!("cannot make the {role} '{}' absolute", requested.display())
        })?;
        let name = display
            .file_name()
            .map(OsStr::to_owned)
            .with_context(|| format!("the {role} '{}' has no file name", display.display()))?;
        let directory = display
            .parent()
            .with_context(|| format!("the {role} '{}' has no directory", display.display()))?;
        let parent = real_path(directory).with_context(|| {
            format!(
                "cannot resolve the directory of the {role} '{}'",
                display.display()
            )
        })?;
        let path = parent.join(name);
        let entry = Entry::inspect(&path)
            .with_context(|| format!("cannot use the {role} '{}'", display.display()))?;
        Ok(Slot {
            role,
            display,
            parent,
            path,
            entry,
        })
    }

    /// An existing slot must still hold the entry that was planned for.
    fn require_unchanged(&self) -> Result<()> {
        let now = Entry::inspect(&self.path).with_context(|| {
            format!(
                "cannot re-inspect the {} '{}'",
                self.role,
                self.display.display()
            )
        })?;
        if now != self.entry {
            bail!(
                "the {} '{}' changed while the installation was being prepared; nothing was \
                 replaced, so run the installer again",
                self.role,
                self.display.display()
            );
        }
        Ok(())
    }
}

struct Plan {
    destination: Slot,
    backup: Option<Slot>,
}

/// Inspects and validates everything without writing.
fn prepare(request: &Request, source: &Source) -> Result<Plan> {
    let layout = Layout::new(&request.home)?;
    refuse_protected(&layout.home, "application home")?;
    let destination = Slot::new("destination", &request.destination)?;
    let backup = request
        .backup
        .as_deref()
        .map(|path| Slot::new("backup", path))
        .transpose()?;
    let roots = protected_roots(&request.managed_roots)?;

    for slot in std::iter::once(&destination).chain(backup.as_ref()) {
        check_location(slot, &layout, &roots)?;
    }
    check_collisions(source, &destination, backup.as_ref())?;
    Ok(Plan {
        destination,
        backup,
    })
}

/// The real directories of the managed roots; a relative entry selects none.
fn protected_roots(roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    roots
        .iter()
        .filter(|root| root.is_absolute())
        .map(|root| {
            real_path(root).with_context(|| {
                format!(
                    "cannot identify the protected .NET installation root '{}'",
                    root.display()
                )
            })
        })
        .collect()
}

fn check_location(slot: &Slot, layout: &Layout, roots: &[PathBuf]) -> Result<()> {
    let (role, shown) = (slot.role, slot.display.display());
    refuse_protected(&slot.parent, role)?;
    if !slot.parent.is_dir() && !layout.will_exist(&slot.parent) {
        bail!(
            "the directory of the {role} '{shown}' does not exist; create it or choose an existing \
             directory (installation creates only the application home's own directories)"
        );
    }

    if let Some(root) = roots.iter().find(|root| same_path(&slot.parent, root)) {
        bail!(
            "the {role} '{shown}' is inside the .NET installation root '{}' selected by \
             the environment; replacing a genuine launcher would make dotnet forward to \
             itself",
            root.display()
        );
    }
    if looks_like_dotnet_root(&slot.parent)? {
        bail!(
            "the {role} '{shown}' is inside a .NET installation root (it contains a host or \
             shared runtime layout); replacing a genuine launcher would make dotnet forward to \
             itself"
        );
    }

    for reserved in &layout.reserved {
        if starts_with(&slot.path, reserved) {
            bail!(
                "the {role} '{shown}' is configuration, extension, metadata, journal or cache \
                 data of the application home, which installation never modifies"
            );
        }
    }
    if starts_with(&slot.path, &layout.home) {
        // A file below bin or staging; never a layout directory's own name.
        let mut inside = slot
            .path
            .components()
            .skip(layout.home.components().count());
        let writable = inside.next().is_some_and(|directory| {
            WRITABLE_INSIDE_HOME
                .iter()
                .any(|name| same_component(directory.as_os_str(), OsStr::new(name)))
        }) && inside.next().is_some();
        if !writable {
            bail!(
                "the {role} '{shown}' is inside the application home but not under its bin or \
                 staging directory; use one of those or a location outside the home"
            );
        }
    }
    Ok(())
}

fn check_collisions(source: &Source, destination: &Slot, backup: Option<&Slot>) -> Result<()> {
    if names_same_file(source, destination)? {
        bail!(
            "the source '{}' is the destination '{}'; there is nothing to install",
            source.display.display(),
            destination.display.display()
        );
    }
    let Some(backup) = backup else {
        return Ok(());
    };
    if same_entry(destination, backup)? {
        bail!(
            "the destination '{}' and the backup '{}' are the same entry; choose a different \
             backup file",
            destination.display.display(),
            backup.display.display()
        );
    }
    if names_same_file(source, backup)? {
        bail!(
            "the backup '{}' is the source '{}'; saving the old entry there would destroy the \
             source",
            backup.display.display(),
            source.display.display()
        );
    }
    if matches!(destination.entry, Entry::Symlink(_)) {
        if let Ok(target) = fs::canonicalize(&destination.path) {
            let backs_up_target = same_path(&backup.path, &target)
                || (matches!(backup.entry, Entry::File { .. })
                    && same_file(&backup.path, &target)?);
            if backs_up_target {
                bail!(
                    "the backup '{}' is the file the destination link '{}' points to; saving the \
                     link there would leave it pointing at itself",
                    backup.display.display(),
                    destination.display.display()
                );
            }
        }
    }
    Ok(())
}

fn names_same_file(source: &Source, slot: &Slot) -> Result<bool> {
    Ok(same_path(&source.path, &slot.path)
        || (matches!(slot.entry, Entry::File { .. }) && same_file(&source.path, &slot.path)?))
}

fn same_entry(left: &Slot, right: &Slot) -> Result<bool> {
    Ok(same_path(&left.path, &right.path)
        || (matches!(left.entry, Entry::File { .. })
            && matches!(right.entry, Entry::File { .. })
            && same_file(&left.path, &right.path)?))
}

/// Whether two regular files are the same file (hard links included). On Unix
/// this compares device and inode without opening either file, so an
/// unreadable file can still be replaced.
#[cfg(unix)]
fn same_file(left: &Path, right: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let identity = |path: &Path| {
        fs::metadata(path)
            .map(|metadata| (metadata.dev(), metadata.ino()))
            .with_context(|| format!("cannot inspect '{}'", path.display()))
    };
    Ok(identity(left)? == identity(right)?)
}

#[cfg(not(unix))]
fn same_file(left: &Path, right: &Path) -> Result<bool> {
    same_file::is_same_file(left, right).with_context(|| {
        format!(
            "cannot compare '{}' with '{}'",
            left.display(),
            right.display()
        )
    })
}

impl Plan {
    fn execute(self, source: &Source, retries: u32) -> Result<Outcome> {
        let Plan {
            destination,
            backup,
        } = self;

        let staged = stage_dispatcher(source, &destination.parent)?;
        let staged_backup = match &backup {
            Some(backup) => {
                stage_backup(&destination, &backup.parent)?.map(|staged| (backup, staged))
            }
            None => None,
        };

        destination.require_unchanged()?;
        let mut saved = None;
        if let Some((backup, staged_backup)) = staged_backup {
            backup.require_unchanged()?;
            publish(staged_backup, &backup.path, true, retries).map_err(|error| {
                describe_failure(
                    "save the backup at",
                    backup,
                    &error,
                    "the destination was left unchanged",
                )
            })?;
            config::sync_directory(&backup.parent).with_context(|| {
                format!(
                    "the backup '{}' was published, but its directory could not be synchronised; \
                     the destination was left unchanged, and backup durability is not confirmed",
                    backup.display.display()
                )
            })?;
            saved = Some(backup);
        }

        let note = match saved {
            Some(backup) => format!(
                "the destination was left unchanged and its previous entry is saved at '{}'",
                backup.display.display()
            ),
            None => "the destination was left unchanged".to_owned(),
        };
        publish(
            staged,
            &destination.path,
            !matches!(destination.entry, Entry::Absent),
            retries,
        )
        .map_err(|error| {
            describe_failure("replace the destination", &destination, &error, &note)
        })?;
        config::sync_directory(&destination.parent).with_context(|| {
            format!(
                "the dispatcher was installed at '{}', but its directory could not be \
                 synchronised; the new file is present but power-loss durability is not confirmed",
                destination.display.display()
            )
        })?;

        Ok(Outcome {
            previous: destination.entry.previous(),
            backup: saved.map(|backup| backup.display.clone()),
            destination: destination.display,
        })
    }
}

fn describe_failure(action: &str, slot: &Slot, error: &io::Error, note: &str) -> anyhow::Error {
    let shown = slot.display.display();
    if is_in_use(error) {
        return anyhow::anyhow!(
            "cannot {action} '{shown}': it is in use, locked or read-only ({error}); {note}. \
             Close the programs using it (and clear its read-only attribute if set) and run the \
             installer again, or let the process that is about to exit be waited for with \
             --wait-pid PID. Muxlet never terminates programs or elevates"
        );
    }
    if error.kind() == io::ErrorKind::CrossesDevices {
        return anyhow::anyhow!(
            "cannot {action} '{shown}': its directory spans filesystems, so an atomic rename is \
             impossible ({error}); {note}. Choose a location on a single filesystem"
        );
    }
    let mut message = format!("cannot {action} '{shown}': {error}; {note}");
    if let Some(advice) = config::advice(error) {
        message.push_str(". ");
        message.push_str(advice);
    }
    anyhow::anyhow!(message)
}

/// Moves `staged` to `target`. With `replace`, an existing file or link there is
/// replaced; without it, an entry that appeared since planning is never
/// clobbered. A target that Windows reports in use is retried after a pause.
fn publish(mut staged: TempPath, target: &Path, replace: bool, mut retries: u32) -> io::Result<()> {
    loop {
        let result = if replace {
            staged.persist(target)
        } else {
            staged.persist_noclobber(target)
        };
        match result {
            Ok(()) => return Ok(()),
            Err(failure) if retries > 0 && is_in_use(&failure.error) => {
                retries -= 1;
                staged = failure.path;
                thread::sleep(RETRY_DELAY);
            }
            Err(failure) => return Err(failure.error),
        }
    }
}

/// Windows refuses to replace a file that is running or open without delete
/// sharing; other platforms replace such files atomically.
fn is_in_use(error: &io::Error) -> bool {
    cfg!(windows) && matches!(error.raw_os_error(), Some(5 | 32 | 33))
}

fn stage_dispatcher(source: &Source, directory: &Path) -> Result<TempPath> {
    #[cfg(unix)]
    let permissions = {
        use std::os::unix::fs::PermissionsExt;
        Some(fs::Permissions::from_mode((source.mode & 0o755) | 0o700))
    };
    #[cfg(not(unix))]
    let permissions = None;

    let staged = stage_copy(&source.path, directory, ".dotnet-", permissions)?;
    // The copy is what will run, so verify it rather than the source.
    executable::require_executable(&staged).with_context(|| {
        format!(
            "the staged copy of '{}' is not executable",
            source.display.display()
        )
    })?;
    if !executable::is_dispatcher(&staged).with_context(|| {
        format!(
            "cannot read the staged copy of '{}'",
            source.display.display()
        )
    })? {
        bail!(
            "the staged copy of '{}' is not a Muxlet dispatcher; nothing was changed",
            source.display.display()
        );
    }
    Ok(staged)
}

/// Stages a copy of the entry at `old`, if there is one: a regular file by its
/// bytes and permission bits, a link by its stored text.
fn stage_backup(old: &Slot, directory: &Path) -> Result<Option<TempPath>> {
    let staged = match &old.entry {
        Entry::Absent => return Ok(None),
        Entry::File { .. } => {
            let permissions = fs::metadata(&old.path)
                .map(|metadata| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::Permissions::from_mode(metadata.permissions().mode() & 0o777)
                    }
                    #[cfg(not(unix))]
                    {
                        metadata.permissions()
                    }
                })
                .map_err(|error| config::Error::io("inspect", &old.path, error))?;
            stage_copy(&old.path, directory, ".dotnet-backup-", Some(permissions))?
        }
        Entry::Symlink(text) => Builder::new()
            .prefix(".dotnet-link-")
            .suffix(".muxlet-stage")
            .make_in(directory, |path| create_symlink(text, path))
            .map_err(|error| {
                if cfg!(windows) && error.raw_os_error() == Some(1314) {
                    anyhow::anyhow!(
                        "cannot recreate the symbolic link '{}' as a backup: Windows allows it \
                         only with Developer Mode or elevation, and Muxlet never elevates; the \
                         destination was left unchanged",
                        old.display.display()
                    )
                } else {
                    config::Error::io("stage a backup link in", directory, error).into()
                }
            })?
            .into_temp_path(),
    };
    Ok(Some(staged))
}

/// Copies `input` to a new staged file in `directory`, applying `permissions`,
/// syncing it, and checking by re-reading that exactly the bytes read were
/// written.
fn stage_copy(
    input: &Path,
    directory: &Path,
    prefix: &str,
    permissions: Option<fs::Permissions>,
) -> Result<TempPath> {
    let mut reader = File::open(input).map_err(|error| config::Error::io("read", input, error))?;
    let mut staged = Builder::new()
        .prefix(prefix)
        .suffix(".muxlet-stage")
        .tempfile_in(directory)
        .map_err(|error| config::Error::io("create a staging file in", directory, error))?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(config::Error::io("read", input, error).into()),
        };
        hasher.update(&buffer[..read]);
        staged
            .write_all(&buffer[..read])
            .map_err(|error| config::Error::io("write a staging file in", directory, error))?;
    }
    let digest = hasher.finalize();
    if let Some(permissions) = permissions {
        staged
            .as_file()
            .set_permissions(permissions)
            .map_err(|error| {
                config::Error::io("set permissions on a staging file in", directory, error)
            })?;
    }
    staged
        .flush()
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|error| config::Error::io("write a staging file in", directory, error))?;
    let staged = staged.into_temp_path();

    let mut copy = File::open(&staged)
        .map_err(|error| config::Error::io("re-read the staged copy in", directory, error))?;
    let mut check = Sha256::new();
    io::copy(&mut copy, &mut check)
        .map_err(|error| config::Error::io("re-read the staged copy in", directory, error))?;
    if check.finalize() != digest {
        bail!(
            "the staged copy of '{}' does not match what was read; nothing was changed",
            input.display()
        );
    }
    Ok(staged)
}

#[cfg(unix)]
fn create_symlink(text: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(text, link)
}

#[cfg(windows)]
fn create_symlink(text: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(text, link)
}

#[cfg(not(any(unix, windows)))]
fn create_symlink(_text: &Path, _link: &Path) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(windows)]
fn wait_for_exit(pid: u32) -> Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        INFINITE, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    if pid == 0 || pid == std::process::id() {
        bail!("--wait-pid must name another running process, not {pid}");
    }
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        // No such process: it has already exited, which is what we wait for.
        if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Ok(());
        }
        return Err(error).with_context(|| {
            format!(
                "cannot wait for process {pid}; an ordinary user can wait only for processes \
                 it may synchronise with"
            )
        });
    }
    let status = unsafe { WaitForSingleObject(handle, INFINITE) };
    let failure = io::Error::last_os_error();
    unsafe { CloseHandle(handle) };
    if status == WAIT_OBJECT_0 {
        Ok(())
    } else {
        Err(failure).with_context(|| format!("waiting for process {pid} failed"))
    }
}

#[cfg(not(windows))]
fn wait_for_exit(_pid: u32) -> Result<()> {
    bail!("--wait-pid is supported only on Windows")
}

const CASE_INSENSITIVE: bool = cfg!(any(windows, target_os = "macos"));

fn same_component(left: &OsStr, right: &OsStr) -> bool {
    left == right
        || (CASE_INSENSITIVE
            && left.to_string_lossy().to_lowercase() == right.to_string_lossy().to_lowercase())
}

fn same_path(left: &Path, right: &Path) -> bool {
    let mut left = left.components();
    let mut right = right.components();
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(left), Some(right)) if same_component(left.as_os_str(), right.as_os_str()) => {}
            _ => return false,
        }
    }
}

fn starts_with(path: &Path, prefix: &Path) -> bool {
    let mut path = path.components();
    prefix.components().all(|expected| {
        path.next()
            .is_some_and(|actual| same_component(actual.as_os_str(), expected.as_os_str()))
    })
}

/// Whether a user-typed path ends in a separator, `.` or `..`, which all name
/// a directory rather than a file.
fn names_directory(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    let separator = |byte: &u8| *byte == b'/' || (cfg!(windows) && *byte == b'\\');
    match bytes.last() {
        None => true,
        Some(last) if separator(last) => true,
        Some(_) => {
            let tail = bytes.rsplit(separator).next().unwrap_or(bytes);
            tail == b"." || tail == b".."
        }
    }
}

/// Resolves links in every existing component of an absolute path and appends
/// the components that do not exist yet unchanged.
fn real_path(path: &Path) -> Result<PathBuf> {
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        match fs::canonicalize(current) {
            Ok(mut real) => {
                real.extend(missing.iter().rev());
                return Ok(real);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = current.file_name().with_context(|| {
                    format!("cannot resolve '{}' through '..' or a root", path.display())
                })?;
                missing.push(name);
                current = current
                    .parent()
                    .with_context(|| format!("cannot resolve '{}'", path.display()))?;
            }
            Err(error) => {
                return Err(config::Error::io("resolve", current, error).into());
            }
        }
    }
}

fn looks_like_dotnet_root(directory: &Path) -> Result<bool> {
    let is_dir = |relative: &str| {
        let path = directory.join(relative);
        match fs::metadata(&path) {
            Ok(metadata) => Ok(metadata.is_dir()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error).with_context(|| {
                format!(
                    "cannot inspect a potentially protected .NET layout '{}'",
                    path.display()
                )
            }),
        }
    };
    Ok(is_dir("host/fxr")?
        || is_dir("shared/Microsoft.NETCore.App")?
        || (is_dir("sdk")? && is_dir("shared")?))
}

fn refuse_protected(directory: &Path, role: &str) -> Result<()> {
    match protected_location(directory) {
        Some(area) => bail!(
            "the {role} '{}' is in a protected system location ({area}); Muxlet installs only to \
             per-user locations and never elevates, so choose a directory in your own profile",
            directory.display()
        ),
        None => Ok(()),
    }
}

#[cfg(unix)]
fn protected_location(directory: &Path) -> Option<String> {
    const PROTECTED: [&str; 15] = [
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/lib",
        "/lib32",
        "/lib64",
        "/libx32",
        "/proc",
        "/sbin",
        "/sys",
        "/usr",
        "/System",
        "/Library",
        "/private/etc",
    ];
    if directory.parent().is_none() {
        return Some("the filesystem root".to_owned());
    }
    // Places below a system prefix where people ordinarily keep software or
    // work: locally installed tools, source trees, and macOS's user data volume.
    const EXCEPTIONS: [&str; 3] = ["/usr/local", "/usr/src", "/System/Volumes/Data"];
    if EXCEPTIONS
        .iter()
        .any(|area| starts_with(directory, Path::new(area)))
    {
        return None;
    }
    PROTECTED
        .iter()
        .find(|area| starts_with(directory, Path::new(area)))
        .map(|area| (*area).to_owned())
}

#[cfg(windows)]
fn protected_location(directory: &Path) -> Option<String> {
    if directory.parent().is_none() {
        return Some("a drive root".to_owned());
    }
    [
        "SystemRoot",
        "windir",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "ProgramData",
    ]
    .iter()
    .filter_map(|variable| {
        let area = fs::canonicalize(env::var_os(variable)?).ok()?;
        starts_with(directory, &area).then(|| area.display().to_string())
    })
    .next()
}

#[cfg(not(any(unix, windows)))]
fn protected_location(_directory: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_creates_without_clobbering_replaces_on_request_and_never_leaves_staging() {
        let work = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-work");
        fs::create_dir_all(&work).unwrap();
        let directory = Builder::new()
            .prefix("placement unit-")
            .tempdir_in(work)
            .unwrap();
        let stage = |bytes: &[u8]| {
            let mut file = Builder::new()
                .suffix(".muxlet-stage")
                .tempfile_in(directory.path())
                .unwrap();
            file.write_all(bytes).unwrap();
            file.into_temp_path()
        };
        let target = directory.path().join("target");

        publish(stage(b"created"), &target, false, 0).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"created");

        let error = publish(stage(b"clobbering"), &target, false, 0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&target).unwrap(), b"created");

        publish(stage(b"replaced"), &target, true, 0).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"replaced");
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            1,
            "no staged file may remain"
        );
    }

    #[test]
    fn user_typed_paths_that_name_directories_are_recognised() {
        for path in ["bin/", ".", "..", "a/b/.", "a/b/..", "a/..", ""] {
            assert!(names_directory(Path::new(path)), "{path:?}");
        }
        for path in [
            "dotnet",
            "bin/dotnet",
            "a/.hidden",
            "a/b.c",
            "..a",
            "a/...",
            "a/.. b",
        ] {
            assert!(!names_directory(Path::new(path)), "{path:?}");
        }
    }

    #[test]
    fn path_comparison_is_by_component_and_ignores_case_where_filesystems_do() {
        assert!(same_path(Path::new("/a/b"), Path::new("/a/b/")));
        assert!(!same_path(Path::new("/a/b"), Path::new("/a/bc")));
        assert!(!same_path(Path::new("/a/b"), Path::new("/a")));
        assert!(starts_with(Path::new("/a/b/c"), Path::new("/a/b")));
        assert!(!starts_with(Path::new("/a/bc"), Path::new("/a/b")));
        assert_eq!(
            same_path(Path::new("/A/B"), Path::new("/a/b")),
            CASE_INSENSITIVE
        );
    }

    #[cfg(unix)]
    #[test]
    fn system_locations_are_protected_but_per_user_and_local_ones_are_not() {
        for protected in [
            "/usr/bin",
            "/usr",
            "/bin",
            "/etc/muxlet",
            "/sbin",
            "/System/x",
            "/",
        ] {
            assert!(
                protected_location(Path::new(protected)).is_some(),
                "{protected}"
            );
        }
        for allowed in [
            "/usr/local/bin",
            "/usr/src/app",
            "/System/Volumes/Data/Users/me",
            "/home/user/.local/bin",
            "/Users/me/Library/x",
            "/opt/tools",
            "/tmp",
        ] {
            assert!(
                protected_location(Path::new(allowed)).is_none(),
                "{allowed}"
            );
        }
        assert_eq!(
            protected_location(Path::new("/USR/BIN")).is_some(),
            CASE_INSENSITIVE
        );
    }
}
