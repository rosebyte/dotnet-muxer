//! Versioned `configuration.json` storage and the shared application-home lock.
//!
//! Implements the cooperative write protocol in `DESIGN.md`. Routing,
//! extension discovery and the configuration path query never parse or lock
//! the document.
//!
//! # Files
//!
//! | Path | Purpose |
//! |---|---|
//! | `<HOME>/configuration.json` | Human-readable, pretty-printed JSON document |
//! | `<HOME>/metadata/application.lock` | Advisory exclusive lock shared by every writer |
//! | `<HOME>/journal/configuration-<UTC>-<id>.json` | Immutable copy of each replaced original |
//!
//! `<UTC>` is `YYYYMMDDTHHMMSSZ` and `<id>` the first twelve hex digits of the
//! original's SHA-256, so names sort chronologically. Core never deletes a
//! snapshot; the user may. A snapshot is always a regular, read-only file with
//! exactly the original's bytes; see the write protocol for what is refused.
//!
//! # Document representation
//!
//! * The document must be one JSON object (UTF-8; a leading byte order mark is
//!   accepted and kept). `schemaVersion` must be the integer `1` and
//!   `extensions` must be an object.
//! * Core owns only the envelope. Each member of `extensions` is an opaque JSON
//!   value owned by that extension, which versions it separately.
//! * Other top-level members, key order, and every value inside an extension
//!   section are preserved opaquely. Numbers keep all their digits (including
//!   integers beyond 64 bits and trailing zeros); the exponent marker is
//!   rewritten as `e+`/`e-`. Whitespace is normalised to two-space indentation
//!   with LF line endings and string escapes are normalised, so values (not
//!   bytes) are preserved.
//! * Object keys, including `"$serde_json::private::Number"` and
//!   `"$serde_json::private::RawValue"`, are never interpreted as library
//!   metadata, whatever their position, spelling or value.
//! * A duplicate object key anywhere in the document, syntax errors, nesting
//!   deeper than 128 levels, lone surrogates, a missing, non-integer or
//!   different `schemaVersion`, and a missing or non-object `extensions` are
//!   all rejected rather than repaired or migrated.
//! * A missing file uses [`Document::new`], written only on commit. A
//!   symbolic link to a regular file is followed and left in place (the target
//!   is replaced in its own directory); dangling or looping links, directories
//!   and special files are rejected.
//!
//! # Publication and recovery
//!
//! Transactions hold [`HomeLock`], check the original fingerprint and resolved
//! target, stage and sync in the destination directory, then save an exact
//! recovery snapshot before the final check and atomic replacement.
//! Creation never overwrites an entry that appeared in the meantime.
//!
//! An existing journal entry is never followed or replaced. Only a regular,
//! singly linked file with identical bytes may be reused; it is made read-only
//! and flushed first. Links, directories, special files and mismatched bytes
//! abort publication.
//!
//! The final check narrows, but is not an operating-system compare-and-swap
//! against an editor racing the last rename. Locked writers cannot race one
//! another. Permission bits of an existing file are preserved (a new file is
//! created private to the user), and a read-only configuration is refused.
//! Failures name the path and say what to change; Muxlet never elevates or
//! changes permissions.
//!
//! # What an error says about the files
//!
//! Every error means the previous configuration is still in place, with one
//! exception: [`ErrorKind::NotDurable`] means the rename succeeded, so the new
//! document **is** the configuration and the previous one is in the named
//! snapshot, but flushing the directory then failed and the change may be lost
//! if the machine crashes before the filesystem catches up. Check the file and
//! repeat the update if it must be durable.
//!
//! Directory flushing reports real failures, except for the explicitly
//! unsupported filesystem/platform cases listed on `sync_directory`.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::Deserialize;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tempfile::Builder;

use crate::home;

/// The only envelope version this implementation reads or writes.
pub const SCHEMA_VERSION: u64 = 1;

/// How long [`HomeLock::acquire`] waits for another Muxlet process.
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// Larger documents are rejected instead of being read into memory.
pub const MAX_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

const SCHEMA_VERSION_KEY: &str = "schemaVersion";
const EXTENSIONS_KEY: &str = "extensions";
const SNAPSHOT_PREFIX: &str = "configuration-";
const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";

/// The advisory lock file shared by every writer of the application home.
pub fn lock_path(home: &Path) -> PathBuf {
    home.join("metadata").join("application.lock")
}

/// The directory holding recovery snapshots of replaced configurations.
pub fn journal_directory(home: &Path) -> PathBuf {
    home.join("journal")
}

pub type Result<T> = std::result::Result<T, Error>;

/// Why an operation was refused or failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Another process still held the application lock when the wait ended.
    Busy,
    /// A filesystem operation failed (permissions, missing space, and so on).
    Io,
    /// The file is not JSON, or lacks the version 1 envelope.
    Malformed,
    /// An object contains the same key twice; nothing was changed.
    DuplicateKey,
    /// `schemaVersion` is a version this implementation cannot edit.
    UnsupportedVersion,
    /// The path is a directory, special file or link that cannot be used.
    UnsupportedEntry,
    /// The file changed after it was read; the configuration was not replaced.
    Changed,
    /// The new document **was published** and is in place, but flushing its
    /// directory failed, so it may not survive a crash or power loss. The
    /// message names the previous version's recovery snapshot.
    NotDurable,
}

/// A refused or failed configuration operation. The message names the path and
/// the next step; [`Error::kind`] allows programmatic handling such as retrying
/// after [`ErrorKind::Busy`] or [`ErrorKind::Changed`].
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    path: PathBuf,
    message: String,
    io_kind: Option<io::ErrorKind>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, path: &Path, message: impl Into<String>) -> Error {
        Error {
            kind,
            path: path.to_owned(),
            message: message.into(),
            io_kind: None,
        }
    }

    pub(crate) fn io(action: impl fmt::Display, path: &Path, source: io::Error) -> Error {
        Error::io_then(action, path, source, "")
    }

    /// An operating-system failure, with a statement of the state it left.
    pub(crate) fn io_then(
        action: impl fmt::Display,
        path: &Path,
        source: io::Error,
        state: &str,
    ) -> Error {
        let mut message = format!("cannot {action} '{}': {source}", path.display());
        if !state.is_empty() {
            message.push_str("; ");
            message.push_str(state);
        }
        if let Some(advice) = advice(&source) {
            message.push_str("; ");
            message.push_str(advice);
        }
        Error {
            kind: ErrorKind::Io,
            path: path.to_owned(),
            message,
            io_kind: Some(source.kind()),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The file, directory or lock the error is about.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The operating-system error category of an [`ErrorKind::Io`] or
    /// [`ErrorKind::NotDurable`] failure.
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        self.io_kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// Guidance appended to operating-system failures the user can fix.
pub(crate) fn advice(error: &io::Error) -> Option<&'static str> {
    // Windows reports a file held open without sharing as these two codes.
    if cfg!(windows) && matches!(error.raw_os_error(), Some(32 | 33)) {
        return Some("another program has it open; close it (an editor, for example) and retry");
    }
    match error.kind() {
        io::ErrorKind::PermissionDenied => Some(
            "check that your user may write there and that no other program has it open; Muxlet \
             never elevates or changes permissions, so fix that yourself or choose a location \
             your user can write to (for example another application home)",
        ),
        io::ErrorKind::ReadOnlyFilesystem => {
            Some("the filesystem is read-only; choose a writable location")
        }
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => {
            Some("the device is out of space or quota; free some and retry")
        }
        _ => None,
    }
}

/// SHA-256 identity of the exact bytes of a configuration file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fingerprint {
    /// There was no file.
    Missing,
    Sha256([u8; 32]),
}

impl Fingerprint {
    pub fn of(bytes: &[u8]) -> Fingerprint {
        Fingerprint::Sha256(Sha256::digest(bytes).into())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fingerprint::Missing => formatter.write_str("missing"),
            Fingerprint::Sha256(digest) => {
                for byte in digest {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

/// A validated version 1 document. Unknown top-level members and every
/// extension section are carried opaquely.
///
/// Clones share the envelope until an extension is changed.
#[derive(Clone, Debug, PartialEq)]
pub struct Document {
    root: Arc<Map<String, Value>>,
}

impl Default for Document {
    fn default() -> Self {
        Document::new()
    }
}

impl Document {
    /// The empty envelope, `{"schemaVersion": 1, "extensions": {}}`.
    pub fn new() -> Document {
        let mut root = Map::new();
        root.insert(SCHEMA_VERSION_KEY.to_owned(), Value::from(SCHEMA_VERSION));
        root.insert(EXTENSIONS_KEY.to_owned(), Value::Object(Map::new()));
        Document {
            root: Arc::new(root),
        }
    }

    /// Validates a complete document with the same strictness as a locked edit.
    pub fn parse(bytes: &[u8]) -> Result<Document> {
        parse_document(Path::new("configuration.json"), bytes).map(|(document, _)| document)
    }

    /// Every extension section, in file order.
    pub fn extensions(&self) -> &Map<String, Value> {
        match self.root.get(EXTENSIONS_KEY) {
            Some(Value::Object(sections)) => sections,
            _ => unreachable!("a validated envelope always has an extensions object"),
        }
    }

    pub fn extension(&self, name: &str) -> Option<&Value> {
        self.extensions().get(name)
    }

    /// Replaces or adds one extension's section, returning the previous value.
    /// A replaced section keeps its position.
    pub fn set_extension(&mut self, name: &str, section: Value) -> Option<Value> {
        self.extensions_mut().insert(name.to_owned(), section)
    }

    /// Removes one extension's section, keeping the others in order.
    pub fn remove_extension(&mut self, name: &str) -> Option<Value> {
        self.extensions_mut().shift_remove(name)
    }

    /// Any top-level member, including ones core does not understand.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.root.get(key)
    }

    /// The pretty-printed document, ending in a newline.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.write_to(&mut bytes, false)
            .expect("a JSON object with string keys always serialises to memory");
        bytes
    }

    fn write_to(&self, mut writer: impl Write, bom: bool) -> io::Result<()> {
        if bom {
            writer.write_all(UTF8_BOM)?;
        }
        serde_json::to_writer_pretty(&mut writer, self.root.as_ref())?;
        writer.write_all(b"\n")?;
        writer.flush()
    }

    fn extensions_mut(&mut self) -> &mut Map<String, Value> {
        match Arc::make_mut(&mut self.root).get_mut(EXTENSIONS_KEY) {
            Some(Value::Object(sections)) => sections,
            _ => unreachable!("a validated envelope always has an extensions object"),
        }
    }
}

/// serde_json keeps the last of two equal keys, silently losing data. This
/// walks the document once, ignoring values, solely to refuse duplicates.
struct RejectDuplicateKeys;

impl<'de> DeserializeSeed<'de> for RejectDuplicateKeys {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for RejectDuplicateKeys {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> std::result::Result<(), A::Error> {
        while items.next_element_seed(RejectDuplicateKeys)?.is_some() {}
        Ok(())
    }

    // With arbitrary_precision, serde_json also presents each number as a
    // one-entry map, which this handles like any other object.
    fn visit_map<A: MapAccess<'de>>(self, mut members: A) -> std::result::Result<(), A::Error> {
        let mut seen = std::collections::HashSet::new();
        while let Some(key) = members.next_key::<String>()? {
            if let Some(key) = seen.replace(key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate object key \"{key}\""
                )));
            }
            members.next_value_seed(RejectDuplicateKeys)?;
        }
        Ok(())
    }
}

/// Validates once before conversion: `RawValue` alone neither rejects
/// duplicate keys nor checks string Unicode and the usual recursion limit.
fn faithful_value(bytes: &[u8]) -> std::result::Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    RejectDuplicateKeys.deserialize(&mut deserializer)?;
    deserializer.end()?;
    value_of(serde_json::from_slice::<&RawValue>(bytes)?)
}

fn value_of(raw: &RawValue) -> std::result::Result<Value, serde_json::Error> {
    let text = raw.get();
    // Value interprets real objects starting with serde_json's private marker
    // keys as numbers or raw text. Both keys start with '$', which can only be
    // written literally or as \u0024. False positives deliberately take the
    // typed-container path; ordinary subtrees use Value without rescanning
    // their contents at every nesting level.
    let possible_marker = || text.contains("\"$") || text.contains("\"\\u0024");
    let mut deserializer = serde_json::Deserializer::from_str(text);
    match text.as_bytes()[0] {
        b'{' if possible_marker() => deserializer.deserialize_map(RawContainer),
        b'[' if possible_marker() => deserializer.deserialize_seq(RawContainer),
        _ => Value::deserialize(&mut deserializer),
    }
}

struct RawContainer;

impl<'de> Visitor<'de> for RawContainer {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object or array")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut members: A) -> std::result::Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some((key, raw)) = members.next_entry::<String, &'de RawValue>()? {
            let value = value_of(raw).map_err(serde::de::Error::custom)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> std::result::Result<Value, A::Error> {
        let mut array = Vec::new();
        while let Some(raw) = items.next_element::<&'de RawValue>()? {
            array.push(value_of(raw).map_err(serde::de::Error::custom)?);
        }
        Ok(Value::Array(array))
    }
}

fn parse_document(path: &Path, bytes: &[u8]) -> Result<(Document, bool)> {
    let (bom, text) = match bytes.strip_prefix(UTF8_BOM) {
        Some(text) => (true, text),
        None => (false, bytes),
    };
    let value = faithful_value(text).map_err(|error| {
        let duplicate = error.classify() == serde_json::error::Category::Data;
        let (kind, advice) = if duplicate {
            (
                ErrorKind::DuplicateKey,
                "remove one of the two members; nothing was changed",
            )
        } else if text.iter().all(u8::is_ascii_whitespace) {
            (
                ErrorKind::Malformed,
                "the file is empty; delete it or write {\"schemaVersion\": 1, \"extensions\": {}}",
            )
        } else {
            (
                ErrorKind::Malformed,
                "fix the file by hand or restore a recovery copy from the journal directory; \
                 it was not changed",
            )
        };
        Error::new(
            kind,
            path,
            format!(
                "'{}' is not a usable configuration: {error}; {advice}",
                path.display()
            ),
        )
    })?;
    let Value::Object(root) = value else {
        return Err(malformed(path, "the top-level value must be a JSON object"));
    };

    match root.get(SCHEMA_VERSION_KEY) {
        None => {
            return Err(malformed(
                path,
                "the required \"schemaVersion\" member is missing",
            ));
        }
        Some(Value::Number(number)) => {
            let text = number.as_str();
            let integer = text.strip_prefix('-').unwrap_or(text);
            if integer.is_empty() || !integer.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(malformed(path, "\"schemaVersion\" must be an integer"));
            }
            if number.as_u64() != Some(SCHEMA_VERSION) {
                return Err(Error::new(
                    ErrorKind::UnsupportedVersion,
                    path,
                    format!(
                        "'{}' uses schema version {text}, but this Muxlet reads and writes only \
                         version {SCHEMA_VERSION}; use a Muxlet that supports it (the file was \
                         not changed)",
                        path.display()
                    ),
                ));
            }
        }
        Some(_) => {
            return Err(malformed(path, "\"schemaVersion\" must be an integer"));
        }
    }
    if !matches!(root.get(EXTENSIONS_KEY), Some(Value::Object(_))) {
        return Err(malformed(
            path,
            "the required \"extensions\" member must be an object",
        ));
    }
    Ok((
        Document {
            root: Arc::new(root),
        },
        bom,
    ))
}

fn malformed(path: &Path, reason: &str) -> Error {
    Error::new(
        ErrorKind::Malformed,
        path,
        format!(
            "'{}' is not a usable configuration: {reason}; fix it by hand (the file was not \
             changed)",
            path.display()
        ),
    )
}

/// An exclusive hold on the application home's advisory lock.
///
/// Every writer of the home (configuration transactions, core placement and
/// cooperating extensions) takes this lock; it is released on drop or when the
/// process exits. Contention is detected across threads and processes because
/// each acquisition uses its own open file, so the lock is deliberately not
/// re-entrant: acquiring it again while a guard is alive waits for that guard.
/// Never hold it across `exec` or while waiting for another process to finish.
#[derive(Debug)]
pub struct HomeLock {
    file: File,
    home: PathBuf,
    path: PathBuf,
}

impl HomeLock {
    /// Waits up to [`DEFAULT_LOCK_TIMEOUT`].
    pub fn acquire(home: &Path) -> Result<HomeLock> {
        HomeLock::acquire_timeout(home, DEFAULT_LOCK_TIMEOUT)
    }

    /// Fails at once with [`ErrorKind::Busy`] if the lock is held.
    pub fn try_acquire(home: &Path) -> Result<HomeLock> {
        HomeLock::acquire_timeout(home, Duration::ZERO)
    }

    /// Creates `<HOME>/metadata/application.lock` if needed and waits up to
    /// `timeout` for it. This is the only place that creates the metadata
    /// directory for a lock, so readers and the path query never write.
    ///
    /// A timeout too large to add to the current time (`Duration::MAX`, say)
    /// waits for as long as the other holder takes, instead of overflowing.
    pub fn acquire_timeout(home: &Path, timeout: Duration) -> Result<HomeLock> {
        let path = lock_path(home);
        let directory = home.join("metadata");
        fs::create_dir_all(&directory).map_err(|error| {
            Error::io(
                "create the application metadata directory",
                &directory,
                error,
            )
        })?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_file() => {
                return Err(Error::new(
                    ErrorKind::UnsupportedEntry,
                    &path,
                    format!(
                        "the lock '{}' must be a regular file, not a link or directory; remove it",
                        path.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::io("inspect the lock", &path, error)),
        }
        let deadline = Instant::now().checked_add(timeout);
        let mut pause = Duration::from_millis(5);
        loop {
            match try_lock(&path) {
                Ok(file) => {
                    return Ok(HomeLock {
                        file,
                        home: home.to_owned(),
                        path,
                    });
                }
                Err(error) if is_contended(&error) => {
                    let wait = match deadline {
                        None => pause,
                        Some(deadline) => {
                            let now = Instant::now();
                            if now >= deadline {
                                return Err(Error::new(
                                    ErrorKind::Busy,
                                    &path,
                                    format!(
                                        "another Muxlet process is using the application home \
                                         (the lock '{}' was still held after {} s); wait for it \
                                         to finish and retry, the lock is released when that \
                                         process exits",
                                        path.display(),
                                        timeout.as_secs()
                                    ),
                                ));
                            }
                            pause.min(deadline - now)
                        }
                    };
                    thread::sleep(wait);
                    pause = (pause * 2).min(Duration::from_millis(100));
                }
                Err(error) => return Err(Error::io("open or lock", &path, error)),
            }
        }
    }

    /// The application home this lock protects.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for HomeLock {
    fn drop(&mut self) {
        // Windows may otherwise release a closed handle's lock late.
        let _ = FileExt::unlock(&self.file);
    }
}

/// The lock is held, or (on Windows) another process opened the file without
/// sharing, which excludes us just as well.
fn is_contended(error: &io::Error) -> bool {
    const SHARING_VIOLATION: i32 = 32;
    error.kind() == io::ErrorKind::WouldBlock
        || error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
        || (cfg!(windows) && error.raw_os_error() == Some(SHARING_VIOLATION))
}

/// Opens the lock file, creating it if needed, and tries to lock it once.
fn try_lock(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    FileExt::try_lock_exclusive(&file)?;
    Ok(file)
}

/// What the file looked like when it was read.
enum Stored {
    Missing,
    File(StoredFile),
}

struct StoredFile {
    /// The regular file holding the document: the resolved target of a link.
    path: PathBuf,
    bytes: Vec<u8>,
    fingerprint: Fingerprint,
    permissions: fs::Permissions,
}

impl Stored {
    fn fingerprint(&self) -> Fingerprint {
        match self {
            Stored::Missing => Fingerprint::Missing,
            Stored::File(file) => file.fingerprint,
        }
    }

    fn same_as(&self, other: &Stored) -> bool {
        match (self, other) {
            (Stored::Missing, Stored::Missing) => true,
            (Stored::File(left), Stored::File(right)) => {
                left.path == right.path && left.fingerprint == right.fingerprint
            }
            _ => false,
        }
    }
}

fn read_stored(path: &Path) -> Result<Stored> {
    let entry = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Stored::Missing),
        Err(error) => return Err(Error::io("inspect the configuration", path, error)),
    };
    let file_path = if entry.file_type().is_symlink() {
        fs::canonicalize(path).map_err(|error| {
            Error::new(
                ErrorKind::UnsupportedEntry,
                path,
                format!(
                    "'{}' is a symbolic link whose target cannot be resolved ({error}); repair \
                     or remove the link",
                    path.display()
                ),
            )
        })?
    } else {
        path.to_owned()
    };
    let metadata = fs::metadata(&file_path)
        .map_err(|error| Error::io("inspect the configuration", &file_path, error))?;
    if !metadata.is_file() {
        let kind = if metadata.is_dir() {
            "a directory"
        } else {
            "not a regular file"
        };
        return Err(Error::new(
            ErrorKind::UnsupportedEntry,
            path,
            format!(
                "'{}' resolves to '{}', which is {kind}; the configuration must be a regular \
                 file or a link to one",
                path.display(),
                file_path.display()
            ),
        ));
    }

    let mut bytes = Vec::new();
    File::open(&file_path)
        .and_then(|file| file.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| Error::io("read the configuration", &file_path, error))?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(malformed(
            path,
            &format!("it is larger than {MAX_DOCUMENT_BYTES} bytes"),
        ));
    }
    Ok(Stored::File(StoredFile {
        path: file_path,
        fingerprint: Fingerprint::of(&bytes),
        bytes,
        permissions: metadata.permissions(),
    }))
}

/// Reads and validates the document without locking. Replacement is atomic, so
/// a reader always sees a complete document. A missing file reads as the empty
/// envelope.
pub fn read(home: &Path) -> Result<Document> {
    let path = home::configuration(home);
    match read_stored(&path)? {
        Stored::Missing => Ok(Document::new()),
        Stored::File(file) => parse_document(&path, &file.bytes).map(|(document, _)| document),
    }
}

/// Locks the home, applies `edit` and commits it: the common read-modify-write.
pub fn update(home: &Path, edit: impl FnOnce(&mut Document)) -> Result<Commit> {
    let lock = HomeLock::acquire(home)?;
    let mut transaction = Transaction::begin(&lock)?;
    edit(transaction.document_mut());
    transaction.commit()
}

/// What a successful [`Transaction::commit`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Commit {
    /// The document was not modified, so the existing file was left alone.
    Unchanged,
    /// There was no file; it was created.
    Created,
    /// The file was atomically replaced after its original bytes were saved.
    Replaced {
        /// The immutable journal copy of the replaced original.
        snapshot: PathBuf,
    },
}

/// One read-edit-commit cycle under a held [`HomeLock`].
///
/// The transaction remembers the fingerprint of what it read; committing
/// refuses with [`ErrorKind::Changed`] if the file is no longer that. Dropping
/// a transaction abandons it without writing anything.
#[derive(Debug)]
pub struct Transaction<'lock> {
    lock: &'lock HomeLock,
    path: PathBuf,
    original: Original,
    bom: bool,
    loaded: Document,
    document: Document,
}

// Debug for the private state keeps `Transaction: Debug` without exposing it.
struct Original(Stored);

impl fmt::Debug for Original {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Original({})", self.0.fingerprint())
    }
}

impl<'lock> Transaction<'lock> {
    /// Reads and validates the configuration. Malformed, duplicate-key,
    /// unsupported or future documents fail here and are never replaced.
    pub fn begin(lock: &'lock HomeLock) -> Result<Transaction<'lock>> {
        let path = home::configuration(lock.home());
        let stored = read_stored(&path)?;
        let (document, bom) = match &stored {
            Stored::Missing => (Document::new(), false),
            Stored::File(file) => parse_document(&path, &file.bytes)?,
        };
        Ok(Transaction {
            lock,
            path,
            original: Original(stored),
            bom,
            loaded: document.clone(),
            document,
        })
    }

    /// `<HOME>/configuration.json`.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn document(&self) -> &Document {
        &self.document
    }

    pub fn document_mut(&mut self) -> &mut Document {
        &mut self.document
    }

    /// The fingerprint of the file as it was read.
    pub fn original_fingerprint(&self) -> Fingerprint {
        self.original.0.fingerprint()
    }

    /// Publishes the edited document. See the module documentation for the
    /// exact sequence. Nothing is written for an unmodified existing document.
    ///
    /// Every error means the previous file is still in place, except
    /// [`ErrorKind::NotDurable`]: then the new document **is** in place and
    /// only its directory flush failed.
    pub fn commit(self) -> Result<Commit> {
        self.commit_with(&mut System)
    }

    fn commit_with(self, effects: &mut dyn Effects) -> Result<Commit> {
        let Transaction {
            lock,
            path,
            original: Original(original),
            bom,
            loaded,
            document,
        } = self;
        if document == loaded && matches!(original, Stored::File(_)) {
            return Ok(Commit::Unchanged);
        }

        let changed = || {
            Error::new(
                ErrorKind::Changed,
                &path,
                format!(
                    "'{}' changed after it was read (an editor or another program wrote it); \
                     the configuration was not replaced, although a recovery snapshot may have \
                     been created; retry to build on the new content",
                    path.display()
                ),
            )
        };
        let current = read_stored(&path)?;
        if !original.same_as(&current) {
            return Err(changed());
        }

        let target = match &current {
            Stored::File(file) => file.path.clone(),
            Stored::Missing => path.clone(),
        };
        let directory = target.parent().unwrap_or(Path::new("."));
        if let Stored::File(file) = &current {
            if file.permissions.readonly() {
                return Err(Error::io(
                    "replace the read-only configuration",
                    &target,
                    io::Error::from(io::ErrorKind::PermissionDenied),
                ));
            }
        }

        // Staging first surfaces unwritable directories before anything else
        // is created, so a refusal leaves no journal entry behind.
        let mut staged = Builder::new()
            .prefix(".configuration-")
            .suffix(".tmp")
            .tempfile_in(directory)
            .map_err(|error| Error::io("stage the new configuration in", directory, error))?;
        document
            .write_to(BufWriter::new(staged.as_file_mut()), bom)
            .and_then(|()| staged.as_file().sync_all())
            .map_err(|error| Error::io("write the staged configuration in", directory, error))?;
        if let Stored::File(file) = &current {
            staged
                .as_file()
                .set_permissions(file.permissions.clone())
                .map_err(|error| Error::io("copy the permissions to", staged.path(), error))?;
        }
        let snapshot = match &current {
            Stored::File(file) => {
                let journal = journal_directory(lock.home());
                let stamp = effects.stamp();
                Some(write_snapshot(
                    &journal,
                    &stamp,
                    &file.bytes,
                    file.fingerprint,
                    effects,
                )?)
            }
            Stored::Missing => None,
        };

        effects.before_publish();
        if !original.same_as(&read_stored(&path)?) {
            return Err(changed());
        }
        effects.before_rename();

        match snapshot {
            Some(snapshot) => {
                staged.persist(&target).map_err(|failure| {
                    Error::io("replace the configuration", &target, failure.error)
                })?;
                effects.sync_directory(directory).map_err(|error| {
                    not_durable(&target, directory, "replaced", Some(&snapshot), &error)
                })?;
                Ok(Commit::Replaced { snapshot })
            }
            None => {
                staged.persist_noclobber(&target).map_err(|failure| {
                    if failure.error.kind() == io::ErrorKind::AlreadyExists {
                        changed()
                    } else {
                        Error::io("create the configuration", &target, failure.error)
                    }
                })?;
                effects
                    .sync_directory(directory)
                    .map_err(|error| not_durable(&target, directory, "created", None, &error))?;
                Ok(Commit::Created)
            }
        }
    }
}

/// The new document is published; only making it durable failed.
fn not_durable(
    target: &Path,
    directory: &Path,
    verb: &str,
    snapshot: Option<&Path>,
    error: &io::Error,
) -> Error {
    let saved = snapshot.map_or_else(String::new, |snapshot| {
        format!(
            " The previous version is saved at '{}'.",
            snapshot.display()
        )
    });
    Error {
        kind: ErrorKind::NotDurable,
        path: target.to_owned(),
        message: format!(
            "the configuration '{}' was {verb} and the new content is in place, but flushing \
             its directory '{}' failed ({error}), so the change may not survive a crash or power \
             loss.{saved} Check the file, and repeat the update if it must be durable",
            target.display(),
            directory.display()
        ),
        io_kind: Some(error.kind()),
    }
}

/// Everything a commit does that depends on the clock or on other processes,
/// so that tests can make it deterministic. Production uses [`System`].
trait Effects {
    /// The `YYYYMMDDTHHMMSSZ` stamp in a new recovery snapshot's name.
    fn stamp(&mut self) -> String;
    /// Flushes a directory after a rename or a new entry in it.
    fn sync_directory(&mut self, directory: &Path) -> io::Result<()>;
    /// Called just before a new recovery snapshot is published, when another
    /// process could create an entry at its name.
    fn before_snapshot_publish(&mut self, _snapshot: &Path) {}
    /// Called just before the final check and replacement, when an editor could
    /// change the file.
    fn before_publish(&mut self) {}
    /// Called between the final check and the rename itself.
    fn before_rename(&mut self) {}
}

struct System;

impl Effects for System {
    fn stamp(&mut self) -> String {
        utc_timestamp(SystemTime::now())
    }

    fn sync_directory(&mut self, directory: &Path) -> io::Result<()> {
        sync_directory(directory)
    }
}

/// Saves the exact original bytes in `journal` before they are replaced and
/// returns the snapshot's path, `configuration-<stamp>-<id>.json`.
///
/// A snapshot is only ever a regular file holding exactly `bytes`, marked
/// read-only, and what is at its name is never followed, opened if it is not a
/// regular file, or replaced:
///
/// * an existing regular file with one name and identical bytes is reused,
///   after it is made read-only and flushed. Anything else there (a link, which
///   could be redirected at the live configuration, a directory, a FIFO, a file
///   with other names or other bytes) is refused;
/// * otherwise the copy is staged, synced and published without replacing
///   anything that appeared since the check; an entry that did is judged by the
///   rules above.
///
/// Every error means the configuration has not been replaced.
fn write_snapshot(
    journal: &Path,
    stamp: &str,
    bytes: &[u8],
    fingerprint: Fingerprint,
    effects: &mut dyn Effects,
) -> Result<PathBuf> {
    fs::create_dir_all(journal)
        .map_err(|error| Error::io("create the recovery journal", journal, error))?;
    let digest = fingerprint.to_string();
    let snapshot = journal.join(format!("{SNAPSHOT_PREFIX}{stamp}-{digest:.12}.json"));

    match fs::symlink_metadata(&snapshot) {
        Ok(existing) => {
            reuse_snapshot(&snapshot, &existing, bytes, journal, effects)?;
            return Ok(snapshot);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::io("inspect the recovery snapshot", &snapshot, error)),
    }

    let mut staged = Builder::new()
        .prefix(".snapshot-")
        .suffix(".tmp")
        .tempfile_in(journal)
        .map_err(|error| Error::io("stage a recovery snapshot in", journal, error))?;
    staged
        .write_all(bytes)
        .and_then(|()| staged.flush())
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|error| Error::io("write a recovery snapshot in", journal, error))?;

    effects.before_snapshot_publish(&snapshot);
    let file = match staged.persist_noclobber(&snapshot) {
        Ok(file) => file,
        Err(failure) if failure.error.kind() == io::ErrorKind::AlreadyExists => {
            // Something appeared after the check. It is never replaced, and
            // the staged copy is discarded; the same rules decide about it.
            drop(failure);
            let existing = fs::symlink_metadata(&snapshot)
                .map_err(|error| Error::io("inspect the recovery snapshot", &snapshot, error))?;
            reuse_snapshot(&snapshot, &existing, bytes, journal, effects)?;
            return Ok(snapshot);
        }
        Err(failure) => {
            return Err(Error::io(
                "publish the recovery snapshot",
                &snapshot,
                failure.error,
            ));
        }
    };
    secure_snapshot(&file, &snapshot, journal, effects)?;
    Ok(snapshot)
}

/// Decides whether an entry found at a snapshot's name may serve as that
/// snapshot, and if so makes it one. See [`write_snapshot`].
fn reuse_snapshot(
    snapshot: &Path,
    existing: &fs::Metadata,
    bytes: &[u8],
    journal: &Path,
    effects: &mut dyn Effects,
) -> Result<()> {
    const NOT_REPLACED: &str = "the configuration was not replaced";
    let refuse = |what: String| {
        Error::new(
            ErrorKind::UnsupportedEntry,
            snapshot,
            format!(
                "the recovery snapshot path '{}' {what}; it was not followed, replaced or \
                 reused, and {NOT_REPLACED}. Remove it and retry",
                snapshot.display()
            ),
        )
    };

    let file_type = existing.file_type();
    if !file_type.is_file() {
        let kind = if file_type.is_symlink() {
            "is a symbolic link"
        } else if file_type.is_dir() {
            "is a directory"
        } else {
            "is not a regular file"
        };
        return Err(refuse(kind.to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if existing.nlink() != 1 {
            return Err(refuse("has more than one hard link".to_owned()));
        }
    }

    let mut file = File::open(snapshot).map_err(|error| {
        Error::io_then("read the recovery snapshot", snapshot, error, NOT_REPLACED)
    })?;
    let opened = file.metadata().map_err(|error| {
        Error::io_then(
            "inspect the recovery snapshot",
            snapshot,
            error,
            NOT_REPLACED,
        )
    })?;
    #[cfg(unix)]
    let same_file = {
        use std::os::unix::fs::MetadataExt;
        (opened.dev(), opened.ino()) == (existing.dev(), existing.ino())
    };
    #[cfg(not(unix))]
    let same_file = true;
    if !opened.is_file() || !same_file {
        return Err(refuse("was replaced while it was being checked".to_owned()));
    }

    // At most one byte more than expected is read, whatever the file holds.
    let expected = bytes.len() as u64;
    let mut found = Vec::with_capacity(bytes.len());
    let identical = opened.len() == expected
        && (&mut file)
            .take(expected + 1)
            .read_to_end(&mut found)
            .map_err(|error| {
                Error::io_then("read the recovery snapshot", snapshot, error, NOT_REPLACED)
            })?
            == bytes.len()
        && found == bytes;
    if !identical {
        return Err(Error::new(
            ErrorKind::Io,
            snapshot,
            format!(
                "the recovery snapshot '{}' already exists with different content; snapshots \
                 are immutable, so it was neither changed nor reused, and {NOT_REPLACED}",
                snapshot.display()
            ),
        ));
    }
    secure_snapshot(&file, snapshot, journal, effects)
}

/// Makes a verified or newly published snapshot read-only and durable: the
/// permission change is applied through the handle that was checked, then the
/// file and the journal directory are flushed.
fn secure_snapshot(
    file: &File,
    snapshot: &Path,
    journal: &Path,
    effects: &mut dyn Effects,
) -> Result<()> {
    const NOT_REPLACED: &str = "the configuration was not replaced";
    let mut permissions = file
        .metadata()
        .map_err(|error| {
            Error::io_then(
                "inspect the recovery snapshot",
                snapshot,
                error,
                NOT_REPLACED,
            )
        })?
        .permissions();
    if !permissions.readonly() {
        permissions.set_readonly(true);
        // The handle is what was checked, so a path swapped in since cannot
        // redirect this. Windows needs write access, which only the path has.
        #[cfg(unix)]
        let protected = file.set_permissions(permissions);
        #[cfg(not(unix))]
        let protected = fs::set_permissions(snapshot, permissions);
        protected.map_err(|error| {
            Error::io_then(
                "protect the recovery snapshot",
                snapshot,
                error,
                NOT_REPLACED,
            )
        })?;
    }
    #[cfg(unix)]
    file.sync_all().map_err(|error| {
        Error::io_then("flush the recovery snapshot", snapshot, error, NOT_REPLACED)
    })?;
    effects.sync_directory(journal).map_err(|error| {
        Error::io_then(
            "flush the recovery journal directory",
            journal,
            error,
            &format!(
                "the snapshot '{}' was written but may not survive a crash, so \
                 {NOT_REPLACED}",
                snapshot.display()
            ),
        )
    })
}

/// Flushes `directory` so that a rename or a newly created entry in it
/// survives a crash or power loss.
///
/// Real failures are returned: the directory cannot be opened, or the flush
/// reports an I/O error. Callers must say accurately what had already happened
/// when it fails (a rename is already visible by then). Exactly one limitation
/// is accepted, and it is deliberately narrow:
///
/// * Unix: the filesystem reports directory flushing as unsupported, which is
///   `ENOSYS` or `EOPNOTSUPP` (`ErrorKind::Unsupported`), `EINVAL`, and on Apple
///   platforms `ENOTSUP` or `ENOTTY` (what `F_FULLFSYNC` returns on network and
///   FAT volumes). Any other error, including a permission failure while
///   opening the directory, is a real failure.
/// * Other platforms (Windows): the standard library cannot flush a directory
///   handle, so nothing is attempted and `Ok` is returned; durability of the
///   rename then rests on the filesystem.
pub(crate) fn sync_directory(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        match File::open(directory)?.sync_all() {
            Err(error) if directory_flush_unsupported(&error) => Ok(()),
            result => result,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}

#[cfg(unix)]
fn directory_flush_unsupported(error: &io::Error) -> bool {
    const EINVAL: i32 = 22;
    #[cfg(target_vendor = "apple")]
    {
        const ENOTTY: i32 = 25;
        const ENOTSUP: i32 = 45;
        if matches!(error.raw_os_error(), Some(ENOTTY | ENOTSUP)) {
            return true;
        }
    }
    error.kind() == io::ErrorKind::Unsupported || error.raw_os_error() == Some(EINVAL)
}

/// `YYYYMMDDTHHMMSSZ` in UTC, which sorts chronologically.
fn utc_timestamp(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let (year, month, day) = civil_date(seconds.div_euclid(86_400));
    let time_of_day = seconds.rem_euclid(86_400);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        time_of_day / 3_600,
        time_of_day % 3_600 / 60,
        time_of_day % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Hinnant's algorithm).
fn civil_date(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Every snapshot below is named with this stamp, so no test depends on the
    /// clock (or on how long the test takes).
    const STAMP: &str = "20260101T000000Z";
    const ORIGINAL: &[u8] = br#"{"schemaVersion":1,"extensions":{"kept":[1,2,3]}}"#;

    fn work_directory() -> tempfile::TempDir {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-work");
        fs::create_dir_all(&root).unwrap();
        tempfile::Builder::new()
            .prefix("config unit \u{00e9}-")
            .tempdir_in(root)
            .unwrap()
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    /// A hook a test runs where another process could interfere.
    type Hook = Box<dyn FnMut()>;
    type SnapshotHook = Box<dyn FnMut(&Path)>;

    /// Deterministic [`Effects`]: a fixed stamp, directories whose flush fails,
    /// and hooks that run at the moments another process could interfere.
    #[derive(Default)]
    struct Probe {
        failing: Vec<PathBuf>,
        flushed: Vec<PathBuf>,
        at_snapshot_publish: Option<SnapshotHook>,
        at_publish: Option<Hook>,
        at_rename: Option<Hook>,
    }

    impl Probe {
        fn failing_flush(directory: &Path) -> Probe {
            Probe {
                failing: vec![directory.to_owned()],
                ..Probe::default()
            }
        }

        fn racing_snapshot(race: impl FnMut(&Path) + 'static) -> Probe {
            Probe {
                at_snapshot_publish: Some(Box::new(race)),
                ..Probe::default()
            }
        }

        fn racing_publish(race: impl FnMut() + 'static) -> Probe {
            Probe {
                at_publish: Some(Box::new(race)),
                ..Probe::default()
            }
        }

        fn racing_rename(race: impl FnMut() + 'static) -> Probe {
            Probe {
                at_rename: Some(Box::new(race)),
                ..Probe::default()
            }
        }
    }

    impl Effects for Probe {
        fn stamp(&mut self) -> String {
            STAMP.to_owned()
        }

        fn sync_directory(&mut self, directory: &Path) -> io::Result<()> {
            if self.failing.iter().any(|failing| failing == directory) {
                return Err(io::Error::other("injected flush failure"));
            }
            self.flushed.push(directory.to_owned());
            sync_directory(directory)
        }

        fn before_snapshot_publish(&mut self, snapshot: &Path) {
            if let Some(race) = self.at_snapshot_publish.as_mut() {
                race(snapshot);
            }
        }

        fn before_publish(&mut self) {
            if let Some(race) = self.at_publish.as_mut() {
                race();
            }
        }

        fn before_rename(&mut self) {
            if let Some(race) = self.at_rename.as_mut() {
                race();
            }
        }
    }

    /// A work directory used as an application home whose configuration is
    /// `bytes`.
    fn home_with(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let directory = work_directory();
        let home = directory.path().to_owned();
        fs::write(home::configuration(&home), bytes).unwrap();
        (directory, home)
    }

    /// Where a [`STAMP`]ed snapshot of `bytes` is published.
    fn snapshot_path(home: &Path, bytes: &[u8]) -> PathBuf {
        let digest = Fingerprint::of(bytes).to_string();
        journal_directory(home).join(format!("{SNAPSHOT_PREFIX}{STAMP}-{}.json", &digest[..12]))
    }

    fn file_name(path: &Path) -> String {
        path.file_name().unwrap().to_string_lossy().into_owned()
    }

    fn names(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn assert_no_staged_files(home: &Path) {
        for directory in [home.to_owned(), journal_directory(home)] {
            let Ok(entries) = fs::read_dir(&directory) else {
                continue;
            };
            let staged: Vec<String> = entries
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| {
                    name.starts_with(".configuration-") || name.starts_with(".snapshot-")
                })
                .collect();
            assert!(
                staged.is_empty(),
                "staged files remain in {}: {staged:?}",
                directory.display()
            );
        }
    }

    fn is_read_only(path: &Path) -> bool {
        fs::symlink_metadata(path).unwrap().permissions().readonly()
    }

    /// Publishes a snapshot of `bytes` in `journal` under the fixed stamp.
    fn publish(journal: &Path, bytes: &[u8], probe: &mut Probe) -> Result<PathBuf> {
        write_snapshot(journal, STAMP, bytes, Fingerprint::of(bytes), probe)
    }

    /// Reads the home's configuration, adds one extension section and commits
    /// with the given effects.
    fn commit_adding(home: &Path, probe: &mut Probe) -> Result<Commit> {
        let lock = HomeLock::acquire(home).unwrap();
        let mut transaction = Transaction::begin(&lock).unwrap();
        transaction
            .document_mut()
            .set_extension("added", serde_json::json!(true));
        transaction.commit_with(probe)
    }

    #[test]
    fn timestamps_are_utc_dates_that_sort_chronologically() {
        assert_eq!(utc_timestamp(at(0)), "19700101T000000Z");
        assert_eq!(utc_timestamp(at(951_782_400)), "20000229T000000Z");
        assert_eq!(utc_timestamp(at(1_000_000_000)), "20010909T014640Z");
        assert_eq!(utc_timestamp(at(1_793_000_000)), "20261026T073320Z");
        assert_eq!(utc_timestamp(at(4_107_542_399)), "21000228T235959Z");
        assert!(utc_timestamp(at(1_000_000_000)) < utc_timestamp(at(1_000_000_001)));
    }

    #[test]
    fn a_change_racing_the_final_publish_is_refused_and_preserved() {
        let (_directory, home) = home_with(br#"{"schemaVersion":1,"extensions":{}}"#);
        let configuration = home::configuration(&home);
        let raced = br#"{"schemaVersion":1,"extensions":{"editor":"wrote this"}}"#;
        let mut probe = Probe::racing_publish({
            let configuration = configuration.clone();
            move || fs::write(&configuration, raced).unwrap()
        });

        let error = commit_adding(&home, &mut probe).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Changed);
        assert_eq!(fs::read(&configuration).unwrap(), raced);
        assert_no_staged_files(&home);
    }

    #[test]
    fn a_file_appearing_while_creating_is_never_overwritten() {
        let directory = work_directory();
        let home = directory.path();
        let configuration = home::configuration(home);
        let mut probe = Probe::racing_publish({
            let configuration = configuration.clone();
            move || fs::write(&configuration, "appeared").unwrap()
        });

        let error = commit_adding(home, &mut probe).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Changed);
        assert_eq!(fs::read(&configuration).unwrap(), b"appeared");
        assert_no_staged_files(home);
    }

    #[test]
    fn a_file_appearing_between_the_final_check_and_the_rename_is_never_overwritten() {
        // The creation path publishes without replacing, so even this window,
        // which no check can close, cannot lose the other program's file.
        let directory = work_directory();
        let home = directory.path();
        let configuration = home::configuration(home);
        let mut probe = Probe::racing_rename({
            let configuration = configuration.clone();
            move || fs::write(&configuration, "appeared late").unwrap()
        });

        let error = commit_adding(home, &mut probe).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Changed);
        assert_eq!(fs::read(&configuration).unwrap(), b"appeared late");
        assert_no_staged_files(home);
    }

    #[test]
    fn extension_sections_keep_their_position_when_replaced_or_removed() {
        let mut document = Document::new();
        for name in ["first", "second", "third"] {
            document.set_extension(name, Value::from(name));
        }
        document.set_extension("second", Value::from("changed"));
        document.remove_extension("first");
        let names: Vec<_> = document.extensions().keys().cloned().collect();
        assert_eq!(names, ["second", "third"]);
        assert_eq!(document.extension("second"), Some(&Value::from("changed")));
    }

    #[test]
    fn document_clones_share_the_envelope_until_an_extension_is_edited() {
        let original = Document::parse(ORIGINAL).unwrap();
        let mut edited = original.clone();
        assert!(Arc::ptr_eq(&original.root, &edited.root));
        assert_eq!(original.to_bytes(), edited.to_bytes());
        assert!(Arc::ptr_eq(&original.root, &edited.root));

        edited.set_extension("added", Value::Bool(true));
        assert!(!Arc::ptr_eq(&original.root, &edited.root));
        assert_eq!(original.extension("added"), None);
        assert_eq!(edited.extension("added"), Some(&Value::Bool(true)));

        let mut removed = edited.clone();
        removed.remove_extension("kept");
        assert!(removed.extension("kept").is_none());
        assert_eq!(edited.extension("kept"), original.extension("kept"));
    }

    #[test]
    fn document_serialisation_propagates_write_and_flush_errors() {
        struct FailingWriter {
            fail_on_write: bool,
        }

        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.fail_on_write {
                    Err(io::ErrorKind::StorageFull.into())
                } else {
                    Ok(bytes.len())
                }
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }

        for bom in [false, true] {
            for (fail_on_write, kind) in [
                (true, io::ErrorKind::StorageFull),
                (false, io::ErrorKind::PermissionDenied),
            ] {
                let error = Document::new()
                    .write_to(FailingWriter { fail_on_write }, bom)
                    .unwrap_err();
                assert_eq!(error.kind(), kind);
            }
        }
    }

    #[test]
    fn a_commit_saves_the_original_then_replaces_it_and_flushes_both_directories() {
        let (_directory, home) = home_with(ORIGINAL);
        let mut probe = Probe::default();

        let commit = commit_adding(&home, &mut probe).unwrap();

        let snapshot = snapshot_path(&home, ORIGINAL);
        assert_eq!(
            commit,
            Commit::Replaced {
                snapshot: snapshot.clone()
            }
        );
        assert_eq!(fs::read(&snapshot).unwrap(), ORIGINAL);
        assert!(is_read_only(&snapshot));
        let document = read(&home).unwrap();
        assert_eq!(document.extension("added"), Some(&Value::Bool(true)));
        assert_eq!(
            document.extension("kept"),
            Some(&serde_json::json!([1, 2, 3]))
        );
        // The journal entry is flushed before the rename, the home after it.
        assert_eq!(probe.flushed, [journal_directory(&home), home.clone()]);
        assert_no_staged_files(&home);
    }

    #[test]
    fn creating_the_configuration_flushes_its_directory_and_writes_no_snapshot() {
        let directory = work_directory();
        let home = directory.path();
        let mut probe = Probe::default();

        assert_eq!(commit_adding(home, &mut probe).unwrap(), Commit::Created);

        assert_eq!(probe.flushed, [home.to_owned()]);
        assert!(!journal_directory(home).exists());
        assert_no_staged_files(home);
    }

    #[test]
    fn replacing_identical_bytes_in_the_same_second_reuses_the_snapshot() {
        let (_directory, home) = home_with(ORIGINAL);
        let first = commit_adding(&home, &mut Probe::default()).unwrap();
        // Restoring the very same original and replacing it again within the
        // same second names the same snapshot, which is reused as it is.
        fs::write(home::configuration(&home), ORIGINAL).unwrap();

        let second = commit_adding(&home, &mut Probe::default()).unwrap();

        let snapshot = snapshot_path(&home, ORIGINAL);
        assert_eq!(
            first,
            Commit::Replaced {
                snapshot: snapshot.clone()
            }
        );
        assert_eq!(second, first);
        assert_eq!(fs::read(&snapshot).unwrap(), ORIGINAL);
        assert_eq!(names(&journal_directory(&home)), [file_name(&snapshot)]);
    }

    #[test]
    fn a_new_snapshot_is_published_read_only_under_its_deterministic_name() {
        let directory = work_directory();
        let journal = journal_directory(directory.path());
        let mut probe = Probe::default();

        let snapshot = publish(&journal, ORIGINAL, &mut probe).unwrap();

        assert_eq!(snapshot, snapshot_path(directory.path(), ORIGINAL));
        let name = file_name(&snapshot);
        let id = name
            .strip_prefix("configuration-20260101T000000Z-")
            .and_then(|rest| rest.strip_suffix(".json"))
            .unwrap_or_else(|| panic!("unexpected snapshot name {name}"));
        assert_eq!(id.len(), 12);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()), "{id}");
        assert_eq!(fs::read(&snapshot).unwrap(), ORIGINAL);
        assert!(is_read_only(&snapshot));
        assert_eq!(names(&journal), [name]);
        assert_eq!(probe.flushed, std::slice::from_ref(&journal));
    }

    #[test]
    fn a_matching_regular_snapshot_is_reused_and_protected_without_new_files() {
        let directory = work_directory();
        let journal = journal_directory(directory.path());
        fs::create_dir_all(&journal).unwrap();
        let existing = snapshot_path(directory.path(), ORIGINAL);
        fs::write(&existing, ORIGINAL).unwrap();
        assert!(!is_read_only(&existing));
        let mut probe = Probe::default();

        let reused = publish(&journal, ORIGINAL, &mut probe).unwrap();

        assert_eq!(reused, existing);
        assert_eq!(fs::read(&existing).unwrap(), ORIGINAL);
        assert!(is_read_only(&existing), "reuse must protect the copy");
        assert_eq!(names(&journal), [file_name(&existing)]);
        assert_eq!(probe.flushed, std::slice::from_ref(&journal));
    }

    #[test]
    fn an_already_read_only_matching_snapshot_is_reused_as_it_is() {
        let directory = work_directory();
        let journal = journal_directory(directory.path());
        fs::create_dir_all(&journal).unwrap();
        let existing = snapshot_path(directory.path(), ORIGINAL);
        fs::write(&existing, ORIGINAL).unwrap();
        let mut permissions = fs::metadata(&existing).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&existing, permissions).unwrap();

        let reused = publish(&journal, ORIGINAL, &mut Probe::default()).unwrap();

        assert_eq!(reused, existing);
        assert_eq!(fs::read(&existing).unwrap(), ORIGINAL);
        assert!(is_read_only(&existing));
        assert_eq!(names(&journal), [file_name(&existing)]);
    }

    #[test]
    fn a_snapshot_with_other_bytes_is_never_reused_or_replaced() {
        let same_length: Vec<u8> = ORIGINAL
            .iter()
            .map(|&byte| if byte == b'3' { b'4' } else { byte })
            .collect();
        assert_eq!(same_length.len(), ORIGINAL.len());
        assert_ne!(same_length, ORIGINAL);
        let others = [
            same_length,
            Vec::new(),
            ORIGINAL[..10].to_vec(),
            [ORIGINAL, &b" "[..]].concat(),
        ];

        for other in others {
            let directory = work_directory();
            let journal = journal_directory(directory.path());
            fs::create_dir_all(&journal).unwrap();
            let existing = snapshot_path(directory.path(), ORIGINAL);
            fs::write(&existing, &other).unwrap();
            let mut probe = Probe::default();

            let error = publish(&journal, ORIGINAL, &mut probe).unwrap_err();

            assert_eq!(error.kind(), ErrorKind::Io);
            let message = error.to_string();
            assert!(message.contains("different content"), "{message}");
            assert!(
                message.contains("the configuration was not replaced"),
                "{message}"
            );
            assert_eq!(fs::read(&existing).unwrap(), other);
            assert!(
                !is_read_only(&existing),
                "a refused entry is left as it was"
            );
            assert_eq!(names(&journal), [file_name(&existing)]);
            assert!(probe.flushed.is_empty());
        }
    }

    #[test]
    fn a_snapshot_name_occupied_by_a_directory_is_refused() {
        let directory = work_directory();
        let journal = journal_directory(directory.path());
        let occupied = snapshot_path(directory.path(), ORIGINAL);
        fs::create_dir_all(&occupied).unwrap();

        let error = publish(&journal, ORIGINAL, &mut Probe::default()).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
        assert!(error.to_string().contains("is a directory"), "{error}");
        assert!(occupied.is_dir());
        assert_eq!(names(&journal), [file_name(&occupied)]);
    }

    #[cfg(unix)]
    #[test]
    fn a_snapshot_symlink_to_the_live_configuration_is_refused_and_never_followed() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (_directory, home) = home_with(ORIGINAL);
        let configuration = home::configuration(&home);
        let journal = journal_directory(&home);
        fs::create_dir_all(&journal).unwrap();
        let link = snapshot_path(&home, ORIGINAL);
        symlink(&configuration, &link).unwrap();
        let mode = fs::metadata(&configuration).unwrap().permissions().mode();
        let mut probe = Probe::default();

        let error = publish(&journal, ORIGINAL, &mut probe).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
        let message = error.to_string();
        assert!(message.contains("is a symbolic link"), "{message}");
        assert!(
            message.contains("the configuration was not replaced"),
            "{message}"
        );
        assert_eq!(fs::read_link(&link).unwrap(), configuration);
        assert_eq!(fs::read(&configuration).unwrap(), ORIGINAL);
        assert_eq!(
            fs::metadata(&configuration).unwrap().permissions().mode(),
            mode,
            "the live configuration must not be protected through the link"
        );
        assert_eq!(names(&journal), [file_name(&link)]);
        assert!(probe.flushed.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_snapshot_symlink_is_refused_and_its_target_is_not_created() {
        let directory = work_directory();
        let journal = journal_directory(directory.path());
        fs::create_dir_all(&journal).unwrap();
        let link = snapshot_path(directory.path(), ORIGINAL);
        let target = directory.path().join("nowhere");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = publish(&journal, ORIGINAL, &mut Probe::default()).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
        assert_eq!(fs::read_link(&link).unwrap(), target);
        assert!(!target.exists());
        assert_eq!(names(&journal), [file_name(&link)]);
    }

    #[cfg(unix)]
    #[test]
    fn a_hard_linked_snapshot_is_refused_and_the_configuration_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (_directory, home) = home_with(ORIGINAL);
        let configuration = home::configuration(&home);
        let journal = journal_directory(&home);
        fs::create_dir_all(&journal).unwrap();
        let linked = snapshot_path(&home, ORIGINAL);
        fs::hard_link(&configuration, &linked).unwrap();
        let mode = fs::metadata(&configuration).unwrap().permissions().mode();

        let error = publish(&journal, ORIGINAL, &mut Probe::default()).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
        assert!(
            error.to_string().contains("more than one hard link"),
            "{error}"
        );
        assert_eq!(
            fs::metadata(&configuration).unwrap().permissions().mode(),
            mode
        );
        assert_eq!(fs::read(&linked).unwrap(), ORIGINAL);
    }

    #[cfg(unix)]
    #[test]
    fn a_snapshot_name_occupied_by_a_fifo_is_refused_without_opening_it() {
        let directory = work_directory();
        let journal = journal_directory(directory.path());
        fs::create_dir_all(&journal).unwrap();
        let fifo = snapshot_path(directory.path(), ORIGINAL);
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !made {
            return;
        }

        // Opening a FIFO nobody writes to blocks for ever, so the attempt runs
        // on its own thread and a regression fails instead of hanging.
        let (sender, receiver) = std::sync::mpsc::channel();
        let attempt = {
            let journal = journal.clone();
            thread::spawn(move || {
                let _ = sender.send(publish(&journal, ORIGINAL, &mut Probe::default()));
            })
        };
        let error = receiver
            .recv_timeout(Duration::from_secs(60))
            .expect("write_snapshot blocked on the FIFO")
            .unwrap_err();
        attempt.join().unwrap();

        assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
        assert!(error.to_string().contains("not a regular file"), "{error}");
        assert_eq!(names(&journal), [file_name(&fifo)]);
    }

    /// Records the inode of the file a racing process creates (Unix), so that a
    /// test can tell that file from a staged copy that replaced it.
    #[cfg(unix)]
    fn inode(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::symlink_metadata(path).unwrap().ino()
    }

    #[test]
    fn a_matching_snapshot_appearing_before_publication_is_adopted_not_replaced() {
        let directory = work_directory();
        let journal = journal_directory(directory.path());
        let target = snapshot_path(directory.path(), ORIGINAL);
        let racer = std::rc::Rc::new(std::cell::Cell::new(0_u64));
        let mut probe = Probe::racing_snapshot({
            let racer = racer.clone();
            move |snapshot: &Path| {
                fs::write(snapshot, ORIGINAL).unwrap();
                #[cfg(unix)]
                racer.set(inode(snapshot));
                #[cfg(not(unix))]
                let _ = &racer;
            }
        });

        let adopted = publish(&journal, ORIGINAL, &mut probe).unwrap();

        assert_eq!(adopted, target);
        assert_eq!(fs::read(&target).unwrap(), ORIGINAL);
        assert!(is_read_only(&target), "an adopted copy is protected too");
        #[cfg(unix)]
        assert_eq!(
            inode(&target),
            racer.get(),
            "the other process's file must stay, not be replaced by the staged copy"
        );
        assert_eq!(names(&journal), [file_name(&target)]);
        assert_eq!(probe.flushed, std::slice::from_ref(&journal));
    }

    #[test]
    fn a_different_snapshot_appearing_before_publication_is_never_replaced() {
        let directory = work_directory();
        let journal = journal_directory(directory.path());
        let target = snapshot_path(directory.path(), ORIGINAL);
        let mut probe = Probe::racing_snapshot(|snapshot: &Path| {
            fs::write(snapshot, b"someone else's bytes").unwrap();
        });

        let error = publish(&journal, ORIGINAL, &mut probe).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Io);
        assert!(error.to_string().contains("different content"), "{error}");
        assert_eq!(fs::read(&target).unwrap(), b"someone else's bytes");
        assert!(!is_read_only(&target));
        assert_eq!(names(&journal), [file_name(&target)], "no staged copy left");
        assert!(probe.flushed.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_appearing_before_publication_is_refused_and_never_replaced() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (_directory, home) = home_with(ORIGINAL);
        let configuration = home::configuration(&home);
        let journal = journal_directory(&home);
        let target = snapshot_path(&home, ORIGINAL);
        let mode = fs::metadata(&configuration).unwrap().permissions().mode();
        let mut probe = Probe::racing_snapshot({
            let configuration = configuration.clone();
            move |snapshot: &Path| symlink(&configuration, snapshot).unwrap()
        });

        let error = publish(&journal, ORIGINAL, &mut probe).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
        assert!(error.to_string().contains("is a symbolic link"), "{error}");
        assert_eq!(fs::read_link(&target).unwrap(), configuration);
        assert_eq!(fs::read(&configuration).unwrap(), ORIGINAL);
        assert_eq!(
            fs::metadata(&configuration).unwrap().permissions().mode(),
            mode
        );
        assert_eq!(names(&journal), [file_name(&target)], "no staged copy left");
    }

    #[cfg(unix)]
    #[test]
    fn a_snapshot_symlink_to_the_live_configuration_blocks_the_commit_and_changes_nothing() {
        // The regression this guards: a matching symlink used to be accepted as
        // the recovery snapshot, and after the commit it led to the NEW document.
        let (_directory, home) = home_with(ORIGINAL);
        let configuration = home::configuration(&home);
        let journal = journal_directory(&home);
        fs::create_dir_all(&journal).unwrap();
        let link = snapshot_path(&home, ORIGINAL);
        std::os::unix::fs::symlink(&configuration, &link).unwrap();

        let error = commit_adding(&home, &mut Probe::default()).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnsupportedEntry);
        assert_eq!(fs::read(&configuration).unwrap(), ORIGINAL);
        assert_eq!(fs::read_link(&link).unwrap(), configuration);
        assert_eq!(names(&journal), [file_name(&link)]);
        assert_no_staged_files(&home);
    }

    #[test]
    fn a_failed_journal_flush_aborts_the_commit_and_leaves_the_configuration_unchanged() {
        let (_directory, home) = home_with(ORIGINAL);
        let mut probe = Probe::failing_flush(&journal_directory(&home));

        let error = commit_adding(&home, &mut probe).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(error.io_kind(), Some(io::ErrorKind::Other));
        let message = error.to_string();
        assert!(message.contains("injected flush failure"), "{message}");
        assert!(message.contains("may not survive a crash"), "{message}");
        assert!(
            message.contains("the configuration was not replaced"),
            "{message}"
        );
        assert_eq!(fs::read(home::configuration(&home)).unwrap(), ORIGINAL);
        assert_no_staged_files(&home);
    }

    #[test]
    fn a_failed_flush_after_the_rename_reports_the_new_state_not_a_failure_to_replace() {
        let (_directory, home) = home_with(ORIGINAL);
        let mut probe = Probe::failing_flush(&home);

        let error = commit_adding(&home, &mut probe).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::NotDurable);
        assert_eq!(error.io_kind(), Some(io::ErrorKind::Other));
        assert_eq!(error.path(), home::configuration(&home));
        let snapshot = snapshot_path(&home, ORIGINAL);
        let message = error.to_string();
        assert!(
            message.contains("was replaced and the new content is in place"),
            "{message}"
        );
        assert!(
            message.contains(&snapshot.display().to_string()),
            "{message}"
        );
        assert!(message.contains("injected flush failure"), "{message}");
        assert!(!message.contains("not replaced"), "{message}");
        // Exactly what the message says: the new document is the configuration
        // and the old one is saved.
        assert_eq!(
            read(&home).unwrap().extension("added"),
            Some(&Value::Bool(true))
        );
        assert_eq!(fs::read(&snapshot).unwrap(), ORIGINAL);
        assert_no_staged_files(&home);
    }

    #[test]
    fn a_failed_flush_after_creating_reports_the_created_file() {
        let directory = work_directory();
        let home = directory.path();
        let mut probe = Probe::failing_flush(home);

        let error = commit_adding(home, &mut probe).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::NotDurable);
        let message = error.to_string();
        assert!(
            message.contains("was created and the new content is in place"),
            "{message}"
        );
        assert!(!message.contains("previous version"), "{message}");
        assert_eq!(
            read(home).unwrap().extension("added"),
            Some(&Value::Bool(true))
        );
        assert!(!journal_directory(home).exists());
        assert_no_staged_files(home);
    }

    #[cfg(unix)]
    #[test]
    fn only_unsupported_directory_flushes_are_accepted() {
        let mut accepted = vec![
            io::Error::from(io::ErrorKind::Unsupported),
            io::Error::from_raw_os_error(22),
        ];
        // What F_FULLFSYNC returns where a volume cannot flush directories.
        #[cfg(target_vendor = "apple")]
        accepted.extend([25, 45].map(io::Error::from_raw_os_error));
        for error in &accepted {
            assert!(directory_flush_unsupported(error), "{error:?}");
        }

        let rejected = [
            io::Error::from_raw_os_error(2),
            io::Error::from_raw_os_error(5),
            io::Error::from_raw_os_error(13),
            io::Error::from_raw_os_error(28),
            io::Error::from_raw_os_error(30),
            io::Error::from(io::ErrorKind::NotFound),
            io::Error::from(io::ErrorKind::PermissionDenied),
            io::Error::from(io::ErrorKind::StorageFull),
            io::Error::other("an unknown failure"),
        ];
        for error in &rejected {
            assert!(!directory_flush_unsupported(error), "{error:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn flushing_a_directory_reports_real_failures() {
        let directory = work_directory();
        sync_directory(directory.path()).unwrap();

        let error = sync_directory(&directory.path().join("missing")).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    const NUMBER_KEY: &str = "$serde_json::private::Number";

    fn object(members: &[(&str, Value)]) -> Value {
        let mut object = Map::new();
        for (key, value) in members {
            object.insert((*key).to_owned(), value.clone());
        }
        Value::Object(object)
    }

    /// The exact digits a number is held as. Unlike comparing the `Value`
    /// with text, this fails for anything that is not a number.
    fn digits(value: &Value) -> &str {
        value
            .as_number()
            .unwrap_or_else(|| panic!("{value:?} is not a number"))
            .as_str()
    }

    #[test]
    fn an_object_keyed_like_serde_jsons_number_marker_stays_an_object() {
        let section = faithful_value(br#"{"$serde_json::private::Number": "123"}"#).unwrap();
        assert!(section.is_object(), "{section:?}");
        assert_eq!(
            section,
            object(&[(NUMBER_KEY, Value::String("123".to_owned()))])
        );

        // A real number is still a number, beside such an object, and keeps
        // exactly the digits it was written with.
        let both =
            faithful_value(br#"[123, {"$serde_json::private::Number": "123"}, 1.50]"#).unwrap();
        let items = both.as_array().unwrap();
        assert_eq!(digits(&items[0]), "123");
        assert!(items[1].is_object());
        assert_eq!(digits(&items[2]), "1.50");
    }

    #[test]
    fn the_converter_validates_duplicates_before_either_conversion_path() {
        assert!(faithful_value(br#"{"a": 1, "a": 2}"#).is_err());
        assert!(
            faithful_value(
                br#"{"x": [{"$serde_json::private::Number": "1", "$serde_json::private::Number": "2"}]}"#
            )
            .is_err()
        );
    }

    /// A small deterministic generator: every run produces the same cases.
    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, bound: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ((self.0 >> 33) as usize) % bound
        }
    }

    const NUMBERS: [&str; 12] = [
        "0",
        "-0",
        "7",
        "123",
        "-12",
        "3.50",
        "0.1000000000000000055511151231257827",
        "123456789012345678901234567890",
        "1E5",
        "1e-7",
        "-2.5E+10",
        "1e400",
    ];

    /// JSON string literals, some spelling reserved words and escapes.
    const STRINGS: [&str; 8] = [
        r#""""#,
        r#""plain""#,
        r#""123""#,
        r#""with \"quotes\" and \\ backslash""#,
        r#""\u00e9\ud83d\ude00 \/ \n\t""#,
        "\"é日本\"",
        r#""$serde_json::private::Number""#,
        r#""\u0024serde_json::private::RawValue""#,
    ];

    /// JSON key literals and what they decode to.
    const KEYS: [(&str, &str); 9] = [
        (r#""a""#, "a"),
        (r#""é""#, "é"),
        (r#""\u0061b""#, "ab"),
        (r#""""#, ""),
        (r#""$""#, "$"),
        (r#""$serde_json::private::Number""#, NUMBER_KEY),
        (r#""\u0024serde_json::private::Number""#, NUMBER_KEY),
        (
            r#""$serde_json::private::RawValue""#,
            "$serde_json::private::RawValue",
        ),
        (
            r#""\u0024serde_json\u003a\u003aprivate::RawValue""#,
            "$serde_json::private::RawValue",
        ),
    ];

    fn space(random: &mut Lcg, text: &mut String) {
        for _ in 0..random.below(3) {
            text.push([' ', '\t', '\n', '\r'][random.below(4)]);
        }
    }

    /// Appends random JSON text (with random spacing) to `text` and returns
    /// the value it must read as, built without the converter under test.
    fn generate(random: &mut Lcg, depth: u32, text: &mut String) -> Value {
        space(random, text);
        let value = match random.below(if depth == 0 { 6 } else { 10 }) {
            0 => {
                text.push_str("null");
                Value::Null
            }
            1 => {
                text.push_str("true");
                Value::Bool(true)
            }
            2 => {
                text.push_str("false");
                Value::Bool(false)
            }
            3 => {
                let literal = NUMBERS[random.below(NUMBERS.len())];
                text.push_str(literal);
                Value::Number(serde_json::from_str(literal).unwrap())
            }
            4 | 5 => {
                let literal = STRINGS[random.below(STRINGS.len())];
                text.push_str(literal);
                Value::String(serde_json::from_str(literal).unwrap())
            }
            6 | 7 => {
                text.push('[');
                let mut items = Vec::new();
                for index in 0..random.below(4) {
                    if index > 0 {
                        text.push(',');
                    }
                    items.push(generate(random, depth - 1, text));
                }
                space(random, text);
                text.push(']');
                Value::Array(items)
            }
            _ => {
                text.push('{');
                let mut members = Map::new();
                for index in 0..random.below(4) {
                    if index > 0 {
                        text.push(',');
                    }
                    space(random, text);
                    let (literal, key) = KEYS[random.below(KEYS.len())];
                    let (literal, key) = if members.contains_key(key) {
                        (format!("\"k{index}\""), format!("k{index}"))
                    } else {
                        (literal.to_owned(), key.to_owned())
                    };
                    text.push_str(&literal);
                    space(random, text);
                    text.push(':');
                    members.insert(key, generate(random, depth - 1, text));
                }
                space(random, text);
                text.push('}');
                Value::Object(members)
            }
        };
        space(random, text);
        value
    }

    /// How many objects start with a key serde_json uses to mark numbers or
    /// raw text: the ones a plain `Value` parse reads wrongly.
    fn reserved_first_keys(value: &Value) -> usize {
        match value {
            Value::Array(items) => items.iter().map(reserved_first_keys).sum(),
            Value::Object(members) => {
                let first = members
                    .keys()
                    .next()
                    .is_some_and(|key| key.starts_with("$serde_json::private::"));
                usize::from(first) + members.values().map(reserved_first_keys).sum::<usize>()
            }
            _ => 0,
        }
    }

    #[test]
    fn generated_documents_read_as_what_they_say_whatever_their_keys() {
        let mut random = Lcg(0x5eed_1234);
        let mut covered = 0;
        for case in 0..600 {
            let mut text = String::new();
            let expected = generate(&mut random, 4, &mut text);

            let actual = faithful_value(text.as_bytes())
                .unwrap_or_else(|error| panic!("case {case}: {error}\n{text}"));

            // Member order is not part of map equality, so compare the text too.
            assert_eq!(actual, expected, "case {case}\n{text}");
            assert_eq!(
                actual.to_string(),
                expected.to_string(),
                "case {case}\n{text}"
            );
            covered += reserved_first_keys(&expected);

            // Writing and reading back changes nothing, compact or pretty.
            for written in [
                serde_json::to_string(&actual).unwrap(),
                serde_json::to_string_pretty(&actual).unwrap(),
            ] {
                let reread = faithful_value(written.as_bytes())
                    .unwrap_or_else(|error| panic!("case {case}: {error}\n{written}"));
                assert_eq!(reread, expected, "case {case}\n{written}");
            }
        }
        assert!(
            covered > 100,
            "the generator must exercise reserved first keys, got {covered}"
        );
    }
}
