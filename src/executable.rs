//! Identifying executables: what may be launched directly, Muxlet's own
//! dispatchers and native .NET hosts.

use std::fs::{self, File};
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

#[cfg(windows)]
pub const DOTNET_FILE_NAME: &str = "dotnet.exe";
#[cfg(not(windows))]
pub const DOTNET_FILE_NAME: &str = "dotnet";

/// How a native .NET host names its resolver library.
#[cfg(windows)]
const HOSTFXR: &[u8] = b"h\0o\0s\0t\0f\0x\0r\0";
#[cfg(not(windows))]
const HOSTFXR: &[u8] = b"hostfxr";

/// The stable, NUL-delimited identity carried by every dispatcher binary.
pub fn dispatcher_marker() -> Vec<u8> {
    // Assembled at run time, so that the installer, which links this code too,
    // never contains the marker and is never mistaken for a dispatcher.
    let prefix = std::hint::black_box(b"\0Muxlet:dispatcher:".as_slice());
    let mut suffix = *std::hint::black_box(b"w1:6cf54fa2-4329-46cc-9558-dc1aac2735eb\0");
    suffix[0] ^= 1;
    [prefix, suffix.as_slice()].concat()
}

/// Whether `path` is a native image carrying the dispatcher marker.
pub fn is_dispatcher(path: &Path) -> io::Result<bool> {
    let mut image = File::open(path)?;
    Ok(classify(&mut image)? == Format::Native && contains(image, &dispatcher_marker())?)
}

/// Whether `path` starts with an ELF, Mach-O or PE header.
pub fn is_native(path: &Path) -> io::Result<bool> {
    Ok(classify(&mut File::open(path)?)? == Format::Native)
}

/// Whether `path` is the native image of a .NET host: it references `hostfxr`
/// and, unlike a dispatcher (which names `hostfxr` too), lacks the marker.
pub(crate) fn is_host_image(path: &Path) -> io::Result<bool> {
    host_image(File::open(path)?)
}

fn host_image(mut image: impl Read + Seek) -> io::Result<bool> {
    if classify(&mut image)? != Format::Native || contains(&mut image, &dispatcher_marker())? {
        return Ok(false);
    }
    image.rewind()?;
    contains(image, HOSTFXR)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Native,
    /// A `#!` script, which only Unix launches directly.
    Script,
    Other,
}

/// Classifies an image by its first four bytes.
fn classify(image: &mut impl Read) -> io::Result<Format> {
    let mut header = [0; 4];
    let length = image.read(&mut header)?;
    Ok(if length == header.len() && is_native_header(header) {
        Format::Native
    } else if cfg!(unix) && header[..length].starts_with(b"#!") {
        Format::Script
    } else {
        Format::Other
    })
}

fn is_native_header(header: [u8; 4]) -> bool {
    matches!(
        header,
        [0x7f, b'E', b'L', b'F']
            | [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
            | [b'M', b'Z', _, _]
    )
}

/// Whether `needle` occurs in `reader`, which is read in bounded chunks.
fn contains(mut reader: impl Read, needle: &[u8]) -> io::Result<bool> {
    // Executables are full of NUL bytes, which also delimit the marker, so test
    // one non-NUL byte before comparing a whole window.
    let anchor = needle.iter().position(|&byte| byte != 0).unwrap_or(0);
    let mut buffer = vec![0; 64 * 1024 + needle.len()];
    let mut retained = 0;
    loop {
        let read = match reader.read(&mut buffer[retained..]) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let filled = retained + read;
        if buffer[..filled]
            .windows(needle.len())
            .any(|window| window[anchor] == needle[anchor] && window == needle)
        {
            return Ok(true);
        }
        if read == 0 {
            return Ok(false);
        }
        // Carry over a partial match that the next read may complete.
        retained = filled.min(needle.len() - 1);
        buffer.copy_within(filled - retained..filled, 0);
    }
}

/// Resolves `path` through links and requires a file that the operating system
/// launches as it is: executable, and a native image or, on Unix, a `#!`
/// script. Anything else is refused rather than left to fall back to a shell.
pub fn require_executable(path: &Path) -> Result<PathBuf> {
    let resolved = fs::canonicalize(path)
        .with_context(|| format!("cannot resolve executable '{}'", path.display()))?;
    let metadata = fs::metadata(&resolved)
        .with_context(|| format!("cannot inspect executable '{}'", path.display()))?;
    if !executable_metadata(&metadata) {
        bail!("'{}' is not an executable file", path.display());
    }
    let mut file =
        File::open(&resolved).with_context(|| format!("cannot read '{}'", path.display()))?;
    let format = classify(&mut file)
        .with_context(|| format!("cannot inspect executable format '{}'", path.display()))?;
    if format == Format::Other {
        bail!(
            "'{}' is not a native executable or an executable script with a shebang",
            path.display()
        );
    }
    Ok(resolved)
}

pub(crate) fn executable_metadata(metadata: &fs::Metadata) -> bool {
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Hands out at most `step` bytes per read, interrupting every other call.
    struct Trickle<'a> {
        bytes: &'a [u8],
        step: usize,
        interrupt: bool,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let length = self.step.min(buffer.len()).min(self.bytes.len());
            buffer[..length].copy_from_slice(&self.bytes[..length]);
            self.bytes = &self.bytes[length..];
            Ok(length)
        }
    }

    #[test]
    fn the_marker_is_the_documented_stable_identity() {
        assert_eq!(
            dispatcher_marker(),
            b"\0Muxlet:dispatcher:v1:6cf54fa2-4329-46cc-9558-dc1aac2735eb\0"
        );
    }

    #[test]
    fn needles_are_found_however_reads_divide_them() {
        let needle = b"\0Muxlet:x\0";
        for step in 1..=needle.len() + 1 {
            for start in 0..=needle.len() {
                let mut bytes = vec![0; start];
                bytes.extend_from_slice(needle);
                bytes.extend_from_slice(&[0; 3]);
                let found = |bytes: &[u8]| {
                    let reader = Trickle {
                        bytes,
                        step,
                        interrupt: false,
                    };
                    contains(reader, needle).unwrap()
                };
                assert!(found(&bytes), "step {step}, start {start}");
                // A near miss: everything matches except one byte.
                bytes[start + needle.len() - 2] ^= 1;
                assert!(!found(&bytes), "step {step}, start {start}");
            }
        }
    }

    #[test]
    fn needles_spanning_full_sized_reads_are_found() {
        let needle = b"\0boundary marker\0";
        let boundary = 64 * 1024 + needle.len();
        for start in boundary - needle.len()..=boundary {
            let mut bytes = vec![0; start];
            bytes.extend_from_slice(needle);
            assert!(contains(Cursor::new(&bytes), needle).unwrap(), "{start}");
            bytes.pop();
            assert!(!contains(Cursor::new(&bytes), needle).unwrap(), "{start}");
        }
    }

    #[test]
    fn host_images_reference_hostfxr_and_are_not_dispatchers() {
        let image = |parts: &[&[u8]]| Cursor::new(parts.concat());
        let native = b"\x7fELF".as_slice();
        let padding = vec![0; 100 * 1024];
        let marker = dispatcher_marker();
        assert!(host_image(image(&[native, &padding, HOSTFXR])).unwrap());
        assert!(host_image(image(&[native, HOSTFXR, &padding])).unwrap());
        assert!(!host_image(image(&[native, &padding])).unwrap());
        assert!(!host_image(image(&[native, HOSTFXR, &padding, &marker])).unwrap());
        assert!(!host_image(image(&[b"#!/bin/sh\n", HOSTFXR])).unwrap());
    }
}
