# Packaging and installation

Muxlet is one Cargo package that builds two native executables:

| Executable | Purpose |
|---|---|
| `dotnet` (`dotnet.exe`) | The dispatcher. This is the file that goes on your PATH. |
| `muxlet-install` (`muxlet-install.exe`) | A separate bootstrap helper that places the dispatcher. It is **not** a dispatcher command, and it is not copied into the application home. |

Neither needs .NET. Installation is per user: it never edits PATH or shell
profiles, never installs SDKs, never uses `sudo` or any other elevation, and
never changes permissions to make something work.

## Bootstrap

From a checkout, with Rust 1.85 or newer:

```sh
./run.sh install                                  # build in release mode, install for you
./run.sh install --home "$HOME/my muxlet"         # a custom application home
./run.sh install --backup "$HOME/dotnet.previous" # keep what was replaced
```

```powershell
.\run.ps1 install
.\run.ps1 install --home "$HOME\my muxlet" --backup "$HOME\dotnet.previous"
```

The runners only wrap Cargo (`build`, `test`, `install`) and never invoke
`dotnet`. `install` runs `cargo build --release --locked --bins`, then
`muxlet-install` with exactly the arguments you gave. Without the runners:

```sh
cargo build --release --locked --bins
target/release/muxlet-install            # installs the dotnet built beside it
```

The runners select this repository with `--manifest-path` and explicitly load
its Cargo configuration, keeping the caller's working directory. Relative home,
destination and backup paths therefore keep their ordinary caller-relative
meaning, even when the runner is elsewhere.

From a release archive, keep `muxlet-install` and `dotnet` in one directory and
run the helper, or name the dispatcher explicitly with `--source`.

## Command line

```text
muxlet-install [--source FILE] [--home PATH] [--destination FILE]
               [--backup FILE] [--wait-pid PID] [--lock-timeout SECS]
muxlet-install --help
```

| Option | Meaning |
|---|---|
| `--source FILE` | The dispatcher to install. Default: `dotnet[.exe]` in the directory of the helper's real location (links followed), never the working directory. |
| `--home PATH` | The application home. Default: nonempty `DOTNET_SDK_HOME`, otherwise the platform default below. A relative path is made absolute against the working directory. |
| `--destination FILE` | A **complete file name** to create or replace. Default: `<home>/bin/dotnet[.exe]`. |
| `--backup FILE` | A complete file name at which to save the entry being replaced. |
| `--wait-pid PID` | Windows only. Wait for that process to exit, then replace. |
| `--lock-timeout SECS` | How long to wait for another Muxlet process that holds the application lock. Default 30. |

Each option takes its value as the next argument and may be given once. Exit
status: `0` success, `1` failure (the reason is on stderr, nothing was
silently skipped), `2` bad command line.

Default application homes: `%LOCALAPPDATA%\muxlet` (Windows),
`~/Library/Application Support/muxlet` (macOS), `$XDG_DATA_HOME/muxlet` or
`~/.local/share/muxlet` (Linux).

**A custom home must be used consistently at run time.** The dispatcher finds
its extensions and configuration from `DOTNET_SDK_HOME` (or the platform
default), not from where it sits. When `--home` differs from what a normal
invocation would resolve, the helper reminds you to set `DOTNET_SDK_HOME` for
every `dotnet` invocation. That variable names the Muxlet application home, not
a .NET SDK root.

## What is created

```text
<home>/
    bin/dotnet[.exe]        the only file installation replaces
    extensions/             created empty; never written
    metadata/application.lock   the shared advisory lock (see below)
    journal/                created empty; never written by the helper
    cache/                  created empty; never written
    staging/                created empty; usable for backups
    configuration.json      never created, read or changed by installation
```

Installation creates only the home and those six directories. Any other
missing directory (for a `--destination` or `--backup` elsewhere) is yours to
create, and its absence is an error. Configuration, extension executables,
extension data, metadata, journals and caches are never overwritten or
deleted, so core upgrades leave independently released extensions such as
`dotnet-sdks` exactly as they were.

## Placement semantics

1. The destination and backup are complete file names, never directories.
2. An existing regular file **or symbolic link** at the destination is
   replaced. By default no backup is kept.
3. `--backup FILE` saves the old entry at exactly that path first, with no
   numbering, and overwrites an existing backup file or link there without
   asking. A regular file is saved as a copy of its bytes and permission bits
   (not timestamps, ownership, extended attributes or ACLs).
4. If there was no old destination, an existing backup is left untouched.
5. A symbolic link is an entry. Replacing it replaces the link, not its target.
   Backing it up creates a new link with the **identical stored text**; a
   relative link can resolve to something else from another directory.
   Backing up over a link replaces that link and never follows it.
6. Refused before anything is written (the application home is checked for
   protected locations too):
   * an actual directory, FIFO, socket or device as destination or backup;
   * destination and backup that are the same entry, even through a
     parent-directory link, a hard link, or a different spelling (and, on
     case-insensitive systems, a different case);
   * a source that is the destination or the backup, or a destination link
     that points at the backup;
   * protected system locations, after resolving links: on Unix `/`, `/bin`,
     `/boot`, `/dev`, `/etc`, `/lib*`, `/proc`, `/sbin`, `/sys`, `/usr`
     (except `/usr/local` and `/usr/src`), `/System` (except
     `/System/Volumes/Data`), `/Library` and `/private/etc`; on
     Windows drive roots, `%SystemRoot%`, `%ProgramFiles%`,
     `%ProgramFiles(x86)%`, `%ProgramW6432%` and `%ProgramData%`;
   * the directory of any genuine .NET installation: one with `host/fxr` or
     `shared/Microsoft.NETCore.App` (or both `sdk` and `shared`) beneath it, or
     one named by a nonempty absolute `DOTNET_ROOT` (also its `_X64`, `_X86`,
     `_ARM64` and `(x86)` forms). Replacing its launcher would make `dotnet`
     forward to itself. A link that points at a genuine launcher can still be
     replaced; the launcher is never touched;
   * inside the application home, anything except files under `bin/` and
     `staging/`.
7. The source must be a native Muxlet dispatcher. Each artefact is staged in
   the directory it will live in (so every rename stays on one filesystem,
   whatever the source, home, destination and backup filesystems are), hashed,
   re-read and verified, and then published by an atomic rename. On Unix the
   installed mode is the source's with group and other write bits and the
   setuid, setgid and sticky bits removed (the owner always has read, write
   and execute).
8. The backup is published before the destination is touched. A pre-publication
   failure leaves the old destination in place and any completed backup remains
   a complete copy. A directory-sync failure after publication is reported
   explicitly, including which replacement has already happened. Atomic
   replacement avoids publishing a partial file; power-loss guarantees depend
   on filesystem and platform durability support. An interrupted run can leave
   `.muxlet-stage` files beside the destination or backup, which are safe to
   delete.
9. Writers share one exclusive advisory lock, `<home>/metadata/application.lock`,
   with configuration writers, so an installation and a configuration update
   never interleave. The lock is released when the helper exits. Routing and
   `dotnet dispatcher configuration` never take it. The cooperative
   configuration protocol that uses the same lock (envelope, fingerprints,
   atomic replacement and the recovery journal in `<home>/journal`) is
   documented in the `muxlet::config` module (`src/config.rs`).

Unwritable locations fail with the path and a suggestion to choose somewhere
your user can write. Nothing escalates.

## Putting the dispatcher on your PATH

Muxlet never does this for you. Do it yourself, once.

* Linux and macOS: add the home's `bin` to your shell profile, for example
  `export PATH="$HOME/.local/share/muxlet/bin:$PATH"` (Linux) or
  `export PATH="$HOME/Library/Application Support/muxlet/bin:$PATH"` (macOS).
* A fixed link from an existing user-owned bin directory works too:
  `ln -s "<home>/bin/dotnet" "$HOME/bin/dotnet"`. Update by running the default
  installation again; the link keeps pointing at the new file. Do not pass the
  link as `--destination` unless you mean to replace the link itself with a
  copy.
* Windows: add `%LOCALAPPDATA%\muxlet\bin` to the **user** Path under
  Settings, System, About, Advanced system settings, Environment Variables, or
  run `[Environment]::SetEnvironmentVariable('Path', "$env:LOCALAPPDATA\muxlet\bin;" + [Environment]::GetEnvironmentVariable('Path', 'User'), 'User')`
  yourself. Open a new terminal afterwards.

Never put `<home>/extensions` on PATH, and remove any block the old
NativeAOT muxer added to your profile by hand.

## Updating

Run the helper again with a newer dispatcher. On Linux and macOS a running
`dotnet` is replaced atomically and keeps running its old image.

Windows cannot replace a running or locked executable. The helper then leaves
the original in place and fails with guidance (any requested backup is already
complete). To update after the program exits, start the helper before it ends,
naming the process whose image is the destination:

```text
muxlet-install.exe --wait-pid 12345 --source C:\Downloads\muxlet\dotnet.exe
```

For example, an updater that is about to exit can start
`muxlet-install.exe` detached with its own PID and then return. The helper
waits for that process with an ordinary-user handle (no elevation, nothing is
terminated), takes the lock, and replaces the file, retrying briefly after the
exit while the system releases the image. It waits for one PID; if another copy
of the destination is still running, replacement fails with the same guidance.
A PID that no longer exists counts as already exited. Waiting for a recycled
PID is possible in principle, so pass the PID shortly after reading it.

## Linkage and platform notes

* Rust does not imply static linking. The standard library and crates are
  linked statically, but system libraries are chosen by the target: Linux
  `-gnu` targets need a glibc at least as new as the build machine's (a
  `-musl` target links statically); macOS links the system libraries that ship
  with the OS. This repository's Cargo configuration gives Windows `-msvc`
  targets `-C target-feature=+crt-static`, so release payloads need no separate
  Visual C++ redistributable installation. Windows system DLLs are still OS
  dependencies. Custom build flags can change that linkage policy.
  Check a build with `ldd`, `otool -L` or `dumpbin /dependents`. None of these
  is .NET.
* Release builds use thin LTO and strip symbols (see `Cargo.toml`).
* Backups copy content and permission bits, not ownership, extended attributes
  or ACLs.
* On Windows, directory links and junctions cannot be replaced. Recreating a
  file link as a backup needs Developer Mode or elevation, which Muxlet will
  not request; the helper then fails before replacing anything.
* Creating a missing destination requires an atomic no-replace operation or
  hard-link support. If the filesystem cannot provide it, placement fails
  rather than risk overwriting a file which appeared concurrently.
* Directory metadata is synchronised after renames where the platform supports
  it. Real I/O failures are reported even if a replacement has already happened;
  the diagnostic identifies the published state rather than claiming rollback.

The opt-in cross-filesystem test requires a genuinely different filesystem;
running it against another directory on the same volume is rejected. Linux CI
runs it with `MUXLET_TEST_FOREIGN_DIRECTORY=/dev/shm`. Native Windows console
and update behaviour still requires execution on Windows, not cross-compilation.
