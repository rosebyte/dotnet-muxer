# Muxlet

Muxlet is a small, extensible native front end for .NET commands. Its executable
is **`dotnet`** (`dotnet.exe` on Windows), but Muxlet itself needs no installed
.NET SDK or runtime.

```text
dotnet dispatcher configuration  -> Muxlet's configuration path
dotnet foo a b                   -> private dotnet-foo, if installed
dotnet build                     -> private dotnet-build, if installed
everything else                  -> a genuine dotnet installation
```

Only `dispatcher` is reserved. Private extensions can deliberately override
native commands; a broken or failing extension never falls back to another
implementation. Options, application paths and file-based app invocations go
to genuine `dotnet`, not extension discovery.

**Muxlet is not an SDK manager.** `dotnet-sdks`, if separately installed, is an
ordinary optional extension. This repository does not contain SDK tracking,
release catalogues, SDK installation or pruning. Building and releasing core
does not require an extensions checkout.

## Build and install

Build with Rust 1.85 or newer (edition 2024), Cargo and the native linker for
your platform:

```sh
cargo build --release --locked --bins
cargo test --locked
./run.sh install
```

On Windows, use `.\run.ps1 install`. The runners also support `build` and `test`;
installation options are forwarded to the standalone `muxlet-install` helper.
For example:

```sh
./run.sh install --home "$HOME/my muxlet"
```

Installation is per user. It does **not** edit PATH, shell profiles, machine
configuration or SDK roots. Put the application's `bin` directory on your user
PATH yourself. For a custom home, also set `DOTNET_SDK_HOME` in the environment
of subsequent invocations so discovery and configuration use that same home.
This legacy variable names the **Muxlet application home**, not an SDK root.

| Platform | Default application home |
|---|---|
| Windows | `%LOCALAPPDATA%\muxlet` (native known-folder discovery) |
| macOS | `~/Library/Application Support/muxlet` |
| Linux | `$XDG_DATA_HOME/muxlet`, otherwise `~/.local/share/muxlet` |

```text
<APP_HOME>/
    bin/dotnet[.exe]
    configuration.json          created only when configuration is written
    extensions/                 initially empty, never added to PATH
    metadata/
    journal/
    cache/
    staging/
```

Core upgrades replace only the core executable. They preserve configuration,
the entire extensions directory, extension data and recovery information.
See [packaging](packaging/README.md) for placement, explicit backups,
cross-filesystem handling and Windows after-exit updates.

Rust does not imply universal static linking. Native library requirements
depend on the chosen Rust target; there is no .NET dependency.

## Select a genuine .NET installation

A nonempty `DOTNET_ROOT` must be an **absolute installation directory**. Muxlet
uses its `dotnet[.exe]`; invalid explicit selection is an error, with no PATH
fallback.

Without `DOTNET_ROOT` (or when it is empty), Muxlet searches PATH in order.
It follows executable links and excludes itself, links to itself and recognised
copies of Muxlet. If there is no genuine executable, forwarding fails explicitly.
There is no implicit `.dotnet` search, named profile or remembered root.

```sh
DOTNET_ROOT="/path/to/repository/.dotnet" dotnet build
```

Children retain the caller's working directory, environment, streams and native
argument boundaries. The dispatcher does not set PATH or reconcile
`DOTNET_ROOT_X64`, `DOTNET_ROOT_ARM64` or `DOTNET_ROOT(x86)`. On Unix it replaces
itself using `exec`; on Windows it launches, waits and returns the child's exit
result, leaving console controls to the child.

Opaque third-party wrappers may be forwarded to, but are not proof of an SDK
root. An extension which mutates an installation must request an explicit
`DOTNET_ROOT` rather than guess or skip an earlier PATH choice. This is not a
security or universal SDK-isolation boundary: directly launched applications,
apphosts, `sdk.paths` and native tool discovery retain their own behaviour.

## Configuration path

```sh
dotnet dispatcher configuration
dotnet dispatcher --home "/custom application home" configuration
```

The output is exactly the absolute configuration filename and a newline.
Diagnostics use stderr and a nonzero exit status. The query does not read,
create, repair or migrate configuration; it works with missing, malformed,
unreadable or future-version configuration and without an SDK.

Home precedence is a core command's explicit `--home`, then nonempty
`DOTNET_SDK_HOME`, then the platform default. An extension's `--home` belongs to
that extension and is not consumed by the router.

The common JSON envelope is:

```json
{
  "schemaVersion": 1,
  "extensions": {}
}
```

Configuration writers share `<APP_HOME>/metadata/application.lock`, preserve
unrelated JSON, refuse incompatible edits, retain recoverable originals and
check content fingerprints before atomic replacement. The path query,
forwarding and extension discovery do not use this write service.

## Install an extension

Place a trusted executable and its supporting files under
`<APP_HOME>/extensions`. For `dotnet foo a b`, Muxlet launches
`extensions/dotnet-foo` (or `dotnet-foo.exe`) with just `a b`. Discovery is not
recursive and never searches the working directory or general PATH.

Extensions receive the unchanged caller environment plus:

| Variable | Contract |
|---|---|
| `MUXLET_CONTRACT_VERSION` | `1` |
| `MUXLET_HOME` | Absolute application home used for discovery |
| `MUXLET_DISPATCHER` | Resolved path of the running dispatcher |

Launching an extension does not resolve or start a genuine SDK. Extensions
resolve roots lazily under the [published contract](DESIGN.md), so they can
initialise an empty installation. Extensions run as the current user; this is
not a plug-in sandbox or an in-process ABI.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

Integration tests compile small native fixtures; they require neither .NET nor
an extensions repository. CI covers Linux, macOS and Windows, including
platform-specific process tests. A platform is not considered validated merely
because its code compiles on another platform.

This pivot replaces the former NativeAOT VS Code/testhost muxer. Its
`DOTNET_MUXER_TARGET`, automatic repository selection and generated shell hooks
are not Muxlet interfaces. Remove any old generated shell-profile block and old
PATH entry manually; the new installer does not rewrite your profiles.
