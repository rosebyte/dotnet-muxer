# Muxlet dispatcher contract

Date: 24 October 2026. Contract version: 1.

This is the dispatcher repository's architecture and published extension
contract. Muxlet is the product and Cargo package name; its command remains
`dotnet` on Unix and `dotnet.exe` on Windows. The separate extensions repository
has its own sources, lockfile, releases and compatibility policy. It is not a
Cargo member, submodule, path dependency or required checkout.

## Boundary

Core owns command routing, application-home discovery, genuine-host resolution,
native process handoff, the configuration envelope and safe core placement.
Core has no .NET startup dependency and does not contain an SDK manager.

Only `dispatcher` is reserved, initially with `configuration` and core help.
`sdks`, `sdk`, `build` and every other ordinary command name are available to
private executable extensions. SDK tracking, release catalogues, installation
and pruning belong to a separately installed `dotnet-sdks`, not this package.
There are no named roots, root-switching commands, active-root settings,
parent-shell hooks, automatic extension updates, shared mutable SDK facades,
in-process plug-ins or privileged helpers.

## Source and release layout

```text
Cargo.toml
Cargo.lock
README.md
DESIGN.md
src/                         native core and local storage/placement services
tests/                       native executable fixtures and acceptance cases
packaging/install.rs         separate muxlet-install bootstrap helper
packaging/README.md
```

The initial implementation uses Rust 2024 with a Rust 1.85 baseline. The
standalone helper is a second binary in the same package, not an additional
dispatcher command. Neither binary builds or installs any extension. Any future
reusable crate must be an explicitly versioned dependency, not a relative
checkout or an unpinned branch. No shared framework or third repository is a
prerequisite.

Windows MSVC builds statically link the C runtime through the repository's Cargo
configuration, avoiding a separate runtime installer. Other targets retain their
native platform linkage; required system libraries are documented in packaging.

## Routing

```text
our dotnet [arguments]
    dispatcher ...             -> core command handler
    matching private command   -> <APP_HOME>/extensions/dotnet-<command>[.exe]
    otherwise                  -> genuine dotnet, all original arguments
```

Core usage errors never become extension or genuine-CLI invocations.
An installed extension's parser, nonzero exit, broken link, missing execute
permission or launch failure is final; another implementation is not tried.
An absent extension uses ordinary genuine fallback. Removing `dotnet-sdks`
therefore reveals no built-in SDK management.

Extension candidates must be ordinary command names. Reject options, leading
dots, path separators, drive/path syntax and traversal before constructing a
filename. Application suffixes (`.dll`, `.exe`, `.cs`, `.csx`, `.fs`, `.fsx`,
`.vb`, `.vbx`) and existing application files are forwarded directly. Native
argument strings and non-ASCII command names are not decoded and reassembled.

Discovery is one level deep, solely in the selected home's `extensions`
directory. Supporting files require no manifest or registration. Never add that
directory to PATH. Once forwarded, genuine .NET keeps its own global/local
tool and PATH resolution.

| Invocation | Behaviour |
|---|---|
| `dotnet dispatcher configuration` | Core path query |
| `dotnet sdks update --prune`, SDKs installed | Private `dotnet-sdks update --prune` |
| `dotnet sdks update --prune`, SDKs absent | Genuine `dotnet sdks update --prune` |
| `dotnet foo a b`, extension installed | Private `dotnet-foo a b` |
| `dotnet build`, override installed | Private `dotnet-build` |
| `dotnet build`, no override | Genuine `dotnet build` |
| `dotnet --list-sdks` | Genuine host inventory |
| `dotnet sdk check`, no override | Genuine built-in SDK command group |

## Genuine executable resolution

### Explicit selection

Nonempty `DOTNET_ROOT` selects `<DOTNET_ROOT>/dotnet[.exe]`. The root must be
absolute. An invalid, missing, non-executable or self-referential explicit
selection is an error, not permission to search another installation.

Resolve executable symlinks when identifying a launcher. A directory containing
a launcher link is not necessarily the actual installation root. Do not run an
SDK merely to select a host.

### PATH fallback

When `DOTNET_ROOT` is absent or empty, search PATH in order for another
`dotnet[.exe]`. Honour executable eligibility, follow links and exclude the
current dispatcher, hard links and recognised copies of Muxlet. Report missing
hosts explicitly. Do not infer roots from configuration, the current directory,
profile names or a previous invocation. Relative/empty PATH components retain
their ordinary platform interpretation; they are not an implicit SDK search.

Native dispatcher binaries contain a stable, NUL-delimited identity:
`Muxlet:dispatcher:v1:6cf54fa2-4329-46cc-9558-dc1aac2735eb`. Identity scanning
also requires a native executable header. This marker belongs to the dispatcher
binary only, not the installer. Keep it stable across compatible releases so
old and new copies can exclude one another.

Opaque wrappers are valid forwarding choices. Do not silently skip one to
select a later SDK for mutation. An extension unable to prove a wrapper's
installation location must request an explicit `DOTNET_ROOT`.

### Recursion and legitimate nested calls

Exclude identifiable dispatcher copies before process launch. For opaque
wrappers, use private forwarding context scoped to live process ancestry:
process ID, start time and canonical target bytes. A repeated target in the
same unresolved wrapper chain is an error, including chains which spawn child
processes rather than replacing themselves.

An inherited boolean or global depth guard is insufficient: SDKs legitimately
invoke `dotnet` again. Drop stale process records and reset context at a
recognised native .NET host boundary. Recognition uses the resolved native
image, the standard `host/fxr` layout and a native hostfxr reference, excluding
Muxlet; a launcher can be renamed behind a link. This does not confer trust or
grant permission to mutate that inferred root. Direct recognised-host forwarding
clears the private context; opaque-wrapper chains can also cross a real host before a nested call.
If a nonstandard wrapper hides all such evidence, explicit `DOTNET_ROOT` to the
actual installation removes the ambiguity.

`MUXLET_FORWARD_CHAIN` is private implementation context, not a user setting or
an extension-registration interface. Core commands ignore it and extensions
start a fresh command boundary.

## Process and environment contract

Launch by resolved executable path with native argument values, never by
interpolating a command into a shell. Preserve working directory, stdin, stdout,
stderr and exit result. The only removed/added environment values are the
private forwarding context and the documented extension handoff below.

On Unix use `execve` directly, preserving process identity and the caller's
streams, and restoring default SIGPIPE handling for the external program.
Unlike `CommandExt::exec` (which calls `execvp`), `execve` never tries a shell
when the kernel rejects an executable image. A shebang still selects its
interpreter normally. Report failed exec explicitly. No application lock is
held across exec.

On Windows launch and wait in the inherited console, and propagate the full
child exit result. The waiting dispatcher handles Ctrl+C/Ctrl+Break without
exiting before the child receives the console event. Other console termination
follows Windows behaviour; do not promise Unix replacement or cancellation
semantics. Platform-gated tests exercise console controls and after-exit update
behaviour on Windows.

Do not assign PATH or change generic/architecture-specific root variables while
forwarding. In particular, leave `DOTNET_ROOT_X64`, `DOTNET_ROOT_ARM64`,
`DOTNET_ROOT(x86)` and future architecture overrides alone.

An extension receives:

| Variable | Meaning |
|---|---|
| `MUXLET_CONTRACT_VERSION=1` | Version of this executable contract |
| `MUXLET_HOME` | Absolute home used to discover it |
| `MUXLET_DISPATCHER` | Actual resolved dispatcher executable |

The original `DOTNET_ROOT` and PATH are the lazy root-selection inputs.
Extensions follow the resolution contract themselves; launching one never
depends on successfully resolving or starting an SDK. No public root command
or checkout-coupled helper is required.

Children are trusted installed code with the user's permissions, not a
sandbox. Directly launched apphosts, app-local hosting, explicit paths,
`sdk.paths` and independent tool discovery can choose another installation.
Muxlet is neither a security nor a universal SDK-isolation boundary.

## Application home and configuration path

Home precedence is explicit `--home PATH` on a core-owned command, nonempty
legacy `DOTNET_SDK_HOME`, then the native per-user default. An explicit relative
home is made absolute against the caller's current directory. Defaults use
Rust platform adapters: Windows known local application data, macOS
`~/Library/Application Support`, Linux absolute XDG data home or
`~/.local/share`, each followed by `muxlet`.

`DOTNET_SDK_HOME` refers to this application's home, not a genuine SDK root.
Renaming the product does not silently rename this existing environment
interface. A custom installation must keep this setting consistent at runtime;
there is no persistent active-home setting. Extension arguments, including
their `--home`, are never consumed by the dispatcher.

`dotnet dispatcher configuration` prints exactly
`<APP_HOME>/configuration.json` as an absolute filename, then a newline.
`--home PATH` may appear before or after `configuration`. It requires no SDK,
valid root, extension, configuration read or write access. It never creates
files, launches an editor, repairs or migrates a document. Diagnostics use
stderr and nonzero status. On Unix the filename's native bytes are preserved.

## Configuration ownership and write protocol

The initial pretty-printed JSON envelope is:

```json
{
  "schemaVersion": 1,
  "extensions": {}
}
```

Core owns the envelope, not extension-specific schemas. An extension owns its
namespaced section, for example `extensions.sdks`, with independently versioned
content. Discovering an extension need not create any configuration section.
Do not add TOML, YAML, JSONC or multi-format discovery before needed.

Cooperating core and extension writers must:

1. Acquire the exclusive application-home lock at
   `<APP_HOME>/metadata/application.lock`.
2. Read and validate the supported common envelope, rejecting malformed,
   duplicate-key or incompatible documents rather than replacing unknown data.
3. Preserve unrelated extension and envelope values as opaque JSON, including
   numerical precision. Missing configuration is initialised only upon commit.
4. Record the original bytes' fingerprint. Retain a recoverable original in
   `journal` before publishing a replacement.
5. Stage the complete new document in its destination filesystem, synchronise
   it, recheck the current content fingerprint, and atomically replace only on
   a matching original.

An external editor does not honour the advisory lock. Fingerprints detect its
changes before commit; the final check is not an operating-system compare-and-
swap against an editor racing the final rename. Editors and writers should
avoid concurrent publication. No initial legacy migration is invented: future
migrations must preserve originals and publish only successful, supported
transformations. Older versions refuse incompatible edits.

Keep known configuration, metadata and journals central so migration need not
search SDK roots. Centralisation does not make core responsible for extension
business meaning. Routing, discovery and the path query never take this lock
or parse/migrate the document.

## Installation, replacement and recovery

The application layout is `bin`, `configuration.json`, `extensions`, `metadata`,
`journal`, `cache` and `staging`. Initial core installation leaves extensions
empty. An extension's supporting files remain private to the application home.
Packaging resolves supporting payloads relative to the actual helper, not the
current directory.

Installation is user-level only: manual user PATH selection or a fixed link
from an existing user-owned bin directory. No system-bin link, machine PATH,
`/etc` configuration, Program Files installation, elevation, automatic shell
profile rewrite or environment-changing parent-shell hook is needed.

The separate `muxlet-install` helper stages and verifies a native dispatcher
before placement. Destination and backup options are **complete filenames**:

1. Replace an existing regular file/symlink by default, without a backup.
2. `--backup BACKUP_PATH` saves the old entry at exactly that path, replacing
   an existing backup file/symlink without prompting or numbered names.
3. If there was no destination, leave an existing backup untouched.
4. Back up symlink entries and their stored link text, never their targets.
5. Reject directories, unsupported entries, identity collisions, protected
   paths and replacement of a managed root's genuine launcher.
6. Complete requested backup before discarding the original destination.
   Cross-filesystem copies are staged on each target filesystem.

Failures remain recoverable and visible, with guidance to choose a writable
location. Core updates replace only core-owned payloads, preserving the entire
extensions directory, independently released SDKs, configuration, metadata and
recovery information. Windows uses a standalone after-exit helper mechanism
(`--wait-pid`); a locked/running destination is never treated as a successful
upgrade. See [packaging details](packaging/README.md).

Native library/linker requirements are properties of the chosen Rust target,
not a promise of universal static linking. Cross-platform operation and
performance must be established by execution, not inferred from this design.

## Acceptance scope

Integration fixtures require no .NET installation and no companion checkout.
They cover empty homes, configuration independence, core precedence, extension
overrides/failures, native arguments/cwd/environment/streams/status, root and
PATH precedence, executable links/copies, wrapper recursion and nested calls.
Storage/placement tests cover cooperative writers, external edits, unsupported
formats, backups, upgrade preservation and ordinary-user paths with spaces and
non-ASCII characters. Unix exec and Windows console/update cases have native
platform tests. Native CI runs separately on Linux, macOS and Windows; adding a
test is not evidence that an unavailable platform has already passed it.

Repository locations and any future helper crate remain independent release
decisions. There is no lockstep version requirement with extensions.
