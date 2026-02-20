# dotnet-muxer

A dispatcher that routes `dotnet` invocations to the right runtime/SDK based on context. Built primarily to make **VS Code work properly with [Arcade](https://github.com/dotnet/arcade)-based repositories** that ship their own local .NET SDK in `.dotnet/`.

## The Problem

Arcade-based .NET repositories (like [dotnet/runtime](https://github.com/dotnet/runtime)) bootstrap a private .NET SDK into a `.dotnet/` directory at the repo root. Command-line builds use wrapper scripts that set up the environment, but VS Code (and extensions like C# Dev Kit) invoke the globally installed `dotnet`, which is the wrong SDK — leading to broken IntelliSense, failed builds, and incorrect test execution.

## How It Works

`dotnet-muxer` installs a small `dotnet` binary into `~/.dotnet-muxer/` and injects a shell wrapper around the `code` command. When you open a repo with `code /path/to/repo`:

1. The wrapper detects if the repo has a `.dotnet/dotnet` (the local SDK).
2. If so, it sets `DOTNET_MUXER_TARGET` to the repo root and prepends `~/.dotnet-muxer` to `PATH`.
3. Every `dotnet` invocation now hits the muxer first, which routes to the correct binary:
   - **Repo's local SDK** (`.dotnet/dotnet`) when `DOTNET_MUXER_TARGET` is set.
   - **Testhost redirect** — when the SDK invokes `vstest.console.dll`, the muxer redirects to the repo's locally-built testhost in `artifacts/bin/testhost/`, preferring the `Release` configuration.
   - **Strict target requirement** — if `DOTNET_MUXER_TARGET` is missing/empty, or `.dotnet/dotnet` does not exist under that path, the muxer exits with an error.

## Installation

```sh
git clone https://github.com/rosebyte/dotnet-muxer.git
cd dotnet-muxer
make install
```

This builds the binary, installs it to `~/.dotnet-muxer/`, and adds a `code` wrapper to your shell profile (`~/.zshrc` / `~/.bashrc`) or PowerShell profile (Windows).

On Windows, run this from an environment where `make` is available (for example Git Bash, MSYS2, or WSL).
If `make` is not available, you can run the scripts directly from the `scripts/` folder:

```powershell
.\scripts\install.ps1
.\scripts\uninstall.ps1
```

## Runner Scripts

You can also use the root runner scripts with a single action argument:

### Unix / macOS

```sh
./run.sh install
./run.sh uninstall
./run.sh build
```

### Windows (PowerShell)

```powershell
.\run.ps1 install
.\run.ps1 uninstall
.\run.ps1 build
```

`build` runs `cargo clean` and then `cargo build --release`.

If you pass an invalid action, the runners show usage/help:

```sh
./run.sh nope
# Usage: ./run.sh <install|uninstall|build>
```

```powershell
.\run.ps1 nope
# Cannot validate argument on parameter 'Action'...
```

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (for building from source)
- `make`

## Environment Variables

| Variable | Description |
|---|---|
| `DOTNET_MUXER_TARGET` | Repo root path. Set automatically by the `code` wrapper when the repo has `.dotnet/dotnet`. |
| `DOTNET_MUXER_VERBOSE` | Set to `1` to enable logging to `~/.dotnet-muxer/log.log`. Useful for troubleshooting. |
| `DOTNET_MULTILEVEL_LOOKUP` | Set to `0` by the wrapper to prevent .NET from searching higher-level shared locations. |
| `BuildTargetFramework` | Set to `net11.0` outside windows if mono is not installed. |

## Uninstall

```sh
make uninstall
```

This removes the binary/log files and the `# >>> dotnet-muxer ... <<< dotnet-muxer` block from your shell profile (`~/.zshrc` / `~/.bashrc`) or PowerShell profile (Windows).

All install/uninstall scripts are located in `scripts/`.

## License

This project is provided as-is without a formal license. See the repository for details.
