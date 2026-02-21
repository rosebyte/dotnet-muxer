# dotnet-muxer

A .NET NativeAOT dispatcher that routes `dotnet` invocations to the right runtime/SDK based on context. Built primarily to make **VS Code work properly with [Arcade](https://github.com/dotnet/arcade)-based repositories** that ship their own local .NET SDK in `.dotnet/`.

## The Problem

Arcade-based .NET repositories (like [dotnet/runtime](https://github.com/dotnet/runtime)) bootstrap a private .NET SDK into a `.dotnet/` directory at the repo root. Command-line builds use wrapper scripts that set up the environment, but VS Code (and extensions like C# Dev Kit) invoke the globally installed `dotnet`, which is the wrong SDK — leading to broken IntelliSense, failed builds, and incorrect test execution.

## How It Works

`dotnet-muxer` installs a small `dotnet` binary into `~/.dotnet-muxer/` and injects a shell wrapper around the `code` command. When you open a repo with `code /path/to/repo`:

**Important:** This flow is activated when VS Code is started from the command line through `code`, for example:

```sh
code .
code <path-to-arcade-repo>
```

That means you should launch VS Code from a terminal in the Arcade repo, or pass the Arcade repo path to `code`.

1. The wrapper detects if the repo has a `.dotnet/dotnet` (the local SDK).
2. If so, it sets `DOTNET_MUXER_TARGET` to the local SDK executable path (`<repo>/.dotnet/dotnet`) and prepends `~/.dotnet-muxer` to `PATH`.
3. Every `dotnet` invocation now hits the muxer first, which routes to the correct binary:
   - **Configured SDK executable** — the path in `DOTNET_MUXER_TARGET`.
   - **Testhost redirect** — when the SDK invokes `vstest.console.dll`, the muxer redirects to the repo's locally-built testhost in `artifacts/bin/testhost/`, preferring the `Release` configuration.
   - **Strict target requirement** — if `DOTNET_MUXER_TARGET` is missing/empty, or the target executable path does not exist, the muxer exits with an error.

## Installation

```sh
git clone https://github.com/rosebyte/dotnet-muxer.git
cd dotnet-muxer
./run.sh install
```

This publishes the NativeAOT binary, installs it to `~/.dotnet-muxer/`, and adds a `code` wrapper to your shell profile (`~/.zshrc` / `~/.bashrc`) or PowerShell profile (Windows).

On Windows (PowerShell):

```powershell
.\run.ps1 install
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

`build` publishes the .NET NativeAOT project for the current platform RID and automatically targets the latest installed `netX.0` SDK framework.

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

- [.NET SDK](https://dotnet.microsoft.com/download)

## Environment Variables

| Variable | Description |
|---|---|
| `DOTNET_MUXER_TARGET` | Full path to the target `dotnet` executable. Set automatically by the `code` wrapper to `<repo>/.dotnet/dotnet` (or `.exe` on Windows). |
| `DOTNET_MUXER_VERBOSE` | Set to `1` to enable logging to `~/.dotnet-muxer/log.log`. Useful for troubleshooting. |
| `DOTNET_MULTILEVEL_LOOKUP` | Set to `0` by the wrapper to prevent .NET from searching higher-level shared locations. |
| `BuildTargetFramework` | Set to `net11.0` outside windows if mono is not installed. |

## Uninstall

```sh
./run.sh uninstall
```

```powershell
.\run.ps1 uninstall
```

This removes the binary/log files and the `# >>> dotnet-muxer ... <<< dotnet-muxer` block from your shell profile (`~/.zshrc` / `~/.bashrc`) or PowerShell profile (Windows).

## License

This project is provided as-is without a formal license. See the repository for details.

## Development

Made using the GPT-5.3-Codex and Claude Opus 4.6 models to explore and compare them. Both models produced acceptable results. However, once we started to prioritise performance, manual interventions were still required, as both showed a reduced signal-to-noise ratio when taken outside their comfortable "anything goes" happy path.
