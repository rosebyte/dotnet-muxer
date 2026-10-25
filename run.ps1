# Thin native Cargo runner for Muxlet. It never invokes dotnet.
#
# Arguments are read from $args instead of a param() block so that cargo and
# installer options such as -p, --home or --backup pass through untouched.
$ErrorActionPreference = "Stop"

function Show-Usage {
    @'
Usage: .\run.ps1 <build|test|install> [arguments]

  build    cargo build --release --locked --bins [arguments]
  test     cargo test --locked [arguments]
  install  build in release mode, then run the muxlet-install helper with the
           given arguments, for example:
             .\run.ps1 install
             .\run.ps1 install --home "$HOME\my muxlet" --backup "$HOME\dotnet.old"

Only Rust and Cargo are needed; no .NET SDK is used. Installation is per user
and never edits PATH or the PowerShell profile. A running dotnet.exe cannot be
replaced; see packaging\README.md for the --wait-pid mechanism.

PowerShell consumes a bare -- before this script sees it. To pass cargo's
separator, quote it: .\run.ps1 test '--' --nocapture
'@ | Write-Host
}

function Invoke-Cargo {
    param([string[]]$CargoArguments)

    & cargo @CargoArguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

$action = if ($args.Count -gt 0) { [string]$args[0] } else { "" }
[string[]]$rest = @($args | Select-Object -Skip 1)

if ($action -in @("-h", "--help", "help")) {
    Show-Usage
    exit 0
}
if ($action -notin @("build", "test", "install")) {
    Show-Usage
    exit 2
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "cargo was not found on PATH; install Rust from https://rustup.rs"
    exit 1
}

$manifest = Join-Path $PSScriptRoot "Cargo.toml"
$cargoConfig = Join-Path $PSScriptRoot ".cargo/config.toml"

switch ($action) {
    "build" {
        Invoke-Cargo (@("build", "--config", $cargoConfig, "--manifest-path", $manifest, "--release", "--locked", "--bins") + $rest)
    }
    "test" {
        Invoke-Cargo (@("test", "--config", $cargoConfig, "--manifest-path", $manifest, "--locked") + $rest)
    }
    "install" {
        Invoke-Cargo @("build", "--config", $cargoConfig, "--manifest-path", $manifest, "--release", "--locked", "--bins")
        # The helper installs the dotnet.exe built beside it unless --source is given.
        Invoke-Cargo (@("run", "--config", $cargoConfig, "--manifest-path", $manifest, "--quiet", "--release", "--locked", "--bin", "muxlet-install", "--") + $rest)
    }
}
