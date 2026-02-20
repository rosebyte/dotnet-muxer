param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("install", "uninstall", "build")]
    [string]$Action
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

switch ($Action) {
    "install" {
        & (Join-Path $Root "scripts/install.ps1")
        exit $LASTEXITCODE
    }
    "uninstall" {
        & (Join-Path $Root "scripts/uninstall.ps1")
        exit $LASTEXITCODE
    }
    "build" {
        cargo clean
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        cargo build --release
        exit $LASTEXITCODE
    }
}
