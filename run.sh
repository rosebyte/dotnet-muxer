#!/bin/bash
# Thin native Cargo runner for Muxlet. It never invokes dotnet.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage: ./run.sh <build|test|install> [arguments]

  build    cargo build --release --locked --bins [arguments]
  test     cargo test --locked [arguments]
  install  build in release mode, then run the muxlet-install helper with the
           given arguments, for example:
             ./run.sh install
             ./run.sh install --home "$HOME/my muxlet" --backup "$HOME/dotnet.old"

Only Rust and Cargo are needed; no .NET SDK is used. Installation is per user
and never edits PATH or shell profiles. See packaging/README.md.
EOF
}

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo was not found on PATH; install Rust from https://rustup.rs" >&2
    exit 1
fi

action="${1:-}"
if [ "$#" -gt 0 ]; then
    shift
fi

case "$action" in
    build)
        exec cargo build --config "$ROOT_DIR/.cargo/config.toml" --manifest-path "$ROOT_DIR/Cargo.toml" --release --locked --bins "$@"
        ;;
    test)
        exec cargo test --config "$ROOT_DIR/.cargo/config.toml" --manifest-path "$ROOT_DIR/Cargo.toml" --locked "$@"
        ;;
    install)
        cargo build --config "$ROOT_DIR/.cargo/config.toml" --manifest-path "$ROOT_DIR/Cargo.toml" --release --locked --bins
        # The helper installs the dotnet built beside it unless --source is given.
        exec cargo run --config "$ROOT_DIR/.cargo/config.toml" --manifest-path "$ROOT_DIR/Cargo.toml" --quiet --release --locked --bin muxlet-install -- "$@"
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
