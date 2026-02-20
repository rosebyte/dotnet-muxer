#!/bin/bash
set -euo pipefail

usage() {
    echo "Usage: ./run.sh <install|uninstall|build>"
}

if [ "$#" -ne 1 ]; then
    usage
    exit 1
fi

case "$1" in
    install)
        bash "$(dirname "$0")/scripts/install.sh"
        ;;
    uninstall)
        bash "$(dirname "$0")/scripts/uninstall.sh"
        ;;
    build)
        cargo clean --manifest-path "$(dirname "$0")/app/Cargo.toml"
        cargo build --release --manifest-path "$(dirname "$0")/app/Cargo.toml"
        ;;
    *)
        usage
        exit 1
        ;;
esac
