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
        cargo clean
        cargo build --release
        ;;
    *)
        usage
        exit 1
        ;;
esac
