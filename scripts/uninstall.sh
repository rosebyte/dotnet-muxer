#!/bin/bash
set -e

MUXER_DIR="$HOME/.dotnet-muxer"

rm -f "$MUXER_DIR/dotnet" "$MUXER_DIR/dotnet.exe" "$MUXER_DIR/log.log"

for RC in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if [ -f "$RC" ]; then
        sed -i.bak '/# >>> dotnet-muxer/,/# <<< dotnet-muxer/d' "$RC" && rm -f "$RC.bak"
    fi
done

echo "Uninstalled dotnet-muxer from $MUXER_DIR and removed shell hooks from .zshrc/.bashrc"
