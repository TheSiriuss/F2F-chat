#!/bin/bash
# Build script producing an optimised ASKI CHAT binary.
#
# Usage:
#   ./build.sh                  # standard release build (~30 MB)
#   ./build.sh --upx            # UPX-compressed build (~8 MB)
#
# Notes:
#   - Requires CGO-capable gcc on PATH (MinGW on Windows) for libopus + malgo.
#   - -s strips the symbol table, -w drops DWARF debug info. The runtime
#     is unaffected; only stacktraces of crashes lose function names.
#   - -trimpath removes the local build path from the binary so it can't
#     be used to identify the developer's machine.
#   - UPX compresses to ~28% of the stripped size. Startup is ~200ms slower
#     and some antivirus engines flag UPX-packed binaries. Don't ship UPX
#     versions to untrusted distribution channels.

set -e

BIN_NAME="aski-cli.exe"
if [[ "$(uname -s)" != MINGW* && "$(uname -s)" != CYGWIN* ]]; then
    BIN_NAME="aski-cli"
fi

echo "Building release binary..."
go build \
    -ldflags="-s -w" \
    -trimpath \
    -o "$BIN_NAME" \
    ./cmd/cli

size_bytes=$(stat -c%s "$BIN_NAME" 2>/dev/null || stat -f%z "$BIN_NAME")
size_mb=$(awk "BEGIN { printf \"%.1f\", $size_bytes/1024/1024 }")
echo "  $BIN_NAME: $size_mb MB"

if [[ "$1" == "--upx" ]]; then
    if ! command -v upx >/dev/null 2>&1; then
        echo "upx not found in PATH — skipping compression."
        echo "Install: https://upx.github.io/"
        exit 0
    fi
    echo "Compressing with UPX..."
    UPX_NAME="${BIN_NAME%.exe}-upx.exe"
    cp "$BIN_NAME" "$UPX_NAME"
    upx --best --lzma "$UPX_NAME" >/dev/null
    size_bytes=$(stat -c%s "$UPX_NAME" 2>/dev/null || stat -f%z "$UPX_NAME")
    size_mb=$(awk "BEGIN { printf \"%.1f\", $size_bytes/1024/1024 }")
    echo "  $UPX_NAME: $size_mb MB"
fi
