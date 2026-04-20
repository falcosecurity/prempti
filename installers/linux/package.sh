#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# package.sh — Build and package coding-agents-kit for Linux.
#
# Creates a self-contained tar.gz with all binaries, configs, and an installer.
# Usage: bash package.sh [--target aarch64-unknown-linux-gnu]
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../.." &>/dev/null && pwd)"

# Read version from workspace Cargo.toml (single source of truth).
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT_DIR/Cargo.toml" | head -1)"
FALCO_VERSION="0.43.0"
TARGET_ARCH=""

# Parse arguments.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target=*) TARGET_ARCH="${1#*=}"; shift ;;
        --target) TARGET_ARCH="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--target ARCH]"
            echo ""
            echo "Options:"
            echo "  --target ARCH   Target architecture: x86_64 or aarch64"
            echo "                  Default: native ($(uname -m))"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Detect architecture.
HOST_ARCH="$(uname -m)"
ARCH="${TARGET_ARCH:-$HOST_ARCH}"

case "$ARCH" in
    x86_64)  RUST_TARGET="x86_64-unknown-linux-gnu" ;;
    aarch64) RUST_TARGET="aarch64-unknown-linux-gnu" ;;
    *) echo "ERROR: unsupported architecture: $ARCH (expected x86_64 or aarch64)" >&2; exit 1 ;;
esac

if [[ "$ARCH" == "$HOST_ARCH" ]]; then
    # Native build — no cross-compilation flags needed.
    CARGO_TARGET_FLAG=""
    INTERCEPTOR_BIN="hooks/claude-code/target/release/claude-interceptor"
    PLUGIN_LIB="plugins/coding-agent-plugin/target/release/libcoding_agent.so"
    CTL_BIN="tools/coding-agents-kit-ctl/target/release/coding-agents-kit-ctl"
else
    # Cross-compilation.
    CARGO_TARGET_FLAG="--target $RUST_TARGET"
    INTERCEPTOR_BIN="hooks/claude-code/target/$RUST_TARGET/release/claude-interceptor"
    PLUGIN_LIB="plugins/coding-agent-plugin/target/$RUST_TARGET/release/libcoding_agent.so"
    CTL_BIN="tools/coding-agents-kit-ctl/target/$RUST_TARGET/release/coding-agents-kit-ctl"
fi

PACKAGE_NAME="coding-agents-kit-${VERSION}-linux-${ARCH}"
BUILD_DIR="${ROOT_DIR}/build/${PACKAGE_NAME}"

echo "=== Building coding-agents-kit ${VERSION} for linux/${ARCH} ==="

# Step 1: Build interceptor.
echo "Building interceptor..."
(cd "$ROOT_DIR/hooks/claude-code" && cargo build --release $CARGO_TARGET_FLAG)

# Step 2: Build plugin.
echo "Building plugin..."
(cd "$ROOT_DIR/plugins/coding-agent-plugin" && cargo build --release $CARGO_TARGET_FLAG)

# Step 2b: Build ctl tool.
echo "Building coding-agents-kit-ctl..."
(cd "$ROOT_DIR/tools/coding-agents-kit-ctl" && cargo build --release $CARGO_TARGET_FLAG)

# Step 3: Download Falco binary.
FALCO_URL="https://download.falco.org/packages/bin/${ARCH}/falco-${FALCO_VERSION}-${ARCH}.tar.gz"
FALCO_CACHE="${ROOT_DIR}/build/falco-${FALCO_VERSION}-${ARCH}.tar.gz"

if [[ ! -f "$FALCO_CACHE" ]]; then
    echo "Downloading Falco ${FALCO_VERSION} for ${ARCH}..."
    mkdir -p "$(dirname "$FALCO_CACHE")"
    curl -fSL -o "$FALCO_CACHE" "$FALCO_URL"
else
    echo "Using cached Falco download: $FALCO_CACHE"
fi

# Step 4: Assemble package directory.
echo "Assembling package..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{bin,share,config,rules/default,rules/user,systemd}

# Binaries.
cp "$ROOT_DIR/$INTERCEPTOR_BIN" "$BUILD_DIR/bin/claude-interceptor"
cp "$ROOT_DIR/$CTL_BIN" "$BUILD_DIR/bin/coding-agents-kit-ctl"
cp "$ROOT_DIR/$PLUGIN_LIB" "$BUILD_DIR/share/libcoding_agent.so"

# Extract only falco binary from the tarball.
tar xzf "$FALCO_CACHE" --strip-components=3 -C "$BUILD_DIR/bin/" \
    "falco-${FALCO_VERSION}-${ARCH}/usr/bin/falco"

# Config files.
cp "$ROOT_DIR/configs/falco.yaml" "$BUILD_DIR/config/"
cp "$ROOT_DIR/configs/falco.coding_agents_plugin.yaml" "$BUILD_DIR/config/"

# Rules.
cp "$ROOT_DIR/rules/default/coding_agents_rules.yaml" "$BUILD_DIR/rules/default/"
cp "$ROOT_DIR/rules/seen.yaml" "$BUILD_DIR/rules/"

# Systemd service template.
cp "$SCRIPT_DIR/coding-agents-kit.service" "$BUILD_DIR/systemd/"

# Installer script.
cp "$SCRIPT_DIR/install.sh" "$BUILD_DIR/"
chmod +x "$BUILD_DIR/install.sh"

# Step 5: Create tar.gz.
echo "Creating archive..."
(cd "$ROOT_DIR/build" && tar czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME")

echo ""
echo "=== Package created ==="
echo "  ${ROOT_DIR}/build/${PACKAGE_NAME}.tar.gz"
echo ""
echo "To install:"
echo "  tar xzf ${PACKAGE_NAME}.tar.gz"
echo "  cd ${PACKAGE_NAME}"
echo "  bash install.sh"
