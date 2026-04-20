#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# package.sh — Build and package coding-agents-kit for macOS.
#
# Creates a self-contained tar.gz with all binaries, configs, and an installer.
# Supports: native builds, cross-compilation, and universal (fat) binaries.
#
# Usage: bash package.sh [--target aarch64|x86_64|universal]
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
            echo "  --target ARCH   Target: aarch64, x86_64, or universal"
            echo "                  Default: native ($(uname -m))"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Detect architecture.
HOST_ARCH="$(uname -m)"
# Normalize: Apple reports arm64, we use aarch64.
[[ "$HOST_ARCH" == "arm64" ]] && HOST_ARCH="aarch64"
ARCH="${TARGET_ARCH:-$HOST_ARCH}"

# ---------------------------------------------------------------------------
# Universal binary: build both archs + lipo
# ---------------------------------------------------------------------------

if [[ "$ARCH" == "universal" ]]; then
    echo "=== Building universal macOS package ==="

    # Build both arch-specific packages first.
    echo ""
    echo "--- Building aarch64 components ---"
    bash "$SCRIPT_DIR/package.sh" --target aarch64
    echo ""
    echo "--- Building x86_64 components ---"
    bash "$SCRIPT_DIR/package.sh" --target x86_64

    PACKAGE_NAME="coding-agents-kit-${VERSION}-darwin-universal"
    BUILD_DIR="${ROOT_DIR}/build/${PACKAGE_NAME}"
    ARM_DIR="${ROOT_DIR}/build/coding-agents-kit-${VERSION}-darwin-aarch64"
    X86_DIR="${ROOT_DIR}/build/coding-agents-kit-${VERSION}-darwin-x86_64"

    echo ""
    echo "--- Creating universal binaries via lipo ---"
    rm -rf "$BUILD_DIR"
    # Start from the aarch64 package (configs, rules, scripts are arch-independent).
    cp -R "$ARM_DIR" "$BUILD_DIR"

    # Replace binaries with universal (fat) versions.
    for bin in bin/falco bin/claude-interceptor bin/coding-agents-kit-ctl; do
        echo "  lipo: $bin"
        lipo -create "$ARM_DIR/$bin" "$X86_DIR/$bin" -output "$BUILD_DIR/$bin"
    done
    echo "  lipo: share/libcoding_agent.dylib"
    lipo -create "$ARM_DIR/share/libcoding_agent.dylib" \
                 "$X86_DIR/share/libcoding_agent.dylib" \
                 -output "$BUILD_DIR/share/libcoding_agent.dylib"

    # Create tar.gz.
    echo "Creating tar.gz..."
    (cd "$ROOT_DIR/build" && tar czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME")

    # Create .pkg (reuse the single-arch pkg build logic via a recursive call
    # wouldn't work since BUILD_DIR is already assembled). Build it inline.
    echo "Creating .pkg..."
    PKG_DIR="${ROOT_DIR}/build/pkg-work-universal"
    PKG_ROOT="${PKG_DIR}/root/.coding-agents-kit"
    PKG_SCRIPTS="${PKG_DIR}/scripts"
    PKG_RESOURCES="${PKG_DIR}/resources"
    COMPONENT_PKG="${PKG_DIR}/component.pkg"
    PRODUCT_PKG="${ROOT_DIR}/build/${PACKAGE_NAME}.pkg"
    rm -rf "$PKG_DIR"
    mkdir -p "$PKG_ROOT"
    cp -R "$BUILD_DIR/bin" "$BUILD_DIR/share" "$BUILD_DIR/config" "$BUILD_DIR/rules" "$BUILD_DIR/launchd" "$PKG_ROOT/"
    mkdir -p "$PKG_ROOT/log"
    mkdir -p "$PKG_SCRIPTS"
    cp "$SCRIPT_DIR/pkg-scripts/preinstall" "$PKG_SCRIPTS/"
    cp "$SCRIPT_DIR/pkg-scripts/postinstall" "$PKG_SCRIPTS/"
    chmod +x "$PKG_SCRIPTS/preinstall" "$PKG_SCRIPTS/postinstall"
    pkgbuild --root "$PKG_DIR/root" --install-location "." --scripts "$PKG_SCRIPTS" \
        --identifier "dev.falcosecurity.coding-agents-kit" --version "$VERSION" \
        "$COMPONENT_PKG" > /dev/null
    mkdir -p "$PKG_RESOURCES"
    cp "$SCRIPT_DIR/pkg-resources/welcome.html" "$PKG_RESOURCES/"
    cp "$SCRIPT_DIR/pkg-resources/conclusion.html" "$PKG_RESOURCES/"
    sed "s/@VERSION@/$VERSION/g" "$SCRIPT_DIR/distribution.xml" > "$PKG_DIR/distribution.xml"
    productbuild --distribution "$PKG_DIR/distribution.xml" --package-path "$PKG_DIR" \
        --resources "$PKG_RESOURCES" "$PRODUCT_PKG" > /dev/null
    rm -rf "$PKG_DIR"

    echo ""
    echo "=== Universal package created ==="
    echo "  ${ROOT_DIR}/build/${PACKAGE_NAME}.tar.gz"
    echo "  ${PRODUCT_PKG}"
    echo ""
    echo "  Architectures:"
    file "$BUILD_DIR/bin/falco"
    echo ""
    echo "To install:"
    echo "  open ${PACKAGE_NAME}.pkg"
    exit 0
fi

# ---------------------------------------------------------------------------
# Single-arch build
# ---------------------------------------------------------------------------

case "$ARCH" in
    aarch64) RUST_TARGET="aarch64-apple-darwin" ;;
    x86_64)  RUST_TARGET="x86_64-apple-darwin" ;;
    *) echo "ERROR: unsupported architecture: $ARCH (expected aarch64, x86_64, or universal)" >&2; exit 1 ;;
esac

# Set up cross-compilation if target != host.
if [[ "$ARCH" != "$HOST_ARCH" ]]; then
    CARGO_TARGET_FLAG="--target $RUST_TARGET"
    INTERCEPTOR_BIN="hooks/claude-code/target/$RUST_TARGET/release/claude-interceptor"
    PLUGIN_LIB="plugins/coding-agent-plugin/target/$RUST_TARGET/release/libcoding_agent.dylib"
    CTL_BIN="tools/coding-agents-kit-ctl/target/$RUST_TARGET/release/coding-agents-kit-ctl"
    # Ensure Rust target is installed.
    rustup target add "$RUST_TARGET" 2>/dev/null || true
else
    CARGO_TARGET_FLAG=""
    INTERCEPTOR_BIN="hooks/claude-code/target/release/claude-interceptor"
    PLUGIN_LIB="plugins/coding-agent-plugin/target/release/libcoding_agent.dylib"
    CTL_BIN="tools/coding-agents-kit-ctl/target/release/coding-agents-kit-ctl"
fi

PACKAGE_NAME="coding-agents-kit-${VERSION}-darwin-${ARCH}"
BUILD_DIR="${ROOT_DIR}/build/${PACKAGE_NAME}"

echo "=== Building coding-agents-kit ${VERSION} for darwin/${ARCH} ==="

# Step 1: Build interceptor.
echo "Building interceptor..."
(cd "$ROOT_DIR/hooks/claude-code" && cargo build --release $CARGO_TARGET_FLAG)

# Step 2: Build plugin.
echo "Building plugin..."
(cd "$ROOT_DIR/plugins/coding-agent-plugin" && cargo build --release $CARGO_TARGET_FLAG)

# Step 2b: Build ctl tool.
echo "Building coding-agents-kit-ctl..."
(cd "$ROOT_DIR/tools/coding-agents-kit-ctl" && cargo build --release $CARGO_TARGET_FLAG)

# Step 3: Build Falco from source.
echo "Building Falco..."
bash "$SCRIPT_DIR/build-falco.sh" --arch "$ARCH"
FALCO_BIN="${ROOT_DIR}/build/falco-${FALCO_VERSION}-darwin-${ARCH}/falco"
if [[ ! -x "$FALCO_BIN" ]]; then
    echo "ERROR: Falco binary not found at $FALCO_BIN" >&2
    exit 1
fi

# Step 4: Assemble package directory.
echo "Assembling package..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{bin,share,config,rules/default,rules/user,launchd}

# Binaries.
cp "$ROOT_DIR/$INTERCEPTOR_BIN" "$BUILD_DIR/bin/claude-interceptor"
cp "$ROOT_DIR/$CTL_BIN" "$BUILD_DIR/bin/coding-agents-kit-ctl"
cp "$ROOT_DIR/$PLUGIN_LIB" "$BUILD_DIR/share/libcoding_agent.dylib"
cp "$FALCO_BIN" "$BUILD_DIR/bin/falco"

# Config files (with .so -> .dylib transform for macOS).
cp "$ROOT_DIR/configs/falco.yaml" "$BUILD_DIR/config/"
sed 's/libcoding_agent\.so/libcoding_agent.dylib/g' \
    "$ROOT_DIR/configs/falco.coding_agents_plugin.yaml" \
    > "$BUILD_DIR/config/falco.coding_agents_plugin.yaml"

# Rules.
cp "$ROOT_DIR/rules/default/coding_agents_rules.yaml" "$BUILD_DIR/rules/default/"
cp "$ROOT_DIR/rules/seen.yaml" "$BUILD_DIR/rules/"

# launchd service template and launcher.
cp "$SCRIPT_DIR/dev.falcosecurity.coding-agents-kit.plist" "$BUILD_DIR/launchd/"
cp "$SCRIPT_DIR/coding-agents-kit-launcher.sh" "$BUILD_DIR/launchd/"

# Installer script.
cp "$SCRIPT_DIR/install.sh" "$BUILD_DIR/"
chmod +x "$BUILD_DIR/install.sh"

# Step 5: Create tar.gz.
echo "Creating tar.gz..."
(cd "$ROOT_DIR/build" && tar czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME")

# Step 6: Create .pkg installer.
echo "Creating .pkg..."
PKG_DIR="${ROOT_DIR}/build/pkg-work-${ARCH}"
PKG_ROOT="${PKG_DIR}/root/.coding-agents-kit"
PKG_SCRIPTS="${PKG_DIR}/scripts"
PKG_RESOURCES="${PKG_DIR}/resources"
COMPONENT_PKG="${PKG_DIR}/component.pkg"
PRODUCT_PKG="${ROOT_DIR}/build/${PACKAGE_NAME}.pkg"

rm -rf "$PKG_DIR"

# Lay out files as they will be installed under ~/.coding-agents-kit/
mkdir -p "$PKG_ROOT"/{bin,share,config,rules/default,rules/user,launchd,log}
cp "$BUILD_DIR/bin/falco" "$PKG_ROOT/bin/"
cp "$BUILD_DIR/bin/claude-interceptor" "$PKG_ROOT/bin/"
cp "$BUILD_DIR/bin/coding-agents-kit-ctl" "$PKG_ROOT/bin/"
cp "$BUILD_DIR/share/libcoding_agent.dylib" "$PKG_ROOT/share/"
cp "$BUILD_DIR/config/falco.yaml" "$PKG_ROOT/config/"
cp "$BUILD_DIR/config/falco.coding_agents_plugin.yaml" "$PKG_ROOT/config/"
cp "$BUILD_DIR/rules/default/coding_agents_rules.yaml" "$PKG_ROOT/rules/default/"
cp "$BUILD_DIR/rules/seen.yaml" "$PKG_ROOT/rules/"
cp "$BUILD_DIR/launchd/dev.falcosecurity.coding-agents-kit.plist" "$PKG_ROOT/launchd/"
cp "$BUILD_DIR/launchd/coding-agents-kit-launcher.sh" "$PKG_ROOT/launchd/"

# Pre/post install scripts.
mkdir -p "$PKG_SCRIPTS"
cp "$SCRIPT_DIR/pkg-scripts/preinstall" "$PKG_SCRIPTS/"
cp "$SCRIPT_DIR/pkg-scripts/postinstall" "$PKG_SCRIPTS/"
chmod +x "$PKG_SCRIPTS/preinstall" "$PKG_SCRIPTS/postinstall"

# Build component package. Installs to .coding-agents-kit/ relative to
# the user's home directory (user-domain install via distribution.xml).
pkgbuild --root "$PKG_DIR/root" \
    --install-location "." \
    --scripts "$PKG_SCRIPTS" \
    --identifier "dev.falcosecurity.coding-agents-kit" \
    --version "$VERSION" \
    "$COMPONENT_PKG" \
    > /dev/null

# Installer resources (welcome/conclusion pages).
mkdir -p "$PKG_RESOURCES"
cp "$SCRIPT_DIR/pkg-resources/welcome.html" "$PKG_RESOURCES/"
cp "$SCRIPT_DIR/pkg-resources/conclusion.html" "$PKG_RESOURCES/"

# Distribution XML (enables user-home-directory installation).
sed "s/@VERSION@/$VERSION/g" "$SCRIPT_DIR/distribution.xml" \
    > "$PKG_DIR/distribution.xml"

# Build product archive (the final .pkg with installer wizard).
productbuild --distribution "$PKG_DIR/distribution.xml" \
    --package-path "$PKG_DIR" \
    --resources "$PKG_RESOURCES" \
    "$PRODUCT_PKG" \
    > /dev/null

rm -rf "$PKG_DIR"

echo ""
echo "=== Package created ==="
echo "  ${ROOT_DIR}/build/${PACKAGE_NAME}.tar.gz"
echo "  ${PRODUCT_PKG}"
echo ""
echo "To install:"
echo "  open ${PACKAGE_NAME}.pkg    # macOS Installer wizard"
echo "  # or: tar xzf ${PACKAGE_NAME}.tar.gz && cd ${PACKAGE_NAME} && bash install.sh"
