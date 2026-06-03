#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build-falco.sh — Build Falco from source for macOS with http_output support.
#
# Falco does not ship pre-built macOS binaries, so we build from source. Since
# Falco 0.44 the curl-based http_output channel is a first-class, OS-agnostic
# build option (BUILD_HTTP_OUTPUT), so no source patch is needed: we keep
# MINIMAL_BUILD=ON (no gRPC/webserver/metrics) and opt http_output back in with
# -DBUILD_HTTP_OUTPUT=ON (it defaults OFF under MINIMAL_BUILD). The broker needs
# http_output to receive Falco alerts on localhost.
#
# Usage: bash build-falco.sh [--version 0.44.0] [--output-dir DIR] [--arch ARCH] [--force]
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../.." &>/dev/null && pwd)"

FALCO_VERSION="0.44.0"
FALCO_TAG="0.44.0"
OUTPUT_DIR=""
FORCE=false
TARGET_ARCH=""

# Parse arguments.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version=*) FALCO_VERSION="${1#*=}"; FALCO_TAG="$FALCO_VERSION"; shift ;;
        --version)   FALCO_VERSION="$2"; FALCO_TAG="$FALCO_VERSION"; shift 2 ;;
        --output-dir=*) OUTPUT_DIR="${1#*=}"; shift ;;
        --output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
        --arch=*) TARGET_ARCH="${1#*=}"; shift ;;
        --arch)   TARGET_ARCH="$2"; shift 2 ;;
        --force) FORCE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--version VERSION] [--output-dir DIR] [--arch ARCH] [--force]"
            echo ""
            echo "Options:"
            echo "  --version VERSION   Falco version/tag to build (default: 0.44.0)"
            echo "  --output-dir DIR    Directory for the built falco binary"
            echo "                      Default: ROOT/build/falco-VERSION-darwin-ARCH/"
            echo "  --arch ARCH         Target architecture: aarch64 or x86_64"
            echo "                      Default: native ($(uname -m))"
            echo "  --force             Rebuild even if a cached binary exists"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

HOST_ARCH="$(uname -m)"
# Normalize: Apple reports arm64, we use aarch64.
[[ "$HOST_ARCH" == "arm64" ]] && HOST_ARCH="aarch64"
ARCH="${TARGET_ARCH:-$HOST_ARCH}"

CROSS_COMPILING=false
if [[ "$ARCH" != "$HOST_ARCH" ]]; then
    CROSS_COMPILING=true
    # Cross-compilation requires Rosetta + x86_64 Homebrew.
    # Falco's bundled CMake ExternalProjects don't respect CMAKE_OSX_ARCHITECTURES,
    # so we run the entire build under arch(1) with x86_64 tools.
    if [[ "$ARCH" == "x86_64" && "$HOST_ARCH" == "aarch64" ]]; then
        X86_CMAKE="/usr/local/bin/cmake"
        if [[ ! -x "$X86_CMAKE" ]]; then
            echo "ERROR: x86_64 cmake not found at $X86_CMAKE" >&2
            echo "  Universal builds require x86_64 Homebrew at /usr/local." >&2
            echo "  Install Rosetta:    softwareupdate --install-rosetta" >&2
            echo "  Install x86_64 Homebrew:" >&2
            echo "    arch -x86_64 /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"" >&2
            echo "  Install x86_64 tools:" >&2
            echo "    arch -x86_64 /usr/local/bin/brew install cmake openssl@3" >&2
            exit 1
        fi
    else
        echo "ERROR: unsupported cross-compilation: $HOST_ARCH → $ARCH" >&2
        exit 1
    fi
fi

SRC_DIR="${ROOT_DIR}/build/falco-src-${FALCO_VERSION}"
if $CROSS_COMPILING; then
    BUILD_DIR="${SRC_DIR}/build-${ARCH}"
else
    BUILD_DIR="${SRC_DIR}/build"
fi
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${ROOT_DIR}/build/falco-${FALCO_VERSION}-darwin-${ARCH}"

# Check if already built (skip if --force).
if [[ -x "$OUTPUT_DIR/falco" ]] && ! $FORCE; then
    echo "Using cached Falco build: $OUTPUT_DIR/falco"
    "$OUTPUT_DIR/falco" --version 2>/dev/null || file "$OUTPUT_DIR/falco"
    exit 0
fi

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

for cmd in cmake git make; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not found." >&2
        echo "  Install Xcode Command Line Tools: xcode-select --install" >&2
        echo "  Install cmake: brew install cmake" >&2
        exit 1
    fi
done

CMAKE_VERSION=$(cmake --version | head -1 | grep -oE '[0-9]+\.[0-9]+')
CMAKE_MAJOR=$(echo "$CMAKE_VERSION" | cut -d. -f1)
CMAKE_MINOR=$(echo "$CMAKE_VERSION" | cut -d. -f2)
if (( CMAKE_MAJOR < 3 || (CMAKE_MAJOR == 3 && CMAKE_MINOR < 24) )); then
    echo "ERROR: cmake >= 3.24 required (found $CMAKE_VERSION)." >&2
    echo "  brew install cmake" >&2
    exit 1
fi

# OpenSSL is required (macOS ships LibreSSL, not OpenSSL).
# For cross-compilation, use x86_64 Homebrew at /usr/local.
OPENSSL_ROOT=""
if $CROSS_COMPILING; then
    OPENSSL_CANDIDATES="/usr/local/opt/openssl@3 /usr/local/opt/openssl"
else
    OPENSSL_CANDIDATES="/opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3 /opt/homebrew/opt/openssl /usr/local/opt/openssl"
fi
for candidate in $OPENSSL_CANDIDATES; do
    if [[ -d "$candidate" ]]; then
        OPENSSL_ROOT="$candidate"
        break
    fi
done
if [[ -z "$OPENSSL_ROOT" ]]; then
    echo "ERROR: OpenSSL not found. Install via Homebrew:" >&2
    if $CROSS_COMPILING; then
        echo "  arch -x86_64 /usr/local/bin/brew install openssl@3" >&2
    else
        echo "  brew install openssl@3" >&2
    fi
    exit 1
fi
echo "Using OpenSSL: $OPENSSL_ROOT"

# ---------------------------------------------------------------------------
# Clone Falco
# ---------------------------------------------------------------------------

if [[ ! -d "$SRC_DIR/.git" ]]; then
    echo "=== Cloning Falco ${FALCO_TAG} ==="
    git clone --depth 1 --branch "$FALCO_TAG" \
        https://github.com/falcosecurity/falco.git "$SRC_DIR"
else
    echo "Using cached Falco source: $SRC_DIR"
fi

# ---------------------------------------------------------------------------
# http_output: native since Falco 0.44 (no patch needed)
# ---------------------------------------------------------------------------
#
# Falco 0.43 gated curl-based http_output behind `NOT APPLE` and compiled
# outputs_http.cpp only under `Linux AND NOT MINIMAL_BUILD`, so Prempti carried
# a patch to re-enable it. Falco 0.44 reworked http_output into a first-class,
# OS-agnostic build option (BUILD_HTTP_OUTPUT, falcosecurity/falco#3827) that
# defines HAS_HTTP_OUTPUT and pulls in curl. It defaults OFF under MINIMAL_BUILD,
# so we just opt in with -DBUILD_HTTP_OUTPUT=ON below — no source patch required.

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

# Map arch to CMake OSX architecture name.
case "$ARCH" in
    aarch64) CMAKE_OSX_ARCH="arm64" ;;
    x86_64)  CMAKE_OSX_ARCH="x86_64" ;;
esac

echo "=== Configuring Falco (MINIMAL_BUILD + http_output) for $ARCH ==="

# Common cmake flags for all builds.
CMAKE_COMMON_FLAGS=(
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_OSX_ARCHITECTURES="$CMAKE_OSX_ARCH"
    -DMINIMAL_BUILD=ON
    -DBUILD_HTTP_OUTPUT=ON
    -DUSE_BUNDLED_DEPS=ON
    -DUSE_BUNDLED_OPENSSL=OFF
    -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT"
    -DUSE_BUNDLED_CURL=OFF
    -DUSE_BUNDLED_ZLIB=OFF
    -DBUILD_FALCO_MODERN_BPF=OFF
    -DBUILD_FALCO_UNIT_TESTS=OFF
    -DBUILD_WARNINGS_AS_ERRORS=OFF
    -DFALCO_VERSION="$FALCO_VERSION"
)

NPROC=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)

if $CROSS_COMPILING; then
    # Run under Rosetta with x86_64 cmake + explicit arch flags.
    # arch -x86_64 makes autotools scripts (OpenSSL ./config) detect x86_64
    # via uname -m. CFLAGS/CXXFLAGS force the universal Apple compiler to
    # produce x86_64 code (without them it picks the native arm64 slice).
    export CFLAGS="-arch $CMAKE_OSX_ARCH"
    export CXXFLAGS="-arch $CMAKE_OSX_ARCH"
    export LDFLAGS="-arch $CMAKE_OSX_ARCH"
    arch -x86_64 "$X86_CMAKE" -B "$BUILD_DIR" -S "$SRC_DIR" "${CMAKE_COMMON_FLAGS[@]}"
    echo "=== Building Falco (under Rosetta) ==="
    arch -x86_64 "$X86_CMAKE" --build "$BUILD_DIR" --target falco -j"$NPROC"
else
    cmake -B "$BUILD_DIR" -S "$SRC_DIR" "${CMAKE_COMMON_FLAGS[@]}"
    echo "=== Building Falco ==="
    cmake --build "$BUILD_DIR" --target falco -j"$NPROC"
fi

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

mkdir -p "$OUTPUT_DIR"
cp "$BUILD_DIR/userspace/falco/falco" "$OUTPUT_DIR/falco"
chmod 755 "$OUTPUT_DIR/falco"

echo ""
echo "=== Falco built successfully ==="
echo "  Binary: $OUTPUT_DIR/falco"
file "$OUTPUT_DIR/falco"
# Run --version (works natively or under Rosetta).
"$OUTPUT_DIR/falco" --version 2>/dev/null || true
