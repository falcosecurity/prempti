#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# install.sh — Install coding-agents-kit on macOS.
#
# Copies binaries, configs, and rules to the install prefix, sets up a
# launchd user agent, and registers the Claude Code hook.
#
# Usage: bash install.sh [--prefix=PATH] [--dry-run] [--help]
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${HOME}/.coding-agents-kit"
DRY_RUN=false
HAS_DIALOG=false

# Parse arguments.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix=*) PREFIX="${1#*=}"; shift ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--prefix=PATH] [--dry-run]"
            echo ""
            echo "Options:"
            echo "  --prefix=PATH   Install directory (default: ~/.coding-agents-kit)"
            echo "  --dry-run       Print what would be done without making changes"
            echo ""
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

command -v dialog &>/dev/null && HAS_DIALOG=true

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info() { echo "  [INFO] $*"; }
warn() { echo "  [WARN] $*" >&2; }
err()  { echo "  [ERROR] $*" >&2; exit 1; }

run() {
    if $DRY_RUN; then
        echo "  [DRY-RUN] $*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

# Verify we are on macOS.
if [[ "$(uname -s)" != "Darwin" ]]; then
    err "This installer is for macOS only (detected: $(uname -s)). Use the Linux installer instead."
fi

# Verify architecture matches the package.
# `file` reports all slices for universal binaries, e.g.
#   "Mach-O universal binary ... [arm64:...] [x86_64:...]"
# so we collect every arch and accept the package as long as the host arch is
# one of them. Without this, universal tarballs would be rejected on Intel
# Macs (the first arch reported by `file` is arm64).
CURRENT_ARCH="$(uname -m)"
[[ "$CURRENT_ARCH" == "arm64" ]] && CURRENT_ARCH="aarch64"
PACKAGE_ARCHS="$(file "$SCRIPT_DIR/bin/falco" 2>/dev/null | grep -oE 'arm64|x86_64' | sort -u | tr '\n' ' ' || true)"
# Normalize arm64 → aarch64 in the arch list.
PACKAGE_ARCHS="${PACKAGE_ARCHS//arm64/aarch64}"
if [[ -n "$PACKAGE_ARCHS" ]]; then
    MATCH=false
    for a in $PACKAGE_ARCHS; do
        [[ "$a" == "$CURRENT_ARCH" ]] && MATCH=true && break
    done
    if ! $MATCH; then
        err "Architecture mismatch: package is for ${PACKAGE_ARCHS% } but this machine is $CURRENT_ARCH."
    fi
fi

# Verify we have the package contents.
for f in bin/falco bin/claude-interceptor bin/coding-agents-kit-ctl \
         share/libcoding_agent.dylib \
         config/falco.yaml config/falco.coding_agents_plugin.yaml \
         rules/default/coding_agents_rules.yaml \
         rules/seen.yaml launchd/dev.falcosecurity.coding-agents-kit.plist \
         launchd/coding-agents-kit-launcher.sh; do
    [[ -f "$SCRIPT_DIR/$f" ]] || err "Missing package file: $f (are you running from the extracted package?)"
done

# ---------------------------------------------------------------------------
# Interactive confirmation (dialog)
# ---------------------------------------------------------------------------

if $HAS_DIALOG && ! $DRY_RUN && [[ -t 0 ]]; then
    # Confirm install prefix.
    DIALOG_PREFIX=$(dialog --stdout --inputbox \
        "Install coding-agents-kit to:" 8 60 "$PREFIX") || true
    [[ -n "$DIALOG_PREFIX" ]] && PREFIX="$DIALOG_PREFIX"

    # Warn about existing installation.
    if [[ -d "$PREFIX" ]]; then
        dialog --stdout --yesno \
            "Directory $PREFIX already exists.\n\nExisting user rules will be preserved.\nOther files will be overwritten.\n\nContinue?" 10 60 \
            || exit 0
    fi

    clear
fi

echo "=== Installing coding-agents-kit ==="
echo "  Prefix: $PREFIX"
$DRY_RUN && echo "  Mode: dry-run (no changes will be made)"
echo ""

# ---------------------------------------------------------------------------
# Create directory structure
# ---------------------------------------------------------------------------

info "Creating directories..."
run mkdir -p "$PREFIX"/{bin,config,run,share,log}
run mkdir -p "$PREFIX"/rules/default
# Preserve existing user rules directory.
if [[ ! -d "$PREFIX/rules/user" ]]; then
    run mkdir -p "$PREFIX/rules/user"
fi

# ---------------------------------------------------------------------------
# Copy files
# ---------------------------------------------------------------------------

info "Installing binaries..."
run install -m 755 "$SCRIPT_DIR/bin/falco" "$PREFIX/bin/falco"
run install -m 755 "$SCRIPT_DIR/bin/claude-interceptor" "$PREFIX/bin/claude-interceptor"
run install -m 755 "$SCRIPT_DIR/bin/coding-agents-kit-ctl" "$PREFIX/bin/coding-agents-kit-ctl"

info "Installing plugin..."
run install -m 644 "$SCRIPT_DIR/share/libcoding_agent.dylib" "$PREFIX/share/libcoding_agent.dylib"

info "Installing configuration..."
run install -m 644 "$SCRIPT_DIR/config/falco.yaml" "$PREFIX/config/falco.yaml"
run install -m 644 "$SCRIPT_DIR/config/falco.coding_agents_plugin.yaml" "$PREFIX/config/falco.coding_agents_plugin.yaml"

info "Installing rules..."
run install -m 644 "$SCRIPT_DIR/rules/default/coding_agents_rules.yaml" "$PREFIX/rules/default/coding_agents_rules.yaml"
run install -m 644 "$SCRIPT_DIR/rules/seen.yaml" "$PREFIX/rules/seen.yaml"

# ---------------------------------------------------------------------------
# launchd user agent
# ---------------------------------------------------------------------------

info "Installing launchd user agent..."
PLIST_DIR="${HOME}/Library/LaunchAgents"
PLIST_FILE="${PLIST_DIR}/dev.falcosecurity.coding-agents-kit.plist"

if ! $DRY_RUN; then
    mkdir -p "$PLIST_DIR"
    # If an agent from a previous install is loaded, unload it first.
    # `launchctl load` fails on an already-loaded plist ("already loaded"),
    # and we need a clean reload to pick up any plist or launcher changes.
    if [[ -f "$PLIST_FILE" ]]; then
        launchctl unload "$PLIST_FILE" 2>/dev/null || true
    fi
    # Render plist template with actual prefix and HOME.
    sed -e "s|@PREFIX@|${PREFIX}|g" -e "s|@HOME@|${HOME}|g" \
        "$SCRIPT_DIR/launchd/dev.falcosecurity.coding-agents-kit.plist" \
        > "$PLIST_FILE"
    # Install and render launcher script.
    sed "s|@PREFIX@|${PREFIX}|g" \
        "$SCRIPT_DIR/launchd/coding-agents-kit-launcher.sh" \
        > "$PREFIX/bin/coding-agents-kit-launcher.sh"
    chmod 755 "$PREFIX/bin/coding-agents-kit-launcher.sh"
    # Load the service.
    launchctl load "$PLIST_FILE"
else
    echo "  [DRY-RUN] launchctl unload $PLIST_FILE (if loaded)"
    echo "  [DRY-RUN] sed → $PLIST_FILE"
    echo "  [DRY-RUN] sed → $PREFIX/bin/coding-agents-kit-launcher.sh"
    echo "  [DRY-RUN] launchctl load $PLIST_FILE"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=== Installation complete ==="
echo ""
echo "  Install prefix:  $PREFIX"
echo "  Falco binary:    $PREFIX/bin/falco"
echo "  Interceptor:     $PREFIX/bin/claude-interceptor"
echo "  Plugin:          $PREFIX/share/libcoding_agent.dylib"
echo "  Config:          $PREFIX/config/"
echo "  Rules:           $PREFIX/rules/"
echo "  User rules:      $PREFIX/rules/user/ (add custom rules here)"
echo "  Logs:            $PREFIX/log/"
echo ""

if ! $DRY_RUN; then
    echo "  Service status:"
    launchctl list dev.falcosecurity.coding-agents-kit 2>&1 | head -5 | sed 's/^/    /' || true
    echo ""
fi

echo "  Management CLI:  $PREFIX/bin/coding-agents-kit-ctl"
echo ""
echo "  To verify:"
echo "    $PREFIX/bin/coding-agents-kit-ctl status"
echo "    $PREFIX/bin/coding-agents-kit-ctl hook status"
echo ""
echo "  To uninstall:"
echo "    $PREFIX/bin/coding-agents-kit-ctl uninstall"
echo ""
echo "  Tip: add to your PATH to use coding-agents-kit-ctl without the full path:"
echo "    export PATH=\"$PREFIX/bin:\$PATH\""
