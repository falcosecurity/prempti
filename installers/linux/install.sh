#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# install.sh — Install coding-agents-kit.
#
# Copies binaries, configs, and rules to the install prefix, sets up a
# systemd user service, and registers the Claude Code hook.
#
# Usage: bash install.sh [--dry-run] [--help]
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${HOME}/.coding-agents-kit"
DRY_RUN=false
HAS_DIALOG=false

# Parse arguments.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--dry-run]"
            echo ""
            echo "Options:"
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

# Verify we have the package contents.
for f in bin/falco bin/claude-interceptor bin/coding-agents-kit-ctl \
         share/libcoding_agent.so \
         config/falco.yaml config/falco.coding_agents_plugin.yaml \
         config/supervisor.yaml \
         rules/seen.yaml systemd/coding-agents-kit.service; do
    [[ -f "$SCRIPT_DIR/$f" ]] || err "Missing package file: $f (are you running from the extracted package?)"
done

# Check systemd user support.
if ! systemctl --user status &>/dev/null 2>&1; then
    warn "systemd user session not available. Service will not be installed."
    SKIP_SYSTEMD=true
else
    SKIP_SYSTEMD=false
fi

# ---------------------------------------------------------------------------
# Interactive confirmation (dialog)
# ---------------------------------------------------------------------------

if $HAS_DIALOG && ! $DRY_RUN && [[ -t 0 ]]; then
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
run install -m 644 "$SCRIPT_DIR/share/libcoding_agent.so" "$PREFIX/share/libcoding_agent.so"

info "Installing configuration..."
run install -m 644 "$SCRIPT_DIR/config/falco.yaml" "$PREFIX/config/falco.yaml"
run install -m 644 "$SCRIPT_DIR/config/falco.coding_agents_plugin.yaml" "$PREFIX/config/falco.coding_agents_plugin.yaml"
# supervisor.yaml: ship the default file only on a fresh install. Existing
# installations may have user edits (the file is meant to be edited).
if [[ ! -f "$PREFIX/config/supervisor.yaml" ]]; then
    run install -m 644 "$SCRIPT_DIR/config/supervisor.yaml" "$PREFIX/config/supervisor.yaml"
else
    info "Preserving existing $PREFIX/config/supervisor.yaml"
fi

info "Installing rules..."
run install -m 644 "$SCRIPT_DIR/rules/default/coding_agents_rules.yaml" "$PREFIX/rules/default/coding_agents_rules.yaml"
run install -m 644 "$SCRIPT_DIR/rules/seen.yaml" "$PREFIX/rules/seen.yaml"

# ---------------------------------------------------------------------------
# systemd user service
# ---------------------------------------------------------------------------

if ! $SKIP_SYSTEMD; then
    info "Installing systemd user service..."
    SYSTEMD_DIR="${HOME}/.config/systemd/user"
    SERVICE_FILE="${SYSTEMD_DIR}/coding-agents-kit.service"

    # Render the service template with the actual prefix.
    if ! $DRY_RUN; then
        mkdir -p "$SYSTEMD_DIR"
        sed "s|@PREFIX@|${PREFIX}|g" "$SCRIPT_DIR/systemd/coding-agents-kit.service" \
            > "$SERVICE_FILE"
    else
        echo "  [DRY-RUN] sed s|@PREFIX@|${PREFIX}|g → $SERVICE_FILE"
    fi

    run systemctl --user daemon-reload
    run systemctl --user enable coding-agents-kit
    run systemctl --user start coding-agents-kit

    # Enable lingering so the service runs even without an active login session.
    if command -v loginctl &>/dev/null; then
        run loginctl enable-linger "$USER"
    fi
else
    warn "Skipping systemd service installation."
fi

# ---------------------------------------------------------------------------
# Claude Code hook registration
# ---------------------------------------------------------------------------

if $SKIP_SYSTEMD; then
    warn "Skipping hook registration (systemd service not installed)."
    warn "The hook requires the service to be running — registering it"
    warn "without the service would block ALL Claude Code tool calls."
    warn "Start the service manually, then run:"
    warn "  ${PREFIX}/bin/coding-agents-kit-ctl hook add"
else
    info "Registering Claude Code hook..."
    if $DRY_RUN; then
        echo "  [DRY-RUN] ${PREFIX}/bin/coding-agents-kit-ctl hook add"
    else
        run "$PREFIX/bin/coding-agents-kit-ctl" hook add
    fi
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
echo "  Plugin:          $PREFIX/share/libcoding_agent.so"
echo "  Config:          $PREFIX/config/"
echo "  Rules:           $PREFIX/rules/"
echo "  User rules:      $PREFIX/rules/user/ (add custom rules here)"
echo ""

if ! $SKIP_SYSTEMD && ! $DRY_RUN; then
    echo "  Service status:"
    systemctl --user status coding-agents-kit --no-pager 2>&1 | head -5 | sed 's/^/    /'
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
