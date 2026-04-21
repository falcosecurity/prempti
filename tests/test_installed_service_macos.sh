#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# test_installed_service_macos.sh — Integration test for the installed
# coding-agents-kit service on macOS.
#
# Drives the .pkg through `installer -pkg` (matching the GUI Installer.app
# code path), exercises the launchd-managed service end to end, and verifies
# the documented `coding-agents-kit-ctl` lifecycle leaves a clean system.
#
# Usage:
#   bash tests/test_installed_service_macos.sh [PATH_TO_PKG]
#
# If no pkg path is given, the most recent build/coding-agents-kit-*-darwin-*.pkg
# is used. Run `make macos-<arch>` first.
#
# Requires: macOS, no other coding-agents-kit install loaded.
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

PKG="${1:-}"
if [[ -z "$PKG" ]]; then
    PKG=$(ls -t "$ROOT_DIR"/build/coding-agents-kit-*-darwin-*.pkg 2>/dev/null | head -1 || true)
fi
if [[ ! -f "$PKG" ]]; then
    echo "ERROR: no .pkg found. Pass a path as the first argument, or run \`make macos-<arch>\` first." >&2
    exit 1
fi

PREFIX="$HOME/.coding-agents-kit"
PLIST="$HOME/Library/LaunchAgents/dev.falcosecurity.coding-agents-kit.plist"
LABEL="dev.falcosecurity.coding-agents-kit"
HOOK="$PREFIX/bin/claude-interceptor"
CTL="$PREFIX/bin/coding-agents-kit-ctl"
SOCK="$PREFIX/run/broker.sock"
PASS=0
FAIL=0

bool() { [[ "$1" -eq 0 ]] && echo 1 || echo 0; }

assert() {
    local name="$1"; local val="$2"
    if [[ "$val" == "1" ]]; then
        echo "  PASS: $name"
        PASS=$((PASS+1))
    else
        echo "  FAIL: $name"
        FAIL=$((FAIL+1))
    fi
}

cleanup() {
    if [[ -x "$CTL" ]]; then
        "$CTL" uninstall >/dev/null 2>&1 || true
    fi
    launchctl unload "$PLIST" 2>/dev/null || true
}
trap cleanup EXIT

run_hook() {
    CODING_AGENTS_KIT_TIMEOUT_MS=8000 \
        printf '%s' "$1" | "$HOOK"
}

wait_for_socket() {
    local timeout=${1:-10}
    local i=0
    while (( i < timeout * 4 )); do
        [[ -S "$SOCK" ]] && return 0
        sleep 0.25
        i=$((i+1))
    done
    return 1
}

# ---------------------------------------------------------------------------
# Pre-test: ensure clean slate
# ---------------------------------------------------------------------------

echo "=== Setup ==="
launchctl unload "$PLIST" 2>/dev/null || true
rm -rf "$PREFIX" "$PLIST"
echo "  Slate clean: $PREFIX, $PLIST"

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

echo
echo "=== Install ==="
installer -pkg "$PKG" -target CurrentUserHomeDirectory >/dev/null
echo "  Installed: $(basename "$PKG")"

if ! wait_for_socket 15; then
    echo "FATAL: broker socket never appeared after install"
    [[ -f "$PREFIX/log/falco.err" ]] && { echo "--- falco.err ---"; tail -40 "$PREFIX/log/falco.err"; }
    [[ -f "$PREFIX/log/falco.log" ]] && { echo "--- falco.log ---"; tail -40 "$PREFIX/log/falco.log"; }
    exit 1
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

echo
echo "=== Preflight ==="
assert "binary: falco"                     "$( [[ -x "$PREFIX/bin/falco" ]] && echo 1 || echo 0 )"
assert "binary: claude-interceptor"        "$( [[ -x "$PREFIX/bin/claude-interceptor" ]] && echo 1 || echo 0 )"
assert "binary: coding-agents-kit-ctl"     "$( [[ -x "$PREFIX/bin/coding-agents-kit-ctl" ]] && echo 1 || echo 0 )"
assert "plugin: libcoding_agent.dylib"     "$( [[ -f "$PREFIX/share/libcoding_agent.dylib" ]] && echo 1 || echo 0 )"
assert "config: falco.yaml"                "$( [[ -f "$PREFIX/config/falco.yaml" ]] && echo 1 || echo 0 )"
assert "rules: default ruleset"            "$( [[ -f "$PREFIX/rules/default/coding_agents_rules.yaml" ]] && echo 1 || echo 0 )"
assert "rules: seen.yaml"                  "$( [[ -f "$PREFIX/rules/seen.yaml" ]] && echo 1 || echo 0 )"
assert "launchd plist installed"           "$( [[ -f "$PLIST" ]] && echo 1 || echo 0 )"
assert "launchd agent registered"          "$( launchctl list "$LABEL" >/dev/null 2>&1 && echo 1 || echo 0 )"
assert "broker socket up"                  "$( [[ -S "$SOCK" ]] && echo 1 || echo 0 )"

# ---------------------------------------------------------------------------
# Interceptor pipeline
# ---------------------------------------------------------------------------

echo
echo "=== Interceptor pipeline ==="
OUT=$(run_hook '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello"},"session_id":"smoke","cwd":"/tmp","tool_use_id":"smoke_allow"}')
assert "interceptor returns a verdict"     "$( [[ "$OUT" == *'"permissionDecision"'* ]] && echo 1 || echo 0 )"
assert "safe Bash → allow"                 "$( [[ "$OUT" == *'"permissionDecision":"allow"'* ]] && echo 1 || echo 0 )"

OUT=$(run_hook '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/readme.txt"},"session_id":"smoke","cwd":"/tmp","tool_use_id":"smoke_read"}')
assert "Read /tmp/* → allow"               "$( [[ "$OUT" == *'"permissionDecision":"allow"'* ]] && echo 1 || echo 0 )"

# Sensitive-path deny via basename-match on a .env file. Using a basename
# rather than a prefix like /etc/ sidesteps the macOS /etc → /private/etc
# canonicalisation that would make a prefix rule miss.
OUT=$(run_hook '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/smoke/.env","content":"x"},"session_id":"smoke","cwd":"/tmp","tool_use_id":"smoke_deny"}')
assert "Write .env → deny (default rule)"  "$( [[ "$OUT" == *'"permissionDecision":"deny"'* ]] && echo 1 || echo 0 )"

# ---------------------------------------------------------------------------
# ctl commands
# ---------------------------------------------------------------------------

echo
echo "=== ctl ==="
"$CTL" status >/dev/null 2>&1
assert "ctl status exits 0"                "$( bool $? )"

OUT=$("$CTL" mode 2>/dev/null)
assert "ctl mode reports enforcement"      "$( [[ "$OUT" == "enforcement" ]] && echo 1 || echo 0 )"

"$CTL" health >/dev/null 2>&1
assert "ctl health exits 0"                "$( bool $? )"

# Regression: disable → enable used to fail with "Load failed: 5: I/O error".
"$CTL" disable >/dev/null 2>&1
sleep 1
"$CTL" enable  >/dev/null 2>&1
assert "ctl disable→enable round-trip"     "$( bool $? )"
wait_for_socket 10
assert "broker socket back after enable"   "$( [[ -S "$SOCK" ]] && echo 1 || echo 0 )"

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

echo
echo "=== Uninstall ==="
"$CTL" uninstall >/dev/null 2>&1
sleep 1
assert "prefix removed"                    "$( [[ ! -d "$PREFIX" ]] && echo 1 || echo 0 )"
assert "launchd plist removed"             "$( [[ ! -f "$PLIST" ]] && echo 1 || echo 0 )"
assert "launchd agent unregistered"        "$( launchctl list "$LABEL" >/dev/null 2>&1 && echo 0 || echo 1 )"

# Already uninstalled — disarm the trap so it doesn't double-uninstall.
trap - EXIT

echo
echo "================================"
echo "Results: $PASS passed, $FAIL failed"
echo "================================"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
