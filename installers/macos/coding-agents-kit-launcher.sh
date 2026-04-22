#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# coding-agents-kit-launcher.sh — Wrapper for launchd service lifecycle.
#
# launchd has no ExecStartPost/ExecStopPost equivalent, so this wrapper
# handles hook registration before Falco starts and hook removal on exit.
#
PREFIX="@PREFIX@"

# Register the hook before starting Falco.
"$PREFIX/bin/coding-agents-kit-ctl" hook add 2>/dev/null

# Remove the hook on exit (SIGTERM from launchd, SIGINT, or normal exit).
cleanup() {
    "$PREFIX/bin/coding-agents-kit-ctl" hook remove 2>/dev/null
}
trap cleanup EXIT TERM INT

# Run Falco in foreground (not exec, so the trap fires on signal).
"$PREFIX/bin/falco" -U \
    -c "$PREFIX/config/falco.yaml" \
    --disable-source syscall
