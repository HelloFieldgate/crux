#!/usr/bin/env bash
# MCP server entry point for Claude Code. Ensures ~/.local/bin/crux is current,
# then hands off to it. Stdout is reserved for JSON-RPC; all build output goes to stderr.
set -e
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
make -C "$REPO" install --no-print-directory INSTALL_DIR="$HOME/.local/bin" >&2
exec "$HOME/.local/bin/crux" --mcp
