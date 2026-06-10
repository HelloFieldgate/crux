#!/usr/bin/env bash
# Launch Helm — double-click this file in Finder to open the Helm graph editor.
# Opens http://127.0.0.1:8111 in your default browser.

set -euo pipefail

trap 'echo; echo "Could not launch Helm. See error above."; read -rp "Press any key to close..." _; exit 1' ERR

# Locate helm binary
HELM=""
if [ -x "$HOME/.local/bin/helm" ]; then
    HELM="$HOME/.local/bin/helm"
elif command -v helm >/dev/null 2>&1; then
    HELM="$(command -v helm)"
fi

if [ -z "$HELM" ]; then
    echo "Helm is not installed."
    echo "Run 'Install Crux.command' first."
    echo
    read -rp "Press any key to close..." _
    exit 1
fi

echo "Launching Helm..."
echo "Browser will open at http://127.0.0.1:8111"
echo "(Press Ctrl+C in this window to stop the server)"
echo

exec "$HELM"
