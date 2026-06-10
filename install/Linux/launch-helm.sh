#!/usr/bin/env bash
# Launch Helm — run from a terminal:  ./launch-helm.sh
# Opens http://127.0.0.1:8111 in your default browser.

set -euo pipefail

# Locate helm binary
HELM=""
if [ -x "$HOME/.local/bin/helm" ]; then
    HELM="$HOME/.local/bin/helm"
fi

if [ -z "$HELM" ]; then
    echo "Helm is not installed."
    echo "Run install-crux.sh first."
    exit 1
fi

echo "Launching Helm..."
echo "Browser will open at http://127.0.0.1:8111"
echo "(Press Ctrl+C to stop the server)"
echo

exec "$HELM"
