#!/usr/bin/env bash
# Install Crux — double-click this file in Finder to install.
# Builds from source (requires git clone) and installs to ~/.local/bin.

set -euo pipefail

# Keep the Terminal window open on error
trap 'echo; echo "Installation failed. See error above."; read -rn 1 -p "Press any key to close..."; echo; exit 1' ERR

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_DIR="$HOME/.local/bin"

echo "Crux Mesh Installer"
echo "==================="
echo
echo "Repo: $REPO_DIR"
echo "Install to: $INSTALL_DIR"
echo

# -- Check for Rust / cargo --------------------------------------------------

if ! command -v cargo >/dev/null 2>&1; then
    echo "It looks like you're missing Rust."
    echo
    while true; do
        read -rp "Would you like to install the latest version from https://rustup.rs/ ? [Y/n] " yn
        case "${yn:-Y}" in
            [Yy]*)
                echo
                echo "Installing Rust via rustup..."
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
                # shellcheck disable=SC1090
                source "$HOME/.cargo/env" 2>/dev/null || true
                if ! command -v cargo >/dev/null 2>&1; then
                    export PATH="$HOME/.cargo/bin:$PATH"
                fi
                echo
                echo "Rust installed."
                break
                ;;
            [Nn]*)
                echo
                echo "OK. Install Rust later from https://rustup.rs/ and re-run this script."
                read -rn 1 -p "Press any key to close..."; echo
                exit 0
                ;;
            *)
                echo "Please type Y or N."
                ;;
        esac
    done
fi

echo "Rust: $(rustc --version)"
echo

# -- Check for curl ----------------------------------------------------------
# curl is required by crux-router for HTTPS forwarding (OAuth token endpoints).

if ! command -v curl >/dev/null 2>&1; then
    echo "It looks like curl is missing."
    echo "crux-router requires curl for HTTPS traffic."
    echo
    while true; do
        read -rp "Would you like to install it via Homebrew now? [Y/n] " yn
        case "${yn:-Y}" in
            [Yy]*)
                echo
                if command -v brew >/dev/null 2>&1; then
                    brew install curl
                else
                    echo "Homebrew not found. Please install curl manually:"
                    echo "  https://curl.se/download.html"
                    echo "Then re-run this script."
                    read -rn 1 -p "Press any key to close..."; echo
                    exit 1
                fi
                echo
                echo "curl installed."
                break
                ;;
            [Nn]*)
                echo
                echo "OK. Install curl later (e.g. 'brew install curl') and re-run."
                echo "crux-router will fall back to plain HTTP only until curl is available."
                break
                ;;
            *)
                echo "Please type Y or N."
                ;;
        esac
    done
fi

if command -v curl >/dev/null 2>&1; then
    echo "curl: $(curl --version | head -1)"
    echo
fi

# -- Build -------------------------------------------------------------------

echo "Building Crux (this takes a minute or two on first build)..."
echo
cd "$REPO_DIR"
cargo build --release
echo

# -- Install -----------------------------------------------------------------

echo "Installing binaries to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp target/release/crux      "$INSTALL_DIR/crux"
cp target/release/crux-router "$INSTALL_DIR/crux-router"
cp target/release/helm      "$INSTALL_DIR/helm"
chmod +x "$INSTALL_DIR/crux" "$INSTALL_DIR/crux-router" "$INSTALL_DIR/helm"

# -- Verify ------------------------------------------------------------------

if "$INSTALL_DIR/crux" --version 2>/dev/null; then
    true
else
    echo "warning: could not verify crux --version"
fi

echo
echo "Installation complete."
echo

# -- PATH hint ---------------------------------------------------------------

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    echo "Add the following line to your shell profile (~/.zshrc or ~/.bash_profile):"
    echo
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo
fi

read -rn 1 -p "Press any key to close..."; echo
