#!/usr/bin/env bash
# Install Crux — run from a terminal:  chmod +x install-crux.sh && ./install-crux.sh
# Builds from source (requires git clone) and installs to ~/.local/bin.

set -euo pipefail

trap 'echo; echo "Installation failed. See error above."; exit 1' ERR

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_DIR="$HOME/.local/bin"

echo "Crux Mesh Installer"
echo "==================="
echo
echo "Repo:       $REPO_DIR"
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
                # Ensure we have a downloader
                if ! command -v curl >/dev/null 2>&1; then
                    if command -v wget >/dev/null 2>&1; then
                        echo "curl not found; using wget to fetch rustup installer..."
                        wget -qO- https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
                    elif command -v apt-get >/dev/null 2>&1; then
                        echo "curl not found; installing it via apt..."
                        sudo apt-get update -qq && sudo apt-get install -y curl
                        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
                    else
                        echo "Error: neither curl nor wget found. Please install curl and re-run."
                        exit 1
                    fi
                else
                    echo "Installing Rust via rustup..."
                    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
                fi
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
        read -rp "Would you like to install it now? [Y/n] " yn
        case "${yn:-Y}" in
            [Yy]*)
                echo
                if command -v apt-get >/dev/null 2>&1; then
                    sudo apt-get update -qq && sudo apt-get install -y curl
                elif command -v dnf >/dev/null 2>&1; then
                    sudo dnf install -y curl
                elif command -v yum >/dev/null 2>&1; then
                    sudo yum install -y curl
                elif command -v pacman >/dev/null 2>&1; then
                    sudo pacman -Sy --noconfirm curl
                else
                    echo "Could not detect a package manager."
                    echo "Please install curl manually: https://curl.se/download.html"
                    echo "Then re-run this script."
                    exit 1
                fi
                echo
                echo "curl installed."
                break
                ;;
            [Nn]*)
                echo
                echo "OK. Install curl later and re-run."
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
cp target/release/crux        "$INSTALL_DIR/crux"
cp target/release/crux-router "$INSTALL_DIR/crux-router"
cp target/release/helm        "$INSTALL_DIR/helm"
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
    echo "$INSTALL_DIR is not in your PATH."
    echo
    SHELL_PROFILE="$HOME/.bashrc"
    while true; do
        read -rp "Add it to $SHELL_PROFILE automatically? [Y/n] " yn
        case "${yn:-Y}" in
            [Yy]*)
                echo "" >> "$SHELL_PROFILE"
                echo "# Added by Crux installer" >> "$SHELL_PROFILE"
                echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_PROFILE"
                echo
                echo "Added. Run:  source $SHELL_PROFILE"
                echo
                break
                ;;
            [Nn]*)
                echo
                echo "To add it manually, put this in your shell profile:"
                echo
                echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
                echo
                break
                ;;
            *)
                echo "Please type Y or N."
                ;;
        esac
    done
fi
