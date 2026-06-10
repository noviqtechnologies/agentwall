#!/usr/bin/env bash
set -e

echo "[*] VEXA AgentWall Installer"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [[ "$OS" == *"mingw"* || "$OS" == *"msys"* || "$OS" == *"cygwin"* ]]; then
  OS="windows"
fi

if [[ "$OS" == "darwin" ]]; then
  OS="macos"
fi

# We map architecture strings so they match our GitHub release artifacts
if [[ "$ARCH" == "amd64" ]]; then
  ARCH="x86_64"
elif [[ "$ARCH" == "arm64" ]]; then
  ARCH="aarch64"
fi

echo "[*] Detected OS: $OS"
echo "[*] Detected Arch: $ARCH"

VERSION="v1.0.9"
echo "[*] Using version: $VERSION"

ASSET_NAME="agentwall-${VERSION}-${OS}-${ARCH}.zip"
ASSET_URL="https://github.com/noviqtechnologies/agentwall/releases/download/${VERSION}/${ASSET_NAME}"

TEMPDIR=$(mktemp -d)
trap 'rm -rf "$TEMPDIR"' EXIT

echo "[*] Downloading $ASSET_URL..."
curl -sSL "$ASSET_URL" -o "${TEMPDIR}/asset.zip"

if [ ! -f "${TEMPDIR}/asset.zip" ]; then
  echo "[!] Download failed."
  exit 1
fi

echo "[*] Extracting..."
unzip -q -o "${TEMPDIR}/asset.zip" -d "$TEMPDIR"

BINARY_PATH="${TEMPDIR}/bin/agentwall"
if [[ "$OS" == "windows" ]]; then
  BINARY_PATH="${TEMPDIR}/bin/agentwall.exe"
fi

if [ ! -f "$BINARY_PATH" ]; then
  echo "[!] Failed to locate the binary inside the extracted archive at $BINARY_PATH."
  exit 1
fi

LOCALBIN="$HOME/.local/bin"
mkdir -p "$LOCALBIN"

echo "[*] Installing to $LOCALBIN..."
mv "$BINARY_PATH" "${LOCALBIN}/agentwall"
chmod +x "${LOCALBIN}/agentwall"

echo ""
echo "[✓] AgentWall has been installed to ${LOCALBIN}/agentwall"
echo ""

if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo "[!] Warning: $HOME/.local/bin is not in your PATH."
  echo "    Please add it to your profile (e.g. ~/.bashrc, ~/.zshrc) like so:"
  echo '    export PATH="$HOME/.local/bin:$PATH"'
  echo ""
fi

echo "Run 'agentwall --help' to get started."
