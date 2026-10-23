#!/bin/sh
# Scout installer for Linux and macOS.
#   curl -fsSL https://scout.codetotech.com/install.sh | sh
#
# Downloads the latest prebuilt binary from GitHub releases and installs it.
# Override the install dir with SCOUT_INSTALL_DIR, or the version with SCOUT_VERSION.
set -eu

REPO="MUKE-coder/scout"
BIN="scout"

say() { printf '\033[36m==>\033[0m %s\n' "$1"; }
err() { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# --- detect platform --------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)  os="linux" ;;
  Darwin) os="darwin" ;;
  *) err "unsupported OS: $os (try: go install github.com/$REPO/cmd/scout@latest)" ;;
esac
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) err "unsupported architecture: $arch" ;;
esac

asset="scout_${os}_${arch}.tar.gz"
if [ -n "${SCOUT_VERSION:-}" ]; then
  url="https://github.com/$REPO/releases/download/${SCOUT_VERSION}/${asset}"
else
  url="https://github.com/$REPO/releases/latest/download/${asset}"
fi

# --- download & extract -----------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
say "Downloading $asset"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tmp/$asset" || err "download failed: $url"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmp/$asset" "$url" || err "download failed: $url"
else
  err "need curl or wget"
fi
tar -xzf "$tmp/$asset" -C "$tmp" || err "extract failed"
[ -f "$tmp/$BIN" ] || err "binary not found in archive"
chmod +x "$tmp/$BIN"

# --- install ----------------------------------------------------------------
dir="${SCOUT_INSTALL_DIR:-/usr/local/bin}"
if [ -w "$dir" ] 2>/dev/null; then
  mv "$tmp/$BIN" "$dir/$BIN"
elif command -v sudo >/dev/null 2>&1 && [ "$dir" = "/usr/local/bin" ]; then
  say "Installing to $dir (needs sudo)"
  sudo mv "$tmp/$BIN" "$dir/$BIN"
else
  dir="$HOME/.local/bin"
  mkdir -p "$dir"
  mv "$tmp/$BIN" "$dir/$BIN"
fi

say "Installed $BIN to $dir/$BIN"
if ! command -v scout >/dev/null 2>&1; then
  printf '\033[33mnote:\033[0m add %s to your PATH:\n  export PATH="%s:$PATH"\n' "$dir" "$dir"
fi
"$dir/$BIN" version 2>/dev/null || true
say "Done. Try:  scout scan --target http://localhost:3000"
