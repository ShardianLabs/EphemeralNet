#!/usr/bin/env bash
set -euo pipefail

REPO="ShardianLabs/EphemeralNet"
INSTALL_DIR=${INSTALL_DIR:-}
CURL_BIN=${CURL_BIN:-curl}
TAR_BIN=${TAR_BIN:-tar}

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required tool '$1' was not found" >&2
    exit 1
  fi
}

require "$CURL_BIN"
require "$TAR_BIN"

uname_s=$(uname -s 2>/dev/null || true)
uname_m=$(uname -m 2>/dev/null || true)
archive_suffix=""
case "$uname_s" in
  Linux)
    case "$uname_m" in
      x86_64|amd64)
        archive_suffix="linux-x64.tar.gz"
        ;;
      *)
        echo "error: unsupported Linux architecture '$uname_m'" >&2
        exit 1
        ;;
    esac
    ;;
  Darwin)
    archive_suffix="macos-universal.tar.gz"
    ;;
  *)
    echo "error: unsupported operating system '$uname_s'" >&2
    exit 1
    ;;
esac

echo "Determining latest EphemeralNet release..."
latest_url=$($CURL_BIN -sI "https://github.com/${REPO}/releases/latest" \
  | grep -i '^location:' | tr -d '\r' | awk '{print $2}')

if [ -z "$latest_url" ]; then
  echo "error: unable to determine latest release tag from redirection" >&2
  exit 1
fi

latest_tag=$(basename "$latest_url")
if [ -z "$latest_tag" ]; then
  echo "error: unable to extract tag name from redirection URL" >&2
  exit 1
fi

archive_name="eph-${latest_tag}-${archive_suffix}"
download_url="https://github.com/${REPO}/releases/download/${latest_tag}/${archive_name}"

tmp_dir=$(mktemp -d)
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

archive_path="$tmp_dir/${archive_name}"
if ! $CURL_BIN -fL "$download_url" -o "$archive_path"; then
  echo "error: failed to download ${download_url}" >&2
  exit 1
fi

$TAR_BIN -xzf "$archive_path" -C "$tmp_dir"

if [ -z "$INSTALL_DIR" ]; then
  if [ "${EUID:-$(id -u)}" -eq 0 ] && [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
  fi
fi

install_path="$INSTALL_DIR/eph"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp_dir/eph" "$install_path"

echo "EphemeralNet ${latest_tag} installed to ${install_path}"
if ! printf '%s' "$PATH" | tr ':' '\n' | grep -Fx "$INSTALL_DIR" >/dev/null 2>&1; then
  echo "warning: ${INSTALL_DIR} is not on your PATH. Add it to use 'eph' without a full path." >&2
fi

echo "Run 'eph --help' to get started."
