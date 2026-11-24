#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
#
# Install the CertiStack CLI on a controller (a small Linux VM, never the Proxmox VE host):
#
#   curl -fsSL https://certistack.dev/install.sh | bash
#
# It does what "Install by hand" in docs/quickstart.md does, and installs nothing unless every check passes:
#   1. downloads the release's executable, CONTAINER-IMAGE.txt and the signed checksum list;
#   2. imports the release public key from this repository at the release tag and requires the fingerprint
#      written below; a key that came from anywhere else is never trusted;
#   3. checks the checksum list's GPG signature, made by the release key's signing subkey;
#   4. checks both files against the checksum list;
#   5. installs certistack into /usr/local/bin (with sudo), keeping a previous one as certistack.prev, and creates
#      /secure/certistack and /var/lib/certistack/reports for certistack setup;
#   6. names the next step: certistack setup, or certistack check with the controller.env that setup directory holds.
# Everything runs inside main, called on the last line, so a download cut short runs nothing.

set -euo pipefail

# The release key: the primary key's fingerprint, and the end of its signing subkey's (SECURITY.md).
RELEASE_KEY_FINGERPRINT="C72ABBC9F3544A71FD5D27A9577480B530101FD2"
SIGNING_SUBKEY_SUFFIX="F701B3B2C1836DDF"

VERSION="${CERTISTACK_VERSION:-v0.1.3}"
REPOSITORY="https://github.com/cliftcloud/certistack"
RELEASE_URL="${CERTISTACK_RELEASE_URL:-$REPOSITORY/releases/download/$VERSION}"
KEY_URL="${CERTISTACK_KEY_URL:-https://raw.githubusercontent.com/cliftcloud/certistack/$VERSION/release/release-public-key.asc}"
BIN_DIR="${CERTISTACK_BIN_DIR:-/usr/local/bin}"
SECURE_DIR="${CERTISTACK_SECURE_DIR:-/secure/certistack}"
REPORT_DIR="${CERTISTACK_REPORT_DIR:-/var/lib/certistack/reports}"
FILES="certistack-linux-amd64 CONTAINER-IMAGE.txt SHA256SUMS-bin.txt SHA256SUMS-bin.txt.asc"

say() { printf '%s\n' "$*"; }
fail() { printf 'certistack install: %s\n' "$*" >&2; exit 1; }

# The next step: certistack setup on a first install, and certistack check with the file when the setup directory
# already holds a controller.env (an upgrade: setup has been run, and what it needs now is proof that this version
# works with it). Without sudo, setup keeps its files in ~/certistack/secure, so that is looked at too, unless
# CERTISTACK_SECURE_DIR names the directory.
next_step() {
  local env_file=""
  if [ -f "$SECURE_DIR/controller.env" ]; then
    env_file="$SECURE_DIR/controller.env"
  elif [ -z "${CERTISTACK_SECURE_DIR:-}" ] && [ -n "${HOME:-}" ] && [ -f "$HOME/certistack/secure/controller.env" ]; then
    env_file="$HOME/certistack/secure/controller.env"
  fi
  if [ -n "$env_file" ]; then
    say "Installed. Next: certistack check --env-file $env_file"
  else
    say "Installed. Next: certistack setup (https://certistack.dev/docs/quickstart/#2-run-the-setup)"
  fi
}

main() {
  say "CertiStack $VERSION installer"

  if [ -d /etc/pve ] || command -v pveversion >/dev/null 2>&1; then
    fail "this is a Proxmox VE host. Run the installer on the controller, a small Linux VM (it may run on this node), not on the host itself: https://certistack.dev/docs/quickstart/"
  fi
  case "$(uname -s)/$(uname -m)" in
    Linux/x86_64 | Linux/amd64) ;;
    *) fail "releases are built for Linux on x86_64 (amd64); this is $(uname -s)/$(uname -m)" ;;
  esac
  local missing="" tool
  for tool in curl gpg gpgv sha256sum install mktemp; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
  done
  [ -z "$missing" ] || fail "missing:$missing. On Debian or Ubuntu: sudo apt install curl gnupg"

  # sudo only when the install directory, or the nearest directory above it that exists, is not writable.
  local sudo="" nearest="$BIN_DIR"
  while [ ! -d "$nearest" ]; do nearest="$(dirname "$nearest")"; done
  if [ "$(id -u)" -ne 0 ] && [ ! -w "$nearest" ]; then
    command -v sudo >/dev/null 2>&1 \
      || fail "$BIN_DIR is not writable and sudo is missing: set CERTISTACK_BIN_DIR to a directory of yours on your PATH (https://certistack.dev/docs/quickstart/#install-without-sudo)"
    sudo="sudo"
  fi

  local work
  work="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand now: the path is fixed
  trap "GNUPGHOME='$work/gnupg' gpgconf --kill gpg-agent >/dev/null 2>&1; rm -rf '$work'" EXIT
  chmod 0700 "$work"
  mkdir -m 0700 "$work/gnupg"

  say "Downloading $VERSION"
  local file
  for file in $FILES; do
    curl -fsSL --retry 3 -o "$work/$file" "$RELEASE_URL/$file" || fail "could not download $RELEASE_URL/$file"
  done
  curl -fsSL --retry 3 -o "$work/release-public-key.asc" "$KEY_URL" || fail "could not download the release public key from $KEY_URL"

  say "Checking the signature"
  GNUPGHOME="$work/gnupg" gpg --batch --quiet --import "$work/release-public-key.asc" 2>/dev/null \
    || fail "the release public key from $KEY_URL could not be imported"
  GNUPGHOME="$work/gnupg" gpg --batch --export "$RELEASE_KEY_FINGERPRINT" > "$work/release.gpg" 2>/dev/null || true
  [ -s "$work/release.gpg" ] \
    || fail "the key from $KEY_URL is not the release key $RELEASE_KEY_FINGERPRINT; nothing was installed"
  local status
  status="$(gpgv --status-fd 1 --keyring "$work/release.gpg" "$work/SHA256SUMS-bin.txt.asc" "$work/SHA256SUMS-bin.txt" 2>/dev/null || true)"
  local valid
  valid="$(printf '%s\n' "$status" | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $3, $NF; exit }')"
  local signer primary
  signer="${valid%% *}"
  primary="${valid##* }"
  if [ -z "$valid" ] || [ "$primary" != "$RELEASE_KEY_FINGERPRINT" ] || [ "${signer%"$SIGNING_SUBKEY_SUFFIX"}" = "$signer" ]; then
    fail "SHA256SUMS-bin.txt is not signed by the release key's signing subkey; nothing was installed"
  fi
  say "  Good signature from the signing subkey $signer"

  say "Checking the checksums"
  (cd "$work" && sha256sum --strict --check --quiet SHA256SUMS-bin.txt) \
    || fail "a downloaded file does not match the signed checksum list; nothing was installed"
  say "  certistack-linux-amd64 and CONTAINER-IMAGE.txt: OK"

  say "Installing into $BIN_DIR${sudo:+ (sudo may ask for your password)}"
  [ -d "$BIN_DIR" ] || $sudo install -d -m 0755 "$BIN_DIR"
  if [ -e "$BIN_DIR/certistack" ]; then
    $sudo cp -p "$BIN_DIR/certistack" "$BIN_DIR/certistack.prev"
    say "  kept the previous version as $BIN_DIR/certistack.prev"
  fi
  $sudo install -m 0755 "$work/certistack-linux-amd64" "$BIN_DIR/certistack"
  # The directories certistack setup and the docs use; with sudo or as root only. Without either, setup offers
  # ~/certistack/secure and a reports directory beside it.
  if [ -n "$sudo" ] || [ "$(id -u)" -eq 0 ] || [ -n "${CERTISTACK_SECURE_DIR:-}" ]; then
    local dir
    for dir in "$SECURE_DIR" "$REPORT_DIR"; do
      [ -d "$dir" ] || $sudo install -d -m 0700 -o "$(id -un)" "$dir"
    done
  fi

  "$BIN_DIR/certistack" version
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) say "Note: $BIN_DIR is not on your PATH; add it, or run $BIN_DIR/certistack." ;;
  esac
  say ""
  next_step
}

main "$@"
