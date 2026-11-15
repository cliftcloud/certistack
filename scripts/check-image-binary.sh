#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
#
# Prove a controller image carries exactly the given executable: the digest of
# /usr/local/bin/certistack inside the image must equal the digest of the file
# the image was built around (make container-release). The release workflow
# runs this before it pushes anything, so a signed image reference always
# names the bytes that were tested and the release checked.
#
# Usage: scripts/check-image-binary.sh IMAGE BINARY
set -euo pipefail

image=${1:?usage: check-image-binary.sh IMAGE BINARY}
binary=${2:?usage: check-image-binary.sh IMAGE BINARY}
engine=${CONTAINER_ENGINE:-docker}

fail() {
    printf 'image binary check: %s\n' "$*" >&2
    exit 1
}

expected=$(sha256sum "$binary")
expected=${expected%% *}
inside=$("$engine" run --rm --entrypoint sha256sum "$image" /usr/local/bin/certistack) ||
    fail "could not read the executable inside $image"
actual=${inside%% *}
[[ "$actual" =~ ^[0-9a-f]{64}$ ]] || fail "the image reported no digest for its executable"
if [[ "$actual" != "$expected" ]]; then
    fail "the image's executable is $actual, not the verified $expected"
fi
printf 'image binary check: %s carries %s\n' "$image" "$actual"
