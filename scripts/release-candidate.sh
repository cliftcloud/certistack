#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
#
# Build the release candidate for a version and print its registry line:
#
#   <tag> <full commit> <sha256 of bin/certistack-linux-amd64>
#
# The candidate is the executable that is tested before a release and the one
# the release publishes, so both must be the same bytes. It is built from the
# checked-out commit with the toolchain go.mod names, stamped with the tag as
# its version and the commit and its commit time as its identity, and none of
# that varies with the machine or the moment, so the release workflow rebuilds
# it and gets the same digest. A maintainer runs this on the release commit,
# runs the test campaign on bin/certistack-linux-amd64, and proposes the
# printed line for release/candidates.txt; the workflow refuses a tag whose
# rebuilt line is not the registered one.
#
# The version is a stable tag (v0.1.0) or a release candidate tag
# (v0.1.0-rc1). A release candidate is built, registered and tested the same
# way, but only a stable tag starts the release workflow, so a candidate is a
# git tag and a registry line and is never published.
#
# Usage: scripts/release-candidate.sh vMAJOR.MINOR.PATCH[-rcN]
# Needs bash, git, make, sha256sum, GNU date and the go.mod toolchain.
set -euo pipefail

fail() {
    printf 'release candidate: %s\n' "$*" >&2
    exit 1
}

tag=${1:-}
[[ -n "$tag" ]] || fail 'usage: release-candidate.sh vMAJOR.MINOR.PATCH[-rcN]'
# Numbers have no leading zeros; a candidate's suffix is -rc and a number from 1.
if [[ ! "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc[1-9][0-9]*)?$ ]]; then
    fail "the version must be a stable tag such as v0.1.0 or a release candidate such as v0.1.0-rc1 (-rc and a number from 1), without leading zeros; got $tag"
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."
commit=$(git rev-parse --verify HEAD) || fail 'this is not a git checkout with a commit'
# The status is taken on its own line: inside the condition below a failing
# git would read as an empty (clean) answer.
status=$(git status --porcelain) || fail 'git status failed, so the working tree cannot be shown to be clean'
if [[ -n "$status" ]]; then
    fail 'the working tree is not clean; a candidate is built from a commit, and only from one'
fi

# go.mod's go line is the toolchain: a newer local Go builds with itself, not
# with that version, so the exact match is checked here. (A toolchain line,
# were go.mod to gain one, names the version instead.)
toolchain=$(awk '$1 == "toolchain" { print $2; exit }' go.mod)
if [[ -z "$toolchain" ]]; then
    toolchain=$(awk '$1 == "go" { print "go" $2; exit }' go.mod)
fi
[[ "$toolchain" =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'go.mod names no Go version to build with'
built_with=$(go env GOVERSION)
if [[ "$built_with" != "$toolchain" ]]; then
    fail "release builds use $toolchain, the go.mod toolchain, and this Go is $built_with (a different compiler builds different bytes); install $toolchain, or run with GOTOOLCHAIN=$toolchain so Go fetches it"
fi

make build-linux VERSION="$tag" >&2
binary=bin/certistack-linux-amd64
[[ -f "$binary" ]] || fail "the build left no $binary"

# Where the binary can run, check that it says what was asked of the build:
# the tag as its version, this commit, and the commit's own time.
if [[ "$(go env GOHOSTOS)/$(go env GOHOSTARCH)" == linux/amd64 ]]; then
    reported=$("./$binary" version)
    reported_version=$(awk 'NR == 1 { print $2 }' <<<"$reported")
    reported_commit=$(awk '$1 == "commit:" { print $2 }' <<<"$reported")
    reported_built=$(awk '$1 == "built:" { print $2 }' <<<"$reported")
    expected_built=$(date -u -d "@$(git log -1 --format=%ct)" +%Y-%m-%dT%H:%M:%SZ)
    [[ "$reported_version" == "$tag" ]] || fail "the binary reports version $reported_version, not $tag"
    [[ "$reported_commit" == "${commit:0:12}" ]] || fail "the binary reports commit $reported_commit, not ${commit:0:12}"
    [[ "$reported_built" == "$expected_built" ]] || fail "the binary reports build date $reported_built, not the commit's $expected_built"
fi

digest=$(sha256sum "$binary")
printf '%s %s %s\n' "$tag" "$commit" "${digest%% *}"
