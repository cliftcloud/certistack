#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
#
# Start the controller image under the restrictions deploy/controller/compose.yaml
# publishes (read-only root, tmpfs at /tmp/certistack, UID 65532, no
# capabilities) and prove a `run` gets through every local startup step --
# plan load, report directory, private staging directory -- up to
# its first contact with the node. The node is deliberately unreachable.
#
# Usage: scripts/controller-container-smoke.sh IMAGE
set -euo pipefail

image=${1:?usage: controller-container-smoke.sh IMAGE}
engine=${CONTAINER_ENGINE:-docker}
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

fail() {
    printf 'controller container smoke: %s\n' "$*" >&2
    exit 1
}

work=$(mktemp -d)
cleanup() {
    # The state volume is written as UID 65532; remove it from a container
    # running as that user rather than needing root on the host.
    "$engine" run --rm --user 65532:65532 --entrypoint /bin/sh -v "$work/state:/state" "$image" \
        -c 'rm -rf /state/* /state/.[!.]* 2>/dev/null; true' >/dev/null 2>&1 || true
    rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$work/state" "$work/secrets" "$work/plans"
chmod 0777 "$work/state" "$work/secrets"
cp "$repo_dir/examples/minimal-single-vm.yaml" "$work/plans/plan.yaml"
# ssh never gets far enough to compare this key: the node port is closed. The
# file belongs to the container's user, mode 0600, as deploy/controller/README.md
# installs it: the controller refuses a known_hosts file that another user owns
# or can write, as OpenSSH does.
"$engine" run --rm --user 65532:65532 --entrypoint /bin/sh -v "$work/secrets:/secrets" "$image" \
    -c "printf '%s\\n' '127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJxK8y7cUqk1Kx0mAq9mWn1pS3oWc2x2lSmokeTestKey' >/secrets/known_hosts && chmod 0600 /secrets/known_hosts" \
    || fail 'could not write known_hosts as the container user'
chmod 0755 "$work/secrets" "$work/plans"
chmod 0644 "$work/plans/plan.yaml"

restricted=(
    "$engine" run --rm --read-only --user 65532:65532 --cap-drop=ALL
    --security-opt no-new-privileges:true
    --tmpfs /tmp/certistack:uid=65532,gid=65532,mode=0700
    -v "$work/state:/var/lib/certistack"
    -v "$work/secrets:/run/certistack-secrets:ro"
    -v "$work/plans:/plans:ro"
    "$image"
)

set +e
output=$("${restricted[@]}" run /plans/plan.yaml --node pve-smoke \
    --ssh-host 127.0.0.1 --ssh-port 1 --ssh-user certistack \
    --ssh-known-hosts /run/certistack-secrets/known_hosts \
    --output /var/lib/certistack/reports 2>&1)
status=$?
set -e

[[ $status -ne 0 ]] || fail 'run succeeded against an unreachable node'
if ! grep -Fq 'determine PVE node architecture' <<<"$output"; then
    printf '%s\n' "$output" >&2
    fail 'run stopped before its first node contact under the published container restrictions'
fi
printf 'controller container smoke: run reached node contact under the published restrictions\n'
