#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
# Hermetic tests for the credentials-free coverage-fleet case generator.
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
generator="$repo_dir/scripts/campaign/generate_current_coverage_cases.go"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
targets="$tmp_dir/targets.yaml"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

write_targets() {
    printf '%s\n' \
        'schema_version: 1' \
        'lab:' \
        '  pbs_namespace: coverage-fleet' \
        '  source_network: { vlan_id: 70, cidr: 10.60.70.0/24 }' \
        'test_boundary:' \
        '  synthetic_data_only: true' \
        '  intended_test: backup_restore' \
        '  workload_configuration: pending' \
        '  readiness: ready' \
        'targets:' \
        '  - { vm_id: 7111, name: ubuntu-2204-nginx, address: 10.60.70.111, os_id: ubuntu-2204, workload: nginx-http, workload_type: http, status: running }' \
        '  - { vm_id: 7112, name: ubuntu-2204-postgresql, address: 10.60.70.112, os_id: ubuntu-2204, workload: postgresql, workload_type: postgresql, status: running }' \
        >"$targets"
}

run_generator() {
    local output="$1"
    local expected_targets="${2:-2}"
    go run "$generator" \
        --targets "$targets" --out "$output" --expected-targets "$expected_targets" \
        --zone-id csLab81 --vnet-id csVn81 --vlan-tag 81 \
        --ip-range 10.0.81.0/24 --probe-ip 10.0.81.1 --allowed-nodes node-a
}

write_reuse_attestation() {
    local path="$1"
    printf '%s\n' \
        'schema_version: 1' \
        'source_vlan_id: 70' \
        'source_cidr: 10.60.70.0/24' \
        'restore_zone_id: csLab70' \
        'restore_vnet_id: csVn70' \
        'restore_vlan_id: 70' \
        'restore_cidr: 10.60.70.0/24' \
        'l2_isolated: true' \
        'no_physical_uplink: true' \
        'no_gateway: true' \
        'no_snat: true' \
        'no_routed_path_to_source: true' \
        >"$path"
}

run_reuse_generator() {
    local output="$1"
    local attestation="$2"
    go run "$generator" \
        --targets "$targets" --out "$output" --expected-targets 2 \
        --zone-id csLab70 --vnet-id csVn70 --vlan-tag 70 \
        --ip-range 10.60.70.0/24 --probe-ip 10.60.70.1 --allowed-nodes node-a \
        --isolation-attestation "$attestation"
}

expect_rejection() {
    local output="$1"
    local expected_targets="${2:-2}"
    set +e
    run_generator "$output" "$expected_targets" >"$tmp_dir/command.out" 2>&1
    local status=$?
    set -e
    [[ "$status" != 0 ]] || fail 'generator unexpectedly accepted invalid inventory'
    [[ ! -e "$output" ]] || fail 'generator wrote plans after rejecting inventory'
}

write_targets
accepted_out="$tmp_dir/accepted"
run_generator "$accepted_out"
[[ $(find "$accepted_out" -maxdepth 1 -name '*.yaml' -type f | wc -l) == 6 ]] || fail 'accepted inventory did not generate all/single/OS/workload cases'
grep -Fxq $'positive\tsingle-7111.yaml' "$accepted_out/certistack-campaign.manifest" || fail 'per-target positive case missing from manifest'
grep -Fxq $'selective\tworkload-postgresql.yaml' "$accepted_out/certistack-campaign.manifest" || fail 'workload matrix case missing from manifest'

# A separately bridged restore VNet may deliberately retain source addressing,
# but only with a retained operational attestation of the air-gap boundary.
reuse_attestation="$tmp_dir/csLab70-isolation.yaml"
write_reuse_attestation "$reuse_attestation"
reuse_out="$tmp_dir/reuse-source-addressing"
run_reuse_generator "$reuse_out" "$reuse_attestation"
cmp "$reuse_attestation" "$reuse_out/restore-isolation-attestation.yaml" || fail 'source-address reuse attestation was not retained with cases'
grep -Fq 'reuses source addressing' "$reuse_out/README.txt" || fail 'reuse boundary was not recorded in README'

set +e
go run "$generator" \
    --targets "$targets" --out "$tmp_dir/reuse-without-attestation" --expected-targets 2 \
    --zone-id csLab70 --vnet-id csVn70 --vlan-tag 70 \
    --ip-range 10.60.70.0/24 --probe-ip 10.60.70.1 --allowed-nodes node-a >"$tmp_dir/reuse.out" 2>&1
reuse_status=$?
set -e
[[ "$reuse_status" != 0 ]] || fail 'generator accepted source-address reuse without an attestation'
grep -Fq -- '--isolation-attestation is required' "$tmp_dir/reuse.out" || fail 'missing reuse attestation denial was not explicit'

# The engine restores only through the run's PBS endpoint (storage_id: pbs);
# a generator that wrote a named PVE storage produced plans validate rejects.
grep -Fq 'storage_id: pbs' "$accepted_out/all.yaml" || fail 'generated plan does not use the pbs storage selector'

# The Community Edition writes unsigned reports and ignores compliance.sign_key_path, so a
# generated plan names no key unless one was asked for, and the generator needs none.
! grep -Fq 'sign_key_path' "$accepted_out/all.yaml" || fail 'generated plan names a signing key although none was given'
# The README it writes does not send the operator to a variable the controller
# refuses (CERTISTACK_SIGN_KEY) or say a plan needs a key (review R1-12).
! grep -Fq 'CERTISTACK_SIGN_KEY' "$accepted_out/README.txt" || fail 'the generated README still tells the operator to set CERTISTACK_SIGN_KEY, which the controller refuses'
! grep -Fq 'requires a controller-local Ed25519 signing key' "$accepted_out/README.txt" || fail 'the generated README still says every plan requires a signing key'
grep -Fq 'writes its reports unsigned' "$accepted_out/README.txt" || fail 'the generated README does not say the Community Edition writes unsigned reports'
keyed_out="$tmp_dir/keyed"
go run "$generator"     --targets "$targets" --out "$keyed_out" --expected-targets 2 --sign-key-path /secure/enterprise-signing.ed25519     --zone-id csLab81 --vnet-id csVn81 --vlan-tag 81     --ip-range 10.0.81.0/24 --probe-ip 10.0.81.1 --allowed-nodes node-a >/dev/null 2>&1 || fail 'generator refused an explicit --sign-key-path'
grep -Fq 'sign_key_path: /secure/enterprise-signing.ed25519' "$keyed_out/all.yaml" || fail 'an explicit --sign-key-path was not written to the plan'
set +e
go run "$generator" \
    --targets "$targets" --out "$tmp_dir/named-storage" --expected-targets 2 --storage-id certistack-coverage \
    --zone-id csLab81 --vnet-id csVn81 --vlan-tag 81 \
    --ip-range 10.0.81.0/24 --probe-ip 10.0.81.1 --allowed-nodes node-a >"$tmp_dir/named-storage.out" 2>&1
named_storage_status=$?
set -e
[[ "$named_storage_status" != 0 ]] || fail 'generator accepted a storage_id the engine rejects'
grep -Fq -- '--storage-id must be pbs' "$tmp_dir/named-storage.out" || fail 'named storage denial was not explicit'
[[ ! -e "$tmp_dir/named-storage" ]] || fail 'generator wrote plans after rejecting the storage selector'

expect_rejection "$tmp_dir/short-inventory" 3
grep -Fq 'expected exactly 3' "$tmp_dir/command.out" || fail 'inventory-count denial was not explicit'

sed -i 's/schema_version: 1/schema_version: 2/' "$targets"
expect_rejection "$tmp_dir/unknown-schema"
grep -Fq 'expected supported version 1' "$tmp_dir/command.out" || fail 'unknown schema denial was not explicit'
write_targets

# The current live handoff is intentionally in this state: no executable plan
# may be generated until image acceptance (identity, cloud-init, SSH, QGA).
sed -i 's/readiness: ready/readiness: blocked/' "$targets"
expect_rejection "$tmp_dir/unaccepted"
grep -Fq 'readiness is "blocked"' "$tmp_dir/command.out" || fail 'unaccepted inventory denial was not explicit'

# These values feed plan names and matrix filenames, so reject malformed
# inventory before writing any artifact or allowing path-shaped labels.
sed -i 's/readiness: blocked/readiness: ready/' "$targets"
sed -i 's/os_id: ubuntu-2204/os_id: ..\/escape/' "$targets"
expect_rejection "$tmp_dir/unsafe-token"
grep -Fq 'unsafe name, OS ID, workload, or workload type' "$tmp_dir/command.out" || fail 'unsafe matrix token denial was not explicit'

write_targets
sed -i 's/address: 10.60.70.112/address: 10.60.70.111/' "$targets"
expect_rejection "$tmp_dir/duplicate-address"
grep -Fq 'appears more than once' "$tmp_dir/command.out" || fail 'duplicate source address denial was not explicit'

printf 'current coverage-case generator tests passed\n'
