#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
# Hermetic tests for the compatibility-contract coverage auditor.
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
auditor="$repo_dir/scripts/campaign/audit_compatibility_matrix.go"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
contract="$tmp_dir/compatibility.yml"
targets="$tmp_dir/targets.yml"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

write_contract() {
    printf '%s\n' \
        'schema_version: 2' \
        'guest_os: [ubuntu-2404]' \
        'platforms:' \
        '  pairs: [{ pve_major: 9, pbs_major: 4 }]' \
        'recipes:' \
        '  - { id: nginx-http, lifecycle: implemented, workload_type: http, supported_guest_os: [ubuntu-2404] }' \
        '  - { id: future-db, lifecycle: planned, workload_type: future_db, supported_guest_os: [ubuntu-2404] }' \
		'test_dimensions:' \
		'  storage_profiles: [{ id: storage-a, status: available }]' \
		'  guest_profiles: [{ id: guest-a, status: available }]' \
		'  backup_profiles: [{ id: backup-a, status: available }]' \
		'  restore_profiles: [{ id: restore-a, status: available }]' \
        'test_suites:' \
        '  release_candidate:' \
		'    platform_pair: { pve_major: 9, pbs_major: 4 }' \
        '    guest_os: all' \
        '    lifecycles: [implemented, planned]' \
		'    storage_profiles: [storage-a]' \
		'    guest_profiles: [guest-a]' \
		'    backup_profiles: [backup-a]' \
		'    restore_profiles: [restore-a]' \
        >"$contract"
}

write_targets() {
    printf '%s\n' \
        'schema_version: 1' \
        'test_boundary:' \
        '  synthetic_data_only: true' \
        '  intended_test: backup_restore' \
        '  workload_configuration: ready' \
        '  readiness: ready' \
		'qualification:' \
		'  platform_pairs: [{ pve_major: 9, pbs_major: 4 }]' \
		'  storage_profiles: [storage-a]' \
		'  guest_profiles: [guest-a]' \
		'  backup_profiles: [backup-a]' \
		'  restore_profiles: [restore-a]' \
        'targets:' \
        '  - { vm_id: 7111, os_id: ubuntu-2404, workload_type: http, status: running }' \
        >"$targets"
}

run_audit() {
    go run "$auditor" --contract "$contract" --targets "$targets" --suite release_candidate
}

expect_rejection() {
    set +e
    run_audit >"$tmp_dir/command.out" 2>&1
    local status=$?
    set -e
    [[ "$status" != 0 ]] || fail 'audit unexpectedly accepted incomplete evidence'
}

write_contract
write_targets
run_audit >"$tmp_dir/success.out"
grep -Fq 'implemented_cells_covered=1 planned_cells_not_claimed=1' "$tmp_dir/success.out" || fail 'successful audit did not report supported/planned cells'

sed -i 's/workload_type: http/workload_type: tcp/' "$targets"
expect_rejection
grep -Fq 'missing 1 implemented compatibility cell' "$tmp_dir/command.out" || fail 'missing supported cell denial was not explicit'

write_targets
sed -i 's/storage_profiles: \[storage-a\]/storage_profiles: []/' "$targets"
expect_rejection
grep -Fq 'lacks accepted evidence for selected storage_profiles' "$tmp_dir/command.out" || fail 'missing storage-profile evidence denial was not explicit'

write_targets
sed -i 's/readiness: ready/readiness: blocked/' "$targets"
expect_rejection
grep -Fq 'image acceptance is required' "$tmp_dir/command.out" || fail 'unaccepted inventory denial was not explicit'

printf 'compatibility matrix audit tests passed\n'
