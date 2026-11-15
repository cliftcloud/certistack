#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
# Hermetic behavior tests for the release-evidence campaign helper. The first
# part drives the helper with a mock CertiStack binary; the second builds the
# real CLI and runs the helper against signed report fixtures through the real
# verifier. Nothing contacts a PVE node.
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
helper="$repo_dir/scripts/run-lab-campaign.sh"
tmp_dir=$(mktemp -d)
tmp_dir=$(cd "$tmp_dir" && pwd -P)
trap 'rm -rf "$tmp_dir"' EXIT
campaign_keyring="$tmp_dir/campaign-keyring.pub"
printf '00\n' >"$campaign_keyring"
unset PVE_TLS_INSECURE

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

expect_status() {
    local expected="$1"
    shift
    # Every non-list campaign must pin a signer or say its reports are unsigned.
    # Add the hermetic fixture by default so individual behavioral tests can
    # focus on their own gate. Release-mode tests that exercise an explicit
    # keyring still pass it, and those that run unsigned pass --unsigned.
    if [[ " $* " == *" $helper "* && " $* " != *" --list-cases "* && " $* " != *" --keyring "* && " $* " != *" --unsigned "* ]]; then
        set -- "$@" --keyring "$campaign_keyring"
    fi
    set +e
    "$@" </dev/null >"$tmp_dir/command.out" 2>&1
    local actual=$?
    set -e
    [[ "$actual" == "$expected" ]] || {
        sed 's/^/  /' "$tmp_dir/command.out" >&2 || true
        fail "expected exit $expected, got $actual: $*"
    }
}

make_case_dir() {
    local name="$1"
    local case_dir="$tmp_dir/$name"
    mkdir -p "$case_dir"
    printf 'format=2\nallowed_nodes\tnode-a\npositive\thealthy.yaml\nfault\tfault-9001.yaml\n' >"$case_dir/certistack-campaign.manifest"
    printf '%s\n' \
        'version: v1' \
        'plan_id: healthy-plan' \
        >"$case_dir/healthy.yaml"
    printf '%s\n' \
        'version: v1' \
        'plan_id: fault-plan' \
        'tiers:' \
        '  - vms:' \
        '      - vmid: 9001' \
        '        probes:' \
        '          - type: tcp' \
        '            description: Expected probe failure' \
        >"$case_dir/fault-9001.yaml"
    printf '%s\n' \
        'version: v1' \
        'plan_id: admission-guard-plan' \
        >"$case_dir/admission-capacity-guard.yaml"
    printf '%s' "$case_dir"
}

# ledger_for OUTPUT prints the single campaign ledger under a campaign's
# --output directory.
ledger_for() {
    find "$1/campaign-logs" -name cases.tsv -type f -print -quit
}

# The mock stands in for CertiStack. `run` saves an empty report in --output
# and prints the controller's saved-report line; `verify-report` records its
# arguments and prints the configured verdict. Acceptance semantics are the
# real verifier's and are tested with it below.
mock_bin="$tmp_dir/certistack-mock"
cat >"$mock_bin" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  version)
    printf 'certistack %s\n' "${MOCK_VERSION_LABEL:-v0.1.0}"
    printf '  commit:    %s\n' "${MOCK_VERSION_COMMIT:-0123456789abcdef}"
    if [[ "${MOCK_VERSION_NO_BUILT:-}" != 1 ]]; then
      printf '  built:     %s\n' "${MOCK_VERSION_BUILT:-2026-09-29T00:00:00Z}"
    fi
    printf '  go:        go1.26.8\n'
    ;;
  validate)
    if [[ "${MOCK_INVALID_PLAN:-}" == "$2" ]]; then printf 'mock validation failure\n' >&2; exit 1; fi
    exit 0
    ;;
  run)
    output="" previous=""
    for argument in "$@"; do
      if [[ "$previous" == "--output" ]]; then output="$argument"; fi
      previous="$argument"
    done
    printf '%s\n' "$@" >"$MOCK_RUN_ARGS"
    printf '%s\n' "$MOCK_RUN_MESSAGE"
    if [[ -n "${MOCK_EDIT_PLAN:-}" ]]; then printf '# edited during the campaign\n' >>"$MOCK_EDIT_PLAN"; fi
    # $2 is the plan the campaign asked this run to read.
    if [[ "${MOCK_EDIT_RUN_PLAN:-}" == 1 ]]; then printf '# edited during the run\n' >>"$2"; fi
    if [[ "${MOCK_RUN_NO_REPORT:-}" == 1 ]]; then exit "$MOCK_RUN_STATUS"; fi
    if [[ -n "${MOCK_REPORT_PATH:-}" ]]; then
      report="$MOCK_REPORT_PATH"
    else
      mkdir -p "$output/mock-plan"
      # A coarse file clock must still date the report after the case start.
      sleep 0.05
      report=$(mktemp "$output/mock-plan/report.XXXXXX")
    fi
    # Lines that imitate the controller's, as failure text a guest or plan
    # controls can: one naming a report that does not exist, one naming a
    # second fresh report in the output directory.
    if [[ -n "${MOCK_FORGED_LINE:-}" ]]; then printf 'Controller report saved to: %s\n' "$MOCK_FORGED_LINE"; fi
    if [[ "${MOCK_SECOND_REPORT:-}" == 1 ]]; then
      second=$(mktemp "$output/mock-plan/report.XXXXXX")
      printf 'Controller report saved to: %s\n' "$second"
    fi
    if [[ "${MOCK_DOUBLE_SAVED:-}" == 1 ]]; then printf 'Controller report saved to: %s\n' "$report"; fi
    printf '✓ Controller report saved to: %s\n' "$report"
    exit "$MOCK_RUN_STATUS"
    ;;
  verify-report)
    if [[ "${2:-}" == --help ]]; then
      if [[ "${MOCK_VERIFY_LEGACY:-}" == 1 ]]; then
        printf 'Flags:\n      --keyring string\n'
      elif [[ "${MOCK_VERIFY_NO_WORKER:-}" == 1 ]]; then
        printf 'Flags:\n      --expect-plan string\n      --expect-outcome string\n'
      elif [[ "${MOCK_VERIFY_NO_UNSIGNED:-}" == 1 ]]; then
        printf 'Flags:\n      --expect-plan string\n      --expect-outcome string\n      --expect-worker-sha256 string\n'
      else
        printf 'Flags:\n      --expect-plan string\n      --expect-outcome string\n      --expect-worker-sha256 string\n      --unsigned\n'
      fi
      exit 0
    fi
    # Exactly one way of judging the report: the pinned keyring, or --unsigned
    # (a verifier makes the two together a usage error).
    trust_flags=0
    [[ " $* " == *" --keyring "* ]] && trust_flags=$((trust_flags + 1))
    [[ " $* " == *" --unsigned "* ]] && trust_flags=$((trust_flags + 1))
    [[ "$trust_flags" == 1 ]] || exit 65
    printf '%s\n' "$@" >"$MOCK_VERIFY_ARGS"
    if [[ " $* " == *" --expect-validation-mode test_skip_integrity "* && " $* " != *" --allow-test-mode "* ]]; then exit 64; fi
    printf '%s\n' "$MOCK_SUMMARY"
    exit "${MOCK_VERIFY_STATUS:-0}"
    ;;
  *) exit 64 ;;
esac
MOCK
chmod 0700 "$mock_bin"
export MOCK_VERIFY_ARGS="$tmp_dir/verify-args"
export MOCK_RUN_ARGS="$tmp_dir/run-args"

accepted_summary() {
    printf '{"signature_valid":true,"acceptance":{"verdict":"accepted","expected_outcome":"%s","bindings":["plan","plan_sha256","probe_policy","rto_objective","admission_policy","node","build","validation_mode"]}}' "$1"
}

# unbound_summary OUTCOME BINDINGS: an accepted verdict whose bindings are the
# JSON array BINDINGS, as verify-report writes one for a report it could not
# bind to everything (an earlier schema, or no plan digest).
unbound_summary() {
    printf '{"signature_valid":true,"acceptance":{"verdict":"accepted","expected_outcome":"%s","bindings":%s}}' "$1" "$2"
}

rejected_summary() {
    printf '{"signature_valid":true,"acceptance":{"verdict":"rejected","expected_outcome":"%s","bindings":["plan"],"reasons":["mock rejection"]}}' "$1"
}

apply_mock() {
    export MOCK_RUN_STATUS="$1"
    export MOCK_RUN_MESSAGE="$2"
    export MOCK_SUMMARY="$3"
    export MOCK_VERIFY_STATUS=0
    unset MOCK_RUN_NO_REPORT MOCK_REPORT_PATH MOCK_DOUBLE_SAVED MOCK_EDIT_PLAN MOCK_EDIT_RUN_PLAN MOCK_FORGED_LINE MOCK_SECOND_REPORT MOCK_VERIFY_LEGACY MOCK_VERIFY_NO_WORKER MOCK_VERIFY_NO_UNSIGNED MOCK_VERSION_NO_BUILT
    rm -f "$MOCK_VERIFY_ARGS" "$MOCK_RUN_ARGS"
}

# verify_arg FLAG VALUE: the last verify-report call passed FLAG VALUE.
verify_arg() {
    arg_in "$MOCK_VERIFY_ARGS" "$1" "$2"
}

# arg_in FILE FLAG VALUE: the argument list recorded in FILE has FLAG VALUE.
arg_in() {
    awk -v flag="$2" -v value="$3" 'previous == flag && $0 == value { found = 1 } { previous = $0 } END { exit !found }' "$1"
}

# bundle_for OUTPUT prints the campaign's evidence directory (a campaign under
# OUTPUT holds one).
bundle_for() {
    dirname "$(ledger_for "$1")"
}

# ledger_has OUTPUT CASE OUTCOME STATUS: the ledger has a row for CASE with the
# outcome and exit status.
ledger_has() {
    awk -F'\t' -v c="$2" -v o="$3" -v s="$4" '$1 == c && $3 == o && $4 == s { found = 1 } END { exit !found }' "$(ledger_for "$1")"
}

# A safety sentinel must win before case selection or executable resolution.
blocked_dir="$tmp_dir/blocked"
mkdir -p "$blocked_dir"
printf 'unsafe restore network\n' >"$blocked_dir/CAMPAIGN-BLOCKED"
expect_status 2 "$helper" --node node-a --cases "$blocked_dir" --list-cases
grep -Fq 'Campaign is blocked pending required lab prerequisites' "$tmp_dir/command.out" || fail 'blocked sentinel was not reported'

# A manifest controls the default matrix and excludes fault fixtures.
list_dir=$(make_case_dir 'list')
expect_status 0 "$helper" --node node-a --cases "$list_dir" --list-cases
grep -Fxq 'healthy.yaml' "$tmp_dir/command.out" || fail 'positive manifest entry was not selected'
! grep -Fq 'fault-9001.yaml' "$tmp_dir/command.out" || fail 'fault manifest entry leaked into positive matrix'
expect_status 2 "$helper" --node node-b --cases "$list_dir" --list-cases
grep -Fq 'not allowlisted' "$tmp_dir/command.out" || fail 'unlisted campaign node was accepted'

# Production-evidence claims are fail-closed: a pinned signer and full image
# integrity are mandatory, even when listing cases would not contact a node.
release_dir=$(make_case_dir 'release-evidence')
expect_status 2 "$helper" --node node-a --cases "$release_dir" --release-evidence --list-cases
grep -Fq -- '--release-evidence requires --keyring' "$tmp_dir/command.out" || fail 'release evidence accepted an unpinned signer'
release_keyring="$tmp_dir/release-keyring.pub"
printf '00\n' >"$release_keyring"
expect_status 2 "$helper" --node node-a --cases "$release_dir" --release-evidence --keyring "$release_keyring" --skip-integrity --list-cases
grep -Fq -- '--release-evidence cannot be combined with --skip-integrity' "$tmp_dir/command.out" || fail 'release evidence accepted skipped integrity'
release_insecure_env="$tmp_dir/release-insecure.env"
printf 'PVE_TLS_INSECURE=" true"\n' >"$release_insecure_env"
apply_mock 0 'mock release should not execute' ''
expect_status 2 "$helper" --node node-a --cases "$release_dir" --case healthy.yaml --certistack "$mock_bin" --env "$release_insecure_env" --keyring "$release_keyring" --release-evidence --output "$tmp_dir/output-release-insecure"
grep -Fq -- '--release-evidence forbids PVE_TLS_INSECURE' "$tmp_dir/command.out" || fail 'release evidence accepted insecure PVE TLS'
[[ ! -e "$tmp_dir/output-release-insecure" ]] || fail 'insecure release evidence created campaign output'
apply_mock 0 'mock release should not execute' ''
expect_status 2 env PVE_TLS_INSECURE=true "$helper" --node node-a --cases "$release_dir" --case healthy.yaml --certistack "$mock_bin" --keyring "$release_keyring" --release-evidence --output "$tmp_dir/output-release-insecure-inherited"
grep -Fq -- '--release-evidence forbids PVE_TLS_INSECURE' "$tmp_dir/command.out" || fail 'release evidence accepted inherited insecure PVE TLS'
[[ ! -e "$tmp_dir/output-release-insecure-inherited" ]] || fail 'inherited insecure release evidence created campaign output'

# A quoted value followed by trailing whitespace on the same line (outside
# the quotes) must be detected identically to an unquoted or leading-space
# variant: the engine trims the whole line before splitting key from value,
# so it reads this exactly as PVE_TLS_INSECURE=true regardless.
release_insecure_trailing_env="$tmp_dir/release-insecure-trailing.env"
printf 'PVE_TLS_INSECURE="true" \n' >"$release_insecure_trailing_env"
apply_mock 0 'mock release should not execute' ''
expect_status 2 "$helper" --node node-a --cases "$release_dir" --case healthy.yaml --certistack "$mock_bin" --env "$release_insecure_trailing_env" --keyring "$release_keyring" --release-evidence --output "$tmp_dir/output-release-insecure-trailing"
grep -Fq -- '--release-evidence forbids PVE_TLS_INSECURE' "$tmp_dir/command.out" || fail 'release evidence accepted insecure PVE TLS with trailing whitespace after the closing quote'
[[ ! -e "$tmp_dir/output-release-insecure-trailing" ]] || fail 'insecure release evidence with trailing whitespace created campaign output'

# A file a Windows editor saved as UTF-8 with a signature starts with the bytes
# EF BB BF. The engine's loader (cmd/certistack/environment.go) drops them
# before it reads the first line, so PVE_TLS_INSECURE=true on that line is
# read as true; the preview gate must read it the same way, or a release
# campaign would run on insecure TLS and be marked release evidence (audit F124).
release_insecure_bom_env="$tmp_dir/release-insecure-bom.env"
printf '\xef\xbb\xbfPVE_TLS_INSECURE=true\n' >"$release_insecure_bom_env"
apply_mock 0 'mock release should not execute' ''
expect_status 2 "$helper" --node node-a --cases "$release_dir" --case healthy.yaml --certistack "$mock_bin" --env "$release_insecure_bom_env" --keyring "$release_keyring" --release-evidence --output "$tmp_dir/output-release-insecure-bom"
grep -Fq -- '--release-evidence forbids PVE_TLS_INSECURE' "$tmp_dir/command.out" || fail 'release evidence accepted insecure PVE TLS on the first line of a file with a UTF-8 signature'
[[ ! -e "$tmp_dir/output-release-insecure-bom" ]] || fail 'insecure release evidence behind a UTF-8 signature created campaign output'
# The same, quoted, with whitespace around it, still after the signature.
release_insecure_bom_quoted_env="$tmp_dir/release-insecure-bom-quoted.env"
printf '\xef\xbb\xbf  PVE_TLS_INSECURE = "true" \n' >"$release_insecure_bom_quoted_env"
apply_mock 0 'mock release should not execute' ''
expect_status 2 "$helper" --node node-a --cases "$release_dir" --case healthy.yaml --certistack "$mock_bin" --env "$release_insecure_bom_quoted_env" --keyring "$release_keyring" --release-evidence --output "$tmp_dir/output-release-insecure-bom-quoted"
grep -Fq -- '--release-evidence forbids PVE_TLS_INSECURE' "$tmp_dir/command.out" || fail 'release evidence accepted quoted insecure PVE TLS behind a UTF-8 signature'
# The controls: a signature does not make a secure file insecure, and a
# signature that is not at the start of the file is no signature.
release_secure_bom_env="$tmp_dir/release-secure-bom.env"
printf '\xef\xbb\xbfPVE_TLS_INSECURE=false\n' >"$release_secure_bom_env"
release_secure_bom_dir=$(make_case_dir 'release-evidence-secure-bom')
apply_mock 0 'mock release-evidence run complete' "$(accepted_summary pass)"
expect_status 0 "$helper" --node node-a --cases "$release_secure_bom_dir" --case healthy.yaml --certistack "$mock_bin" --env "$release_secure_bom_env" --keyring "$release_keyring" --release-evidence --output "$tmp_dir/output-release-secure-bom"

# Report verification itself requires a trusted key, so the helper must refuse
# an ordinary executable campaign before it can create a ledger or contact PVE.
unkeyed_campaign_dir=$(make_case_dir 'unkeyed-campaign')
set +e
"$helper" --node node-a --cases "$unkeyed_campaign_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-unkeyed-campaign" </dev/null >"$tmp_dir/command.out" 2>&1
unkeyed_status=$?
set -e
[[ "$unkeyed_status" == 2 ]] || fail "unkeyed campaign exit = $unkeyed_status, want 2"
grep -Fq -- '--keyring is required for every executable campaign' "$tmp_dir/command.out" || fail 'unkeyed campaign was not refused clearly'
[[ ! -e "$tmp_dir/output-unkeyed-campaign" ]] || fail 'unkeyed campaign created output before admission'

# Every campaign binds reports to its binary's build identity, so a
# binary that cannot state all of it (here, no build date) is refused before
# any output or PVE contact, release evidence or not.
unidentified_dir=$(make_case_dir 'unidentified-build')
apply_mock 0 'mock unidentified build should not execute' ''
export MOCK_VERSION_NO_BUILT=1
expect_status 2 "$helper" --node node-a --cases "$unidentified_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-unidentified"
grep -Fq 'did not report its build identity' "$tmp_dir/command.out" || fail 'a binary without a full build identity was accepted'
[[ ! -e "$tmp_dir/output-unidentified" ]] || fail 'an unidentified build created campaign output'
unset MOCK_VERSION_NO_BUILT

# A verifier that cannot bind a report to the request would fail
# every case after it ran; it is refused before any PVE contact.
legacy_verifier_dir=$(make_case_dir 'legacy-verifier')
apply_mock 0 'mock legacy verifier should not execute' ''
export MOCK_VERIFY_LEGACY=1
expect_status 2 "$helper" --node node-a --cases "$legacy_verifier_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-legacy-verifier"
grep -Fq "verify-report cannot bind reports to a plan, node, build, and executable digest" "$tmp_dir/command.out" || fail 'a verifier without expectations was accepted'
[[ ! -e "$tmp_dir/output-legacy-verifier" ]] || fail 'a legacy verifier created campaign output'
unset MOCK_VERIFY_LEGACY

# A verifier that binds the plan and the build labels but cannot bind the
# executable's digest would credit a report from any executable that carries
# the same labels; it is refused the same way, before any PVE contact.
no_worker_dir=$(make_case_dir 'verifier-without-worker-digest')
apply_mock 0 'mock verifier without a worker digest should not execute' ''
export MOCK_VERIFY_NO_WORKER=1
expect_status 2 "$helper" --node node-a --cases "$no_worker_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-no-worker-digest"
grep -Fq "executable digest" "$tmp_dir/command.out" || fail 'a verifier that cannot bind the executable digest was accepted'
[[ ! -e "$tmp_dir/output-no-worker-digest" ]] || fail 'a verifier without the digest flag created campaign output'
unset MOCK_VERIFY_NO_WORKER

# A zero CLI exit without a signed report must never become a healthy pass.
missing_report_dir=$(make_case_dir 'missing-report')
apply_mock 0 'mock run complete' ''
export MOCK_RUN_NO_REPORT=1
expect_status 1 "$helper" --node node-a --cases "$missing_report_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-missing"
grep -Fq 'zero exit without signed pass-and-cleanup evidence' "$tmp_dir/command.out" || fail 'missing report was accepted as a healthy pass'
grep -Fq 'The case log does not name a saved controller report.' "$tmp_dir/command.out" || fail 'missing report was not named as the reason'
grep -Fq '"verdict":"rejected"' "$(bundle_for "$tmp_dir/output-missing")/healthy.verification.json" || fail 'a refusal was not retained as a rejected verdict'

# A healthy case is credited only when the verifier accepts its report
# bound to this case's plan, the requested node, this binary's version,
# commit and build date, the validation mode, and a pass. The run and the
# verification read the checked copy of the plan kept beside the case log, and
# the verified report is kept beside it too.
healthy_dir=$(make_case_dir 'healthy')
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
expect_status 0 "$helper" --node node-a --cases "$healthy_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-healthy"
grep -Fq $'healthy.yaml\tpositive\tverified-pass\t0' "$(ledger_for "$tmp_dir/output-healthy")" || fail 'healthy evidence was not recorded as verified'
healthy_bundle=$(bundle_for "$tmp_dir/output-healthy")
verify_arg --expect-plan "$healthy_bundle/healthy.plan.yaml" || fail 'the checked plan copy was not the expected plan'
verify_arg --expect-node node-a || fail 'the requested node was not the expected node'
verify_arg --expect-version v0.1.0 || fail 'the binary version was not the expected version'
verify_arg --expect-commit 0123456789abcdef || fail 'the binary commit was not the expected commit'
verify_arg --expect-build-date 2026-09-29T00:00:00Z || fail 'the binary build date was not the expected build date'
# The labels name a build; the signed worker digest names the bytes, and must
# be this executable's own.
verify_arg --expect-worker-sha256 "$(sha256sum <"$mock_bin" | awk '{print $1}')" || fail 'the executable digest was not the expected worker digest'
verify_arg --expect-validation-mode full_integrity || fail 'the campaign validation mode was not expected'
verify_arg --expect-outcome pass || fail 'a healthy case was not verified as a pass'
verify_arg --keyring "$campaign_keyring" || fail 'the pinned keyring was not used'
[[ $(sed -n 2p "$MOCK_RUN_ARGS") == "$healthy_bundle/healthy.plan.yaml" ]] || fail 'the run did not read the checked plan copy'
[[ $(sha256sum <"$healthy_dir/healthy.yaml") == $(sha256sum <"$healthy_bundle/healthy.plan.yaml") ]] || fail 'the plan copy differs from the plan'
grep -Fq "$(sha256sum <"$healthy_bundle/healthy.plan.yaml" | awk '{print $1}')" "$healthy_bundle/plans.tsv" || fail 'the plan copy is not the digest the campaign recorded'
grep -Fq '"acceptance":{"verdict":"accepted"' "$healthy_bundle/healthy.verification.json" || fail 'the verifier verdict was not retained'
[[ -f "$healthy_bundle/healthy.report.json" ]] || fail 'the verified report was not kept beside the case log'
[[ $(tail -n 1 "$MOCK_VERIFY_ARGS") == "$healthy_bundle/healthy.report.json" ]] || fail 'the verifier did not read the kept copy of the report'

# The worker digest is the executable file's own. A command that is not a file
# (here an exported shell function) has none to bind: an ordinary campaign runs
# without the digest flag and says so in its identity, and release evidence is
# refused before any PVE contact.
eval "certistack_function() { '$mock_bin' \"\$@\"; }"
export -f certistack_function
function_dir=$(make_case_dir 'function-binary')
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
expect_status 0 "$helper" --node node-a --cases "$function_dir" --case healthy.yaml --certistack certistack_function --output "$tmp_dir/output-function"
! grep -Fxq -- '--expect-worker-sha256' "$MOCK_VERIFY_ARGS" || fail 'a worker digest was passed for a command that is not a file'
grep -Fq 'certistack_identity=command:certistack_function' "$(bundle_for "$tmp_dir/output-function")/campaign.meta" || fail 'the weaker identity of a command was not recorded'
release_function_dir=$(make_case_dir 'function-binary-release')
apply_mock 0 'mock release should not execute' ''
expect_status 2 "$helper" --node node-a --cases "$release_function_dir" --case healthy.yaml --certistack certistack_function --keyring "$release_keyring" --release-evidence --output "$tmp_dir/output-function-release"
grep -Fq 'requires the CertiStack executable as a file' "$tmp_dir/command.out" || fail 'release evidence accepted a command with no digest to bind'
[[ ! -e "$tmp_dir/output-function-release" ]] || fail 'release evidence for a command created campaign output'
export -nf certistack_function
unset -f certistack_function

# The verifier's verdict decides. A rejected verdict, or an accepted
# one with a failing exit status, is never credited.
rejected_verdict_dir=$(make_case_dir 'rejected-verdict')
apply_mock 0 'mock run complete' '{"signature_valid":true,"all_passed":true,"all_cleaned":true,"acceptance":{"verdict":"rejected","expected_outcome":"pass","bindings":["plan"],"reasons":["the report was produced on node \"other\""]}}'
expect_status 1 "$helper" --node node-a --cases "$rejected_verdict_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-rejected-verdict"
grep -Fq 'not accepted as pass evidence' "$tmp_dir/command.out" || fail 'a rejected verdict was credited'
inconsistent_verdict_dir=$(make_case_dir 'inconsistent-verdict')
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
export MOCK_VERIFY_STATUS=1
expect_status 1 "$helper" --node node-a --cases "$inconsistent_verdict_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-inconsistent-verdict"
grep -Fq 'verify-report exit 1' "$tmp_dir/command.out" || fail 'a failing verifier exit was credited'
# An accepted verdict credits a case only if it bound everything a campaign
# asks for. A report that predates the evidence (an earlier schema, or no plan
# digest) is accepted on what it records and its verdict lists NOT BOUND
# entries, or lacks a binding; that is not evidence, so the case is not
# credited however clean the report looks, in every mode.
unbound_index=0
for unbound in \
    '["plan","probe_policy","rto_objective","admission_policy","node","build","validation_mode","NOT BOUND: plan digest (the report carries no plan_sha256, so the plan file'"'"'s exact bytes are not compared)"]' \
    '["plan","plan_sha256","node","build","validation_mode","NOT BOUND: probe policy (report schema \"1.5\" predates 1.6, which records each probe'"'"'s timeout)"]' \
    '["plan","plan_sha256","probe_policy","rto_objective","admission_policy","node","build","validation_mode","NOT BOUND: something else"]' \
    '["plan","plan_sha256","probe_policy","rto_objective","admission_policy","node","build"]' \
    '["plan","plan_sha256","probe_policy","rto_objective","admission_policy","build","validation_mode"]' \
    '["plan","plan_sha256","probe_policy","rto_objective","admission_policy","node","validation_mode"]' \
    '["plan","plan_sha256","node","build","validation_mode"]' \
    '["plan","probe_policy","rto_objective","admission_policy","node","build","validation_mode"]' \
    '["plan_sha256","probe_policy","rto_objective","admission_policy","node","build","validation_mode"]' \
    '["plan","plan_sha256","probe_policy","admission_policy","node","build","validation_mode"]' \
    '["plan","plan_sha256","probe_policy","rto_objective","node","build","validation_mode"]' \
    '[]'; do
    unbound_index=$((unbound_index + 1))
    for kind in pass fault denied; do
        unbound_dir=$(make_case_dir "unbound-$kind-$unbound_index")
        case "$kind" in
            pass) apply_mock 0 'mock run complete' "$(unbound_summary pass "$unbound")"; mode_args=(); case_file=healthy.yaml; ledger_mode=positive ;;
            fault) apply_mock 1 'mock detected fault' "$(unbound_summary fault "$unbound")"; mode_args=(--mode fault); case_file=fault-9001.yaml; ledger_mode=fault ;;
            denied) apply_mock 1 'Error: DR validation failed: admission control guardrail triggered: admission denied' "$(unbound_summary denied "$unbound")"; mode_args=(--mode guard); case_file=admission-capacity-guard.yaml; ledger_mode=guard ;;
        esac
        out="$tmp_dir/output-unbound-$kind-$unbound_index"
        if [[ "$kind" == denied ]]; then
            expect_status 1 "$helper" --node node-a --cases "$unbound_dir" "${mode_args[@]}" --certistack "$mock_bin" --output "$out"
        else
            expect_status 1 "$helper" --node node-a --cases "$unbound_dir" "${mode_args[@]}" --case "$case_file" --certistack "$mock_bin" --output "$out"
        fi
        grep -Fq 'without binding it to everything a campaign credits' "$tmp_dir/command.out" || fail "an accepted $kind verdict that bound too little was credited ($unbound)"
        ! awk -F'\t' -v c="$case_file" '$1 == c && $3 ~ /^verified-/ { found = 1 } END { exit !found }' "$(ledger_for "$out")" || fail "an under-bound $kind verdict was recorded as verified ($unbound)"
        verification="$(bundle_for "$out")/${case_file%.yaml}.verification.json"
        grep -Fq '"helper_refusal":true' "$verification" || fail "an under-bound $kind verdict left no helper refusal ($unbound)"
        grep -Fq '"verdict":"rejected"' "$verification" || fail "an under-bound $kind verdict was kept as accepted ($unbound)"
        [[ -f "${verification%.json}.unbound.json" ]] && grep -Fq '"verdict":"accepted"' "${verification%.json}.unbound.json" || fail "the verifier's own verdict was not kept beside the refusal ($unbound)"
    done
done

# A verifier that trusts no signature prints no verdict; the refusal and its
# reason are kept instead of an empty file.
untrusted_dir=$(make_case_dir 'untrusted-verdict')
apply_mock 0 'mock run complete' ''
export MOCK_VERIFY_STATUS=2
expect_status 1 "$helper" --node node-a --cases "$untrusted_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-untrusted-verdict"
grep -Fq '"verdict":"rejected"' "$(bundle_for "$tmp_dir/output-untrusted-verdict")/healthy.verification.json" || fail 'an untrusted report left no rejected verdict'

# Only the report this case's run saved counts. Every "report saved" line in the
# log is a candidate: a line naming anything but a regular file in the
# campaign's output directory written after the case started is ignored, so a
# line a guest or plan can forge blocks nothing and credits nothing; a second
# fresh report in the output directory is ambiguous, and none is credited.
stale_dir=$(make_case_dir 'stale-report')
mkdir -p "$tmp_dir/output-stale/mock-plan"
stale_report="$tmp_dir/output-stale/mock-plan/earlier-run.json"
: >"$stale_report"
touch -d '2026-01-01 00:00:00' "$stale_report"
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
export MOCK_REPORT_PATH="$stale_report"
expect_status 1 "$helper" --node node-a --cases "$stale_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-stale"
grep -Fq "was not written by this case's run" "$tmp_dir/command.out" || fail 'a report from an earlier run was credited'
foreign_dir=$(make_case_dir 'foreign-report')
foreign_report="$tmp_dir/foreign-report.json"
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
: >"$foreign_report"
export MOCK_REPORT_PATH="$foreign_report"
expect_status 1 "$helper" --node node-a --cases "$foreign_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-foreign"
grep -Fq 'not a readable regular file in the campaign output directory' "$tmp_dir/command.out" || fail 'a report outside the output directory was credited'
unset MOCK_REPORT_PATH
double_dir=$(make_case_dir 'double-saved')
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
export MOCK_DOUBLE_SAVED=1
expect_status 0 "$helper" --node node-a --cases "$double_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-double"
forged_dir=$(make_case_dir 'forged-line')
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
export MOCK_FORGED_LINE="$tmp_dir/nowhere/report.json"
expect_status 0 "$helper" --node node-a --cases "$forged_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-forged"
grep -Fq $'healthy.yaml\tpositive\tverified-pass\t0' "$(ledger_for "$tmp_dir/output-forged")" || fail 'a forged report line blocked the genuine report'
ambiguous_dir=$(make_case_dir 'ambiguous-reports')
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
export MOCK_SECOND_REPORT=1
expect_status 1 "$helper" --node node-a --cases "$ambiguous_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-ambiguous"
grep -Fq 'names more than one report written by this run' "$tmp_dir/command.out" || fail 'two fresh reports were not refused'
unset MOCK_DOUBLE_SAVED MOCK_FORGED_LINE MOCK_SECOND_REPORT

# A case is credited only for the plan bytes recorded in plans.tsv. A plan
# edited while the campaign runs is not run. The run reads a checked copy, so an
# edit to the original during a run is neither read nor credited; a copy changed
# during the run is refused, and the case keeps a rejected verdict, never an
# accepted one.
edited_dir=$(make_case_dir 'edited-plan')
printf '%s\n' 'version: v1' 'plan_id: second-plan' >"$edited_dir/second.yaml"
printf 'format=2\nallowed_nodes\tnode-a\npositive\thealthy.yaml\npositive\tsecond.yaml\n' >"$edited_dir/certistack-campaign.manifest"
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
export MOCK_EDIT_PLAN="$edited_dir/second.yaml"
expect_status 1 "$helper" --node node-a --cases "$edited_dir" --certistack "$mock_bin" --output "$tmp_dir/output-edited"
grep -Fq 'FAILED: case second.yaml changed after the campaign recorded its plan digest; it was not run.' "$tmp_dir/command.out" || fail 'an edited plan was run'
edited_ledger=$(ledger_for "$tmp_dir/output-edited")
grep -Fq $'healthy.yaml\tpositive\tverified-pass\t0' "$edited_ledger" || fail 'the unedited case was not credited'
grep -Fq $'second.yaml\tpositive\tfailed\tnot-run' "$edited_ledger" || fail 'the edited case was not recorded as not run'
self_edited_dir=$(make_case_dir 'self-edited-plan')
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
export MOCK_EDIT_PLAN="$self_edited_dir/healthy.yaml"
expect_status 0 "$helper" --node node-a --cases "$self_edited_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-self-edited"
self_edited_bundle=$(bundle_for "$tmp_dir/output-self-edited")
grep -Fq "$(sha256sum <"$self_edited_bundle/healthy.plan.yaml" | awk '{print $1}')" "$self_edited_bundle/plans.tsv" || fail 'the plan that ran is not the recorded plan'
unset MOCK_EDIT_PLAN
copy_edited_dir=$(make_case_dir 'copy-edited-plan')
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
export MOCK_EDIT_RUN_PLAN=1
expect_status 1 "$helper" --node node-a --cases "$copy_edited_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-copy-edited"
grep -Fq 'does not match the digest the campaign recorded' "$tmp_dir/command.out" || fail 'a plan copy changed during its run was credited'
copy_edited_verdict="$(bundle_for "$tmp_dir/output-copy-edited")/healthy.verification.json"
grep -Fq '"verdict":"rejected"' "$copy_edited_verdict" || fail 'a refused case did not keep a rejected verdict'
! grep -Fq 'accepted' "$copy_edited_verdict" || fail 'a refused case kept an accepted verdict'
unset MOCK_EDIT_RUN_PLAN

# --resume credits a positive case only when the ledger records that its
# run exited 0 and was credited, and its stored report is accepted again. A
# run whose report was saved clean but that then exited non-zero (removing the
# credential-bearing node workspace was not verified: exit 2) is never
# resumed as a pass, and neither is a case whose recorded attempt was not
# credited, whatever the stored report says.
resume_dir_a=$(make_case_dir 'resume-exit-2')
apply_mock 2 'Error: temporary controller material cleanup was not verified' "$(accepted_summary pass)"
expect_status 1 "$helper" --node node-a --cases "$resume_dir_a" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-resume-a"
ledger_has "$tmp_dir/output-resume-a" healthy.yaml failed 2 || fail 'the exit-2 attempt was not recorded as failed 2'
resume_log_a=$(bundle_for "$tmp_dir/output-resume-a")
expect_status 1 "$helper" --node node-a --cases "$resume_dir_a" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-resume-a" --resume "$resume_log_a"
grep -Fq 'Retrying healthy.yaml' "$tmp_dir/command.out" || fail 'a case whose run exited 2 was resumed'
! grep -Fq 'RESUMED' "$tmp_dir/command.out" || fail 'a case whose run exited 2 was resumed as a pass'
! grep -Fq $'\tresumed-verified-pass\t' "$resume_log_a/cases.tsv" || fail 'the ledger credits a resumed case whose run exited 2'
resume_dir_b=$(make_case_dir 'resume-uncredited')
apply_mock 0 'mock run complete' "$(rejected_summary pass)"
expect_status 1 "$helper" --node node-a --cases "$resume_dir_b" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-resume-b"
ledger_has "$tmp_dir/output-resume-b" healthy.yaml failed 0 || fail 'the uncredited attempt was not recorded as failed 0'
resume_log_b=$(bundle_for "$tmp_dir/output-resume-b")
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
expect_status 0 "$helper" --node node-a --cases "$resume_dir_b" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-resume-b" --resume "$resume_log_b"
grep -Fq 'Retrying healthy.yaml' "$tmp_dir/command.out" || fail 'a case whose recorded attempt was not credited was resumed on its report alone'
ledger_has "$tmp_dir/output-resume-b" healthy.yaml verified-pass 0 || fail 'the retried case was not credited by its own run'
# A credited attempt is resumed, and stays resumable when resumed again.
expect_status 0 "$helper" --node node-a --cases "$resume_dir_b" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-resume-b" --resume "$resume_log_b"
grep -Fq 'RESUMED: healthy case healthy.yaml' "$tmp_dir/command.out" || fail 'a credited attempt was not resumed'
expect_status 0 "$helper" --node node-a --cases "$resume_dir_b" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-resume-b" --resume "$resume_log_b"
grep -Fq 'RESUMED: healthy case healthy.yaml' "$tmp_dir/command.out" || fail 'a resumed case was not resumed again'

# Static plan validation is an admission gate for the whole selected campaign.
# A rejected fixture must not create a ledger or contact PVE after another case
# has already mutated the isolated lab.
invalid_plan_dir=$(make_case_dir 'invalid-plan')
apply_mock 0 'mock run should not execute' ''
export MOCK_INVALID_PLAN="$invalid_plan_dir/healthy.yaml"
expect_status 2 "$helper" --node node-a --cases "$invalid_plan_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-invalid-plan"
grep -Fq 'Campaign plan validation failed: healthy.yaml' "$tmp_dir/command.out" || fail 'invalid plan was not named'
grep -Fq 'Campaign refused before PVE contact: 1 selected plan(s) failed static validation.' "$tmp_dir/command.out" || fail 'invalid plan did not fail closed before PVE contact'
[[ ! -e "$tmp_dir/output-invalid-plan" ]] || fail 'invalid plan created campaign output before admission'
unset MOCK_INVALID_PLAN

# A release-evidence success is separately marked in its immutable campaign
# metadata, so a later reviewer can distinguish it from an ordinary lab run.
release_success_dir=$(make_case_dir 'release-evidence-success')
apply_mock 0 'mock release-evidence run complete' "$(accepted_summary pass)"
expect_status 0 "$helper" --node node-a --cases "$release_success_dir" --case healthy.yaml --certistack "$mock_bin" --keyring "$release_keyring" --release-evidence --output "$tmp_dir/output-release-evidence"
release_meta=$(find "$tmp_dir/output-release-evidence/campaign-logs" -name campaign.meta -type f -print -quit)
grep -Fxq 'format=4' "$release_meta" || fail 'release evidence did not write format 4 metadata'
grep -Fxq 'release_evidence=true' "$release_meta" || fail 'release evidence claim was not retained in metadata'
release_inventory=$(find "$tmp_dir/output-release-evidence/campaign-logs" -name plans.tsv -type f -print -quit)
grep -Eq $'^healthy.yaml\t[0-9a-f]{64}$' "$release_inventory" || fail 'release evidence did not retain the selected plan digest'

# Release evidence must be bound to a clean, reviewed controller source
# identity; a conveniently built dirty binary is never a release candidate.
dirty_release_dir=$(make_case_dir 'dirty-release-evidence')
apply_mock 0 'mock dirty release should not execute' ''
export MOCK_VERSION_LABEL='v0.1.0-dirty'
export MOCK_VERSION_COMMIT='0123456789abcdef'
expect_status 2 "$helper" --node node-a --cases "$dirty_release_dir" --case healthy.yaml --certistack "$mock_bin" --keyring "$release_keyring" --release-evidence --output "$tmp_dir/output-dirty-release"
grep -Fq -- '--release-evidence requires a clean controller build with an immutable Git commit' "$tmp_dir/command.out" || fail 'dirty controller binary was accepted for release evidence'
[[ ! -e "$tmp_dir/output-dirty-release" ]] || fail 'dirty controller binary created campaign output'
unset MOCK_VERSION_LABEL MOCK_VERSION_COMMIT

# A clean commit alone does not turn a development build into release evidence.
development_release_dir=$(make_case_dir 'development-release-evidence')
apply_mock 0 'mock development release should not execute' ''
export MOCK_VERSION_LABEL='dev'
export MOCK_VERSION_COMMIT='0123456789abcdef'
expect_status 2 "$helper" --node node-a --cases "$development_release_dir" --case healthy.yaml --certistack "$mock_bin" --keyring "$release_keyring" --release-evidence --output "$tmp_dir/output-development-release"
grep -Fq -- '--release-evidence requires a clean controller build with an immutable Git commit' "$tmp_dir/command.out" || fail 'development controller binary was accepted for release evidence'
[[ ! -e "$tmp_dir/output-development-release" ]] || fail 'development controller binary created campaign output'
unset MOCK_VERSION_LABEL MOCK_VERSION_COMMIT

# An apparently clean label is insufficient when the embedded revision is not
# a real immutable Git identity.
unknown_commit_release_dir=$(make_case_dir 'unknown-commit-release-evidence')
apply_mock 0 'mock unknown-commit release should not execute' ''
export MOCK_VERSION_LABEL='v0.1.0'
export MOCK_VERSION_COMMIT='unknown'
expect_status 2 "$helper" --node node-a --cases "$unknown_commit_release_dir" --case healthy.yaml --certistack "$mock_bin" --keyring "$release_keyring" --release-evidence --output "$tmp_dir/output-unknown-commit-release"
grep -Fq -- '--release-evidence requires a clean controller build with an immutable Git commit' "$tmp_dir/command.out" || fail 'unknown controller commit was accepted for release evidence'
[[ ! -e "$tmp_dir/output-unknown-commit-release" ]] || fail 'unknown controller commit created campaign output'
unset MOCK_VERSION_LABEL MOCK_VERSION_COMMIT

# Concurrent or rapid retries must receive distinct, atomically created
# evidence directories instead of appending to a prior campaign ledger.
apply_mock 0 'mock rapid retry' "$(accepted_summary pass)"
expect_status 0 "$helper" --node node-a --cases "$healthy_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-healthy"
[[ $(find "$tmp_dir/output-healthy/campaign-logs" -mindepth 1 -maxdepth 1 -type d | wc -l) == 2 ]] || fail 'rapid retry did not receive a separate campaign directory'

# A fault pass needs the verifier to accept the report as the fault
# plan's own injected failure; any unrelated non-zero status is rejected.
fault_dir=$(make_case_dir 'fault')
apply_mock 1 'mock injected failure' "$(accepted_summary fault)"
expect_status 0 "$helper" --node node-a --cases "$fault_dir" --mode fault --case fault-9001.yaml --certistack "$mock_bin" --output "$tmp_dir/output-fault"
grep -Fq $'fault-9001.yaml\tfault\tverified-fault-detection\t1' "$(ledger_for "$tmp_dir/output-fault")" || fail 'fault evidence was not recorded as verified'
verify_arg --expect-outcome fault || fail 'a fault case was not verified as a fault'
verify_arg --expect-plan "$(bundle_for "$tmp_dir/output-fault")/fault-9001.plan.yaml" || fail 'the fault plan copy was not the expected plan'
unrelated_fault_dir=$(make_case_dir 'unrelated-fault')
apply_mock 1 'mock unrelated failure' '{"signature_valid":true,"acceptance":{"verdict":"rejected","expected_outcome":"fault","bindings":["plan"],"reasons":["the failed probe is on VM 90010, not the fault plan'"'"'s target VM 9001"]}}'
export MOCK_VERIFY_STATUS=1
expect_status 1 "$helper" --node node-a --cases "$unrelated_fault_dir" --mode fault --case fault-9001.yaml --certistack "$mock_bin" --output "$tmp_dir/output-unrelated-fault"
grep -Fq 'does not prove exactly the expected VM/probe failure' "$tmp_dir/command.out" || fail 'unrelated fault was accepted as expected evidence'
grep -Fq 'non-zero without a failed probe report' "$tmp_dir/command.out" || fail 'unrelated fault was not recorded as a failed case'

# A fault is credited only for the status a failed validation with
# verified cleanup exits with, 1. Status 2 (cleanup of the run's credential-
# bearing material or the node's resources was not verified, or a transport
# error) and 130 (interrupted) are never fault detection, whatever the report
# says, and the verifier is not even asked.
for bad_status in 2 130 7; do
    fault_status_dir=$(make_case_dir "fault-status-$bad_status")
    apply_mock "$bad_status" 'mock failure whose cleanup was not verified' "$(accepted_summary fault)"
    expect_status 1 "$helper" --node node-a --cases "$fault_status_dir" --mode fault --case fault-9001.yaml --certistack "$mock_bin" --output "$tmp_dir/output-fault-status-$bad_status"
    grep -Fq "exited $bad_status, not the validation-failed status 1" "$tmp_dir/command.out" || fail "a fault whose run exited $bad_status was credited"
    ledger_has "$tmp_dir/output-fault-status-$bad_status" fault-9001.yaml failed "$bad_status" || fail "a fault whose run exited $bad_status was not recorded as failed"
    [[ ! -e "$MOCK_VERIFY_ARGS" ]] || fail "the verifier was asked about a fault whose run exited $bad_status"
done

# The same report is valid evidence inside a --skip-integrity campaign,
# which must ask verify-report to accept test mode and nothing else.
skip_fault_dir=$(make_case_dir 'skip-integrity-fault')
apply_mock 1 'mock skipped integrity fault' "$(accepted_summary fault)"
expect_status 0 "$helper" --node node-a --cases "$skip_fault_dir" --mode fault --case fault-9001.yaml --certistack "$mock_bin" --skip-integrity --output "$tmp_dir/output-skip-integrity-fault"
verify_arg --expect-validation-mode test_skip_integrity || fail 'a skip-integrity campaign did not expect test mode'
grep -Fxq -- '--allow-test-mode' "$MOCK_VERIFY_ARGS" || fail 'a skip-integrity campaign did not allow test mode'

# Capacity guards must prove denial before any recovery phase and retain a
# signed, clean failed report rather than treating a generic CLI error as safe.
# The controller's own report line is what the log must show.
guard_dir=$(make_case_dir 'guard')
apply_mock 1 'Error: DR validation failed: admission control guardrail triggered: admission denied: RAM usage 91.20% exceeds max 5.00%' "$(accepted_summary denied)"
expect_status 0 "$helper" --node node-a --cases "$guard_dir" --mode guard --certistack "$mock_bin" --output "$tmp_dir/output-guard"
grep -Fq $'admission-capacity-guard.yaml\tguard\tverified-guard-denial\t1' "$(ledger_for "$tmp_dir/output-guard")" || fail 'guard denial was not recorded as verified'
verify_arg --expect-outcome denied || fail 'a guard case was not verified as a denial'
verify_arg --expect-plan "$(bundle_for "$tmp_dir/output-guard")/admission-capacity-guard.plan.yaml" || fail 'the guard plan copy was not the expected plan'

# A guard denial whose report the verifier rejects is not a safe denial.
guard_rejected_dir=$(make_case_dir 'guard-rejected')
apply_mock 1 'Error: DR validation failed: admission control guardrail triggered: admission denied' '{"signature_valid":true,"acceptance":{"verdict":"rejected","expected_outcome":"denied","bindings":[],"reasons":["the report records 1 VM(s); a denied run must stop before any VM is restored"]}}'
export MOCK_VERIFY_STATUS=1
expect_status 1 "$helper" --node node-a --cases "$guard_rejected_dir" --mode guard --certistack "$mock_bin" --output "$tmp_dir/output-guard-rejected"
grep -Fq 'Guard case report does not prove a signed, clean failed validation.' "$tmp_dir/command.out" || fail 'a rejected guard report was credited'

# A guard denial is credited only for status 1, like a fault.
for bad_status in 2 130 6; do
    guard_status_dir=$(make_case_dir "guard-status-$bad_status")
    apply_mock "$bad_status" 'Error: DR validation failed: admission control guardrail triggered: admission denied' "$(accepted_summary denied)"
    expect_status 1 "$helper" --node node-a --cases "$guard_status_dir" --mode guard --certistack "$mock_bin" --output "$tmp_dir/output-guard-status-$bad_status"
    grep -Fq "exited $bad_status, not the validation-failed status 1" "$tmp_dir/command.out" || fail "a guard denial whose run exited $bad_status was credited"
    [[ ! -e "$MOCK_VERIFY_ARGS" ]] || fail "the verifier was asked about a guard whose run exited $bad_status"
done

# The engine's runtime admission denial reads "admission control guardrail
# triggered: max admission retries exceeded", and a node preflight refusal for
# memory "node preflight failed: memory: ..."; both are guard denials, in the
# controller's own report line.
guard_runtime_dir=$(make_case_dir 'guard-runtime')
apply_mock 1 'Error: DR validation failed: admission control guardrail triggered: max admission retries exceeded' "$(accepted_summary denied)"
expect_status 0 "$helper" --node node-a --cases "$guard_runtime_dir" --mode guard --certistack "$mock_bin" --output "$tmp_dir/output-guard-runtime"
guard_preflight_dir=$(make_case_dir 'guard-preflight')
apply_mock 1 '[00:00:12] ERROR Report saved at /reports/admission-capacity-guard/r.json; validation failed: node preflight failed: memory: the plan can never be admitted on this node: its sandbox VMs reserve 200 GiB of memory' "$(accepted_summary denied)"
expect_status 0 "$helper" --node node-a --cases "$guard_preflight_dir" --mode guard --certistack "$mock_bin" --output "$tmp_dir/output-guard-preflight"

# The log is only a second opinion, and text a plan controls cannot
# satisfy it. A run that began "Starting DR validation plan "admission denied
# guard"" and failed for another reason shows no capacity denial in the
# controller's own lines, so it is refused even when the verifier's verdict
# says otherwise; the refusal is kept as the case's verdict.
guard_plan_text_dir=$(make_case_dir 'guard-plan-text')
apply_mock 1 $'[00:00:10] INFO Starting DR validation plan "admission control guardrail triggered: node preflight failed: memory:" with 1 recovery tier(s).\n[00:00:12] ERROR Report saved at /reports/x.json; validation failed: SDN sandbox setup failed: create zone csSb01: 500 zone already exists\nError: DR validation failed: SDN sandbox setup failed: create zone csSb01: 500 zone already exists' "$(accepted_summary denied)"
expect_status 1 "$helper" --node node-a --cases "$guard_plan_text_dir" --mode guard --certistack "$mock_bin" --output "$tmp_dir/output-guard-plan-text"
grep -Fq 'Guard case did not show a recognized capacity denial.' "$tmp_dir/command.out" || fail 'plan text satisfied the guard log check'
grep -Fq '"verdict":"rejected"' "$(bundle_for "$tmp_dir/output-guard-plan-text")/admission-capacity-guard.verification.json" || fail 'a refused guard did not keep a rejected verdict'

# ---------------------------------------------------------------------------
# Unsigned reports, the Community Edition's. The campaign says so with
# --unsigned; the verifier is then asked with --unsigned and the same --expect-*
# flags, never with --keyring, and the verifier's verdict still decides. The two
# options exclude each other and one of them is required.
# ---------------------------------------------------------------------------
unsigned_dir=$(make_case_dir 'unsigned-healthy')
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
expect_status 0 "$helper" --node node-a --cases "$unsigned_dir" --case healthy.yaml --certistack "$mock_bin" --unsigned --output "$tmp_dir/output-unsigned-healthy"
unsigned_bundle=$(bundle_for "$tmp_dir/output-unsigned-healthy")
grep -Fxq -- '--unsigned' "$MOCK_VERIFY_ARGS" || fail 'an unsigned campaign did not ask the verifier for --unsigned'
! grep -Fxq -- '--keyring' "$MOCK_VERIFY_ARGS" || fail 'an unsigned campaign pinned a keyring'
verify_arg --expect-plan "$unsigned_bundle/healthy.plan.yaml" || fail 'an unsigned campaign did not expect the checked plan copy'
verify_arg --expect-node node-a || fail 'an unsigned campaign did not expect the requested node'
verify_arg --expect-version v0.1.0 || fail 'an unsigned campaign did not expect the binary version'
verify_arg --expect-commit 0123456789abcdef || fail 'an unsigned campaign did not expect the binary commit'
verify_arg --expect-build-date 2026-09-29T00:00:00Z || fail 'an unsigned campaign did not expect the binary build date'
verify_arg --expect-worker-sha256 "$(sha256sum <"$mock_bin" | awk '{print $1}')" || fail 'an unsigned campaign did not expect the executable digest'
verify_arg --expect-validation-mode full_integrity || fail 'an unsigned campaign did not expect the validation mode'
verify_arg --expect-outcome pass || fail 'an unsigned campaign did not verify a healthy case as a pass'
[[ $(tail -n 1 "$MOCK_VERIFY_ARGS") == "$unsigned_bundle/healthy.report.json" ]] || fail 'the unsigned verifier did not read the kept copy of the report'
grep -Fq $'healthy.yaml\tpositive\tverified-pass\t0' "$(ledger_for "$tmp_dir/output-unsigned-healthy")" || fail 'unsigned healthy evidence was not recorded as verified'
grep -Fxq 'keyring_identity=unsigned' "$unsigned_bundle/campaign.meta" || fail 'the campaign metadata does not say the reports were judged as unsigned'
grep -Fq 'UNSIGNED: the reports are the run' "$tmp_dir/command.out" || fail 'an unsigned campaign did not say its reports are not authenticated'
grep -Fq 'PASS: healthy case healthy.yaml completed with unsigned cleanup evidence.' "$tmp_dir/command.out" || fail 'an unsigned pass was not named as unsigned'
! grep -Eq '(^|[^n])signed cleanup evidence' "$tmp_dir/command.out" || fail 'an unsigned pass claimed signed evidence'

# The two ways of judging reports exclude each other, and one is required.
both_dir=$(make_case_dir 'unsigned-and-keyring')
apply_mock 0 'mock run should not execute' ''
expect_status 2 "$helper" --node node-a --cases "$both_dir" --case healthy.yaml --certistack "$mock_bin" --unsigned --keyring "$campaign_keyring" --output "$tmp_dir/output-both"
grep -Fq -- '--unsigned and --keyring contradict each other' "$tmp_dir/command.out" || fail '--unsigned with --keyring was not refused clearly'
[[ ! -e "$tmp_dir/output-both" ]] || fail '--unsigned with --keyring created campaign output'
neither_dir=$(make_case_dir 'neither-unsigned-nor-keyring')
set +e
"$helper" --node node-a --cases "$neither_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-neither" </dev/null >"$tmp_dir/command.out" 2>&1
neither_status=$?
set -e
[[ "$neither_status" == 2 ]] || fail "a campaign with neither --keyring nor --unsigned exit = $neither_status, want 2"
grep -Fq -- 'unless --unsigned says the reports are unsigned' "$tmp_dir/command.out" || fail 'the refusal of a campaign with neither option does not name --unsigned'
[[ ! -e "$tmp_dir/output-neither" ]] || fail 'a campaign with neither option created output'

# Release evidence may run unsigned (the Community Edition's reports), and is marked so in its metadata; --list-cases needs neither option.
expect_status 0 "$helper" --node node-a --cases "$release_dir" --release-evidence --unsigned --list-cases
apply_mock 0 'mock release-evidence run complete' "$(accepted_summary pass)"
unsigned_release_dir=$(make_case_dir 'unsigned-release-evidence')
expect_status 0 "$helper" --node node-a --cases "$unsigned_release_dir" --case healthy.yaml --certistack "$mock_bin" --unsigned --release-evidence --output "$tmp_dir/output-unsigned-release"
unsigned_release_meta=$(find "$tmp_dir/output-unsigned-release/campaign-logs" -name campaign.meta -type f -print -quit)
grep -Fxq 'release_evidence=true' "$unsigned_release_meta" && grep -Fxq 'keyring_identity=unsigned' "$unsigned_release_meta" || fail 'unsigned release evidence is not marked in its metadata'
grep -Fq 'Release-evidence mode: reports are judged as unsigned' "$tmp_dir/command.out" || fail 'unsigned release evidence did not say how its reports are judged'
verify_arg --expect-validation-mode full_integrity || fail 'unsigned release evidence did not expect full integrity'

# The verifier's verdict decides, unsigned as signed: a rejected verdict, or a failing exit status, is never credited.
unsigned_rejected_dir=$(make_case_dir 'unsigned-rejected')
apply_mock 0 'mock run complete' "$(rejected_summary pass)"
expect_status 1 "$helper" --node node-a --cases "$unsigned_rejected_dir" --case healthy.yaml --certistack "$mock_bin" --unsigned --output "$tmp_dir/output-unsigned-rejected"
grep -Fq 'The unsigned report was not accepted as pass evidence' "$tmp_dir/command.out" || fail 'a rejected unsigned report was credited'
ledger_has "$tmp_dir/output-unsigned-rejected" healthy.yaml failed 0 || fail 'a rejected unsigned report was not recorded as failed'
unsigned_status_dir=$(make_case_dir 'unsigned-verifier-status')
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
export MOCK_VERIFY_STATUS=2
expect_status 1 "$helper" --node node-a --cases "$unsigned_status_dir" --case healthy.yaml --certistack "$mock_bin" --unsigned --output "$tmp_dir/output-unsigned-status"
grep -Fq 'verify-report exit 2' "$tmp_dir/command.out" || fail 'a verifier that refused an unsigned report (exit 2) was credited'
grep -Fq '"verdict":"rejected"' "$(bundle_for "$tmp_dir/output-unsigned-status")/healthy.verification.json" || fail 'the refusal of an unsigned report was not kept as a rejected verdict'
unsigned_unbound_dir=$(make_case_dir 'unsigned-unbound')
apply_mock 0 'mock run complete' "$(unbound_summary pass '["plan","probe_policy","rto_objective","admission_policy","node","build","validation_mode","NOT BOUND: plan digest (the report carries no plan_sha256)"]')"
expect_status 1 "$helper" --node node-a --cases "$unsigned_unbound_dir" --case healthy.yaml --certistack "$mock_bin" --unsigned --output "$tmp_dir/output-unsigned-unbound"
grep -Fq 'not bound' "$tmp_dir/command.out" || fail 'an unsigned report accepted without everything bound was credited'

# Faults and guards, unsigned.
unsigned_fault_dir=$(make_case_dir 'unsigned-fault')
apply_mock 1 'mock detected fault' "$(accepted_summary fault)"
expect_status 0 "$helper" --node node-a --cases "$unsigned_fault_dir" --mode fault --case fault-9001.yaml --certistack "$mock_bin" --unsigned --output "$tmp_dir/output-unsigned-fault"
grep -Fq 'PASS: fault case fault-9001.yaml produced an unsigned failed-probe report.' "$tmp_dir/command.out" || fail 'an unsigned fault was not named as unsigned'
verify_arg --expect-outcome fault || fail 'an unsigned fault case was not verified as a fault'
grep -Fxq -- '--unsigned' "$MOCK_VERIFY_ARGS" || fail 'an unsigned fault campaign did not ask for --unsigned'
unsigned_guard_dir=$(make_case_dir 'unsigned-guard')
apply_mock 1 'Error: DR validation failed: admission control guardrail triggered: admission denied' "$(accepted_summary denied)"
expect_status 0 "$helper" --node node-a --cases "$unsigned_guard_dir" --mode guard --certistack "$mock_bin" --unsigned --output "$tmp_dir/output-unsigned-guard"
verify_arg --expect-outcome denied || fail 'an unsigned guard case was not verified as a denial'
unsigned_guard_rejected_dir=$(make_case_dir 'unsigned-guard-rejected')
apply_mock 1 'Error: DR validation failed: admission control guardrail triggered: admission denied' "$(rejected_summary denied)"
export MOCK_VERIFY_STATUS=1
expect_status 1 "$helper" --node node-a --cases "$unsigned_guard_rejected_dir" --mode guard --certistack "$mock_bin" --unsigned --output "$tmp_dir/output-unsigned-guard-rejected"
grep -Fq 'Guard case report does not prove an unsigned, clean failed validation.' "$tmp_dir/command.out" || fail 'a rejected unsigned guard report was credited or mislabelled'

# A verifier that cannot judge unsigned reports is refused before any output, but is fine for a keyring campaign.
no_unsigned_dir=$(make_case_dir 'verifier-without-unsigned')
apply_mock 0 'mock verifier without --unsigned should not execute' ''
export MOCK_VERIFY_NO_UNSIGNED=1
expect_status 2 "$helper" --node node-a --cases "$no_unsigned_dir" --case healthy.yaml --certistack "$mock_bin" --unsigned --output "$tmp_dir/output-no-unsigned"
grep -Fq 'cannot judge unsigned reports' "$tmp_dir/command.out" || fail 'a verifier without --unsigned was accepted for an unsigned campaign'
[[ ! -e "$tmp_dir/output-no-unsigned" ]] || fail 'a verifier without --unsigned created campaign output'
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
export MOCK_VERIFY_NO_UNSIGNED=1
expect_status 0 "$helper" --node node-a --cases "$no_unsigned_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-keyring-old-verifier"
unset MOCK_VERIFY_NO_UNSIGNED

# Resume applies the way reports are judged. A campaign judged unsigned is
# resumed unsigned (and then skips what it credited), and never with a keyring;
# one judged against a keyring is never resumed unsigned.
resume_unsigned_dir=$(make_case_dir 'resume-unsigned')
apply_mock 0 'mock run complete' "$(accepted_summary pass)"
expect_status 0 "$helper" --node node-a --cases "$resume_unsigned_dir" --case healthy.yaml --certistack "$mock_bin" --unsigned --output "$tmp_dir/output-resume-unsigned"
resume_unsigned_log=$(bundle_for "$tmp_dir/output-resume-unsigned")
expect_status 0 "$helper" --node node-a --cases "$resume_unsigned_dir" --case healthy.yaml --certistack "$mock_bin" --unsigned --output "$tmp_dir/output-resume-unsigned" --resume "$resume_unsigned_log"
grep -Fq 'RESUMED: healthy case healthy.yaml has matching unsigned pass and cleanup evidence.' "$tmp_dir/command.out" || fail 'an accepted unsigned report was not resumed'
grep -Fq 'Resume mode: only cases with matching build, unsigned-report mode' "$tmp_dir/command.out" || fail 'the unsigned resume banner is missing'
expect_status 1 "$helper" --node node-a --cases "$resume_unsigned_dir" --case healthy.yaml --certistack "$mock_bin" --keyring "$campaign_keyring" --output "$tmp_dir/output-resume-unsigned" --resume "$resume_unsigned_log"
grep -Fq 'Campaign resume metadata does not match' "$tmp_dir/command.out" || fail 'a campaign judged unsigned was resumed against a keyring'
resume_keyring_dir=$(make_case_dir 'resume-keyring-then-unsigned')
expect_status 0 "$helper" --node node-a --cases "$resume_keyring_dir" --case healthy.yaml --certistack "$mock_bin" --output "$tmp_dir/output-resume-keyring"
resume_keyring_log=$(bundle_for "$tmp_dir/output-resume-keyring")
expect_status 1 "$helper" --node node-a --cases "$resume_keyring_dir" --case healthy.yaml --certistack "$mock_bin" --unsigned --output "$tmp_dir/output-resume-keyring" --resume "$resume_keyring_log"
grep -Fq 'Campaign resume metadata does not match' "$tmp_dir/command.out" || fail 'a campaign judged against a keyring was resumed as unsigned'

# ---------------------------------------------------------------------------
# The real verifier. Build the CLI with the fixture identity that
# cmd/certistack/verify_acceptance_test.go signs into its campaign fixtures,
# write those signed fixtures, and run the helper against each one. A wrapper
# forwards version, validate, and verify-report to the real CLI; its `run`
# only saves the selected fixture as the controller would.
# ---------------------------------------------------------------------------
command -v go >/dev/null 2>&1 || fail 'Go is required to build the real verifier for the campaign evidence tests'
fixture_version='v0.1.0-campaign-fixture'
fixture_commit='0123456789ab'
fixture_built='2026-09-29T00:00:00Z'
real_bin="$tmp_dir/certistack-real"
(cd "$repo_dir" && go build -trimpath -ldflags "-X main.version=$fixture_version -X main.commit=$fixture_commit -X main.buildDate=$fixture_built" -o "$real_bin" ./cmd/certistack) ||
    fail 'could not build the CertiStack CLI'
evidence_wrapper="$tmp_dir/certistack-evidence"
cat >"$evidence_wrapper" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  version|validate|verify-report) exec "$EVIDENCE_REAL_CERTISTACK" "$@" ;;
  run)
    output="" previous=""
    for argument in "$@"; do
      if [[ "$previous" == "--output" ]]; then output="$argument"; fi
      previous="$argument"
    done
    mkdir -p "$output/acme-erp-full-stack-dr"
    sleep 0.05
    report=$(mktemp "$output/acme-erp-full-stack-dr/report.XXXXXX")
    cat "$EVIDENCE_FIXTURE" >"$report"
    # The controller's own lines, in its order: a progress line whose text
    # includes the plan ID, the failure it reports, the saved-report line, and
    # the command's error.
    printf '[00:00:10] INFO Starting DR validation plan "acme-erp-full-stack-dr" with 3 recovery tier(s).\n' >&2
    if [[ -n "${EVIDENCE_ERROR:-}" ]]; then
      printf '[00:00:12] ERROR Report saved at %s; validation failed: %s\n' "$report" "$EVIDENCE_ERROR" >&2
    fi
    printf '✓ Controller report saved to: %s\n' "$report"
    if [[ -n "${EVIDENCE_ERROR:-}" ]]; then
      printf 'Error: DR validation failed: %s\n' "$EVIDENCE_ERROR" >&2
    fi
    exit "$EVIDENCE_RUN_STATUS"
    ;;
  *) exit 64 ;;
esac
WRAPPER
chmod 0700 "$evidence_wrapper"
export EVIDENCE_REAL_CERTISTACK="$real_bin"

# The helper binds every report to the digest of the file it runs. A real
# controller signs the digest of its own executable into the report
# (worker_sha256); here the wrapper stands for that executable, so the fixtures
# sign the wrapper's digest.
evidence_digest=$(sha256sum <"$evidence_wrapper" | awk '{print $1}')
fixtures="$tmp_dir/fixtures"
mkdir -p "$fixtures"
if ! (cd "$repo_dir" && CERTISTACK_CAMPAIGN_WORKER_SHA256="$evidence_digest" CERTISTACK_CAMPAIGN_FIXTURES="$fixtures" go test -count=1 -run '^TestWriteCampaignEvidenceFixtures$' ./cmd/certistack) >"$tmp_dir/fixtures.out" 2>&1 ||
    [[ ! -s "$fixtures/fixtures.tsv" ]]; then
    sed 's/^/  /' "$tmp_dir/fixtures.out" >&2
    fail 'could not write the signed campaign fixtures'
fi

# The reporter's selected plan requests VMs 9001, 9002 and 9003 with 3, 2 and 3
# probes; the fault plan is the same plan, so its target is VM 9001's first
# probe (tcp "LDAP TCP handshake on domain controller"), and the guard plan is
# the same plan refused before any VM restored.
evidence_cases="$tmp_dir/evidence-cases"
mkdir -p "$evidence_cases"
cp "$repo_dir/testdata/plans/valid_plan.yaml" "$evidence_cases/healthy.yaml"
cp "$repo_dir/testdata/plans/valid_plan.yaml" "$evidence_cases/fault-9001.yaml"
cp "$repo_dir/testdata/plans/valid_plan.yaml" "$evidence_cases/admission-denied-guard.yaml"
printf 'format=2\nallowed_nodes\tnode-a\npositive\thealthy.yaml\nfault\tfault-9001.yaml\n' >"$evidence_cases/certistack-campaign.manifest"

# run_evidence_case NAME OUTPUT WANT MODE [helper options...] runs one fixture
# through the helper in its campaign mode (positive, fault or guard) and
# requires exit status WANT. The fake run exits with the status a real one
# gives the mode (0, and 1 for a failed validation with verified cleanup),
# unless EVIDENCE_STATUS names another; EVIDENCE_ERROR is the failure the run
# prints.
run_evidence_case() {
    local name="$1" output="$2" want="$3" mode="$4"
    shift 4
    local case_file=healthy.yaml run_status=0
    case "$mode" in
        fault) case_file=fault-9001.yaml run_status=1 ;;
        guard) case_file=admission-denied-guard.yaml run_status=1 ;;
    esac
    # EVIDENCE_UNSIGNED=1 runs the same fixtures stripped of their signature
    # members (the Community Edition's reports) through --unsigned.
    local fixture_dir="$fixtures" trust_args=(--keyring "$fixtures/trusted.pub")
    if [[ "${EVIDENCE_UNSIGNED:-}" == 1 ]]; then
        fixture_dir="$unsigned_fixtures" trust_args=(--unsigned)
    fi
    export EVIDENCE_FIXTURE="$fixture_dir/$name.json" EVIDENCE_RUN_STATUS="${EVIDENCE_STATUS:-$run_status}"
    expect_status "$want" "$helper" --node node-a --mode "$mode" --cases "$evidence_cases" --case "$case_file" \
        --certistack "$evidence_wrapper" "${trust_args[@]}" --output "$output" "$@"
}

# The reporter's thirteen campaign fixtures and further cases, each through the
# unmodified helper flow and the real verifier, in a release-evidence campaign.
# The fixture index says which the helper must accept.
fixture_count=0
while IFS=$'\t' read -r name mode verdict integrity reason; do
    fixture_count=$((fixture_count + 1))
    output="$tmp_dir/evidence-$name"
    want_status=1 want_outcome=failed
    if [[ "$verdict" == accept ]]; then
        want_status=0 want_outcome=verified-pass
        [[ "$mode" == fault ]] && want_outcome=verified-fault-detection
        [[ "$mode" == guard ]] && want_outcome=verified-guard-denial
    fi
    EVIDENCE_ERROR="$reason" run_evidence_case "$name" "$output" "$want_status" "$mode" --release-evidence
    grep -Fq $'\t'"$mode"$'\t'"$want_outcome"$'\t' "$(ledger_for "$output")" || fail "$name was not recorded as $want_outcome"
    verification=$(find "$output/campaign-logs" -name '*.verification.json' -print -quit)
    if [[ "$verdict" == accept ]]; then
        grep -Fq '"acceptance":{"verdict":"accepted"' "$verification" || fail "$name verdict was not retained as accepted"
    elif [[ "$name" == untrusted_control ]]; then
        grep -Fq 'untrusted signer' "$tmp_dir/command.out" || fail 'an untrusted signer was not reported'
        grep -Fq '"verdict":"rejected"' "$verification" || fail 'an untrusted signer left no rejected verdict'
    else
        grep -Fq '"verdict":"rejected"' "$verification" || fail "$name verdict was not retained as rejected"
    fi
    if [[ "$integrity" == test ]]; then
        # A test-mode report is lab evidence only inside a --skip-integrity
        # campaign, never in a release-evidence one.
        EVIDENCE_ERROR="$reason" run_evidence_case "$name" "$output-skip" 0 "$mode" --skip-integrity
        grep -Fq $'\t'"$mode"$'\tverified-pass\t' "$(ledger_for "$output-skip")" || fail "$name was not accepted in a test-mode campaign"
    fi
done <"$fixtures/fixtures.tsv"
((fixture_count >= 13)) || fail "only $fixture_count campaign fixtures were written"

# The reporter's reproduction. A failure on VM 90010 is not the expected
# VM 9001's failure; the verdict names both VMs as integers.
grep -Fq "the failed probe is on VM 90010, not the fault plan's target VM 9001" \
    "$(find "$tmp_dir/evidence-fault_vmid_prefix/campaign-logs" -name '*.verification.json' -print -quit)" ||
    fail 'the VM 90010 fault was not rejected for its VM'
# Wrong build and wrong node are rejected for exactly that reason.
grep -Fq 'the report was produced by CertiStack version \"v0.0.9\", not the expected \"v0.1.0-campaign-fixture\"' \
    "$(find "$tmp_dir/evidence-wrong_build/campaign-logs" -name '*.verification.json' -print -quit)" ||
    fail 'the wrong build was not named'
grep -Fq 'the report was produced on node \"unrequested-node\", not the expected node \"node-a\"' \
    "$(find "$tmp_dir/evidence-wrong_node/campaign-logs" -name '*.verification.json' -print -quit)" ||
    fail 'the wrong node was not named'
# The reporter's reproduction. A guard plan whose run failed on SDN
# setup, with a plan ID that reads like a denial, is not a capacity denial: the
# log shows none, and, when the log is made to claim one, the signed failure
# reason still decides.
grep -Fq 'Guard case did not show a recognized capacity denial.' \
    "$(find "$tmp_dir/evidence-guard_sdn_failure/campaign-logs" -name '*.verification.json' -print -quit)" ||
    fail 'a guard plan that failed on SDN setup was credited as a denial'
EVIDENCE_ERROR='admission control guardrail triggered: max admission retries exceeded' run_evidence_case guard_sdn_failure "$tmp_dir/evidence-guard-log-lies" 1 guard --release-evidence
grep -Fq 'the failure reason is not an admission or preflight capacity denial' \
    "$(find "$tmp_dir/evidence-guard-log-lies/campaign-logs" -name '*.verification.json' -print -quit)" ||
    fail 'a log that claims a capacity denial outweighed the signed failure reason'
# The probe target, the boot disk, the duplicate slot and a newer schema are
# each named.
for named in \
    'probe_target_mismatch|targeted' \
    'duplicate_disk_slot|more than once' \
    'boot_disk_without_evidence|has no integrity evidence' \
    'schema_newer_minor|newer than this verifier understands'; do
    grep -Fq "${named#*|}" "$(find "$tmp_dir/evidence-${named%%|*}/campaign-logs" -name '*.verification.json' -print -quit)" ||
        fail "${named%%|*} was not rejected for its reason"
done

admission_reason='admission control guardrail triggered: max admission retries exceeded'
# Through the real verifier, a run that exited with any status but the
# one its mode needs is never credited, however good its report.
for status in 2 130; do
    EVIDENCE_STATUS="$status" run_evidence_case matching_control "$tmp_dir/evidence-positive-status-$status" 1 positive --release-evidence
    ledger_has "$tmp_dir/evidence-positive-status-$status" healthy.yaml failed "$status" || fail "a healthy run that exited $status was credited"
    EVIDENCE_STATUS="$status" run_evidence_case fault_exact_control "$tmp_dir/evidence-fault-status-$status" 1 fault --release-evidence
    grep -Fq "exited $status, not the validation-failed status 1" "$tmp_dir/command.out" || fail "a fault run that exited $status was credited"
    EVIDENCE_STATUS="$status" EVIDENCE_ERROR="$admission_reason" run_evidence_case guard_admission_control "$tmp_dir/evidence-guard-status-$status" 1 guard --release-evidence
    grep -Fq "exited $status, not the validation-failed status 1" "$tmp_dir/command.out" || fail "a guard run that exited $status was credited"
done

# The reporter's reproduction R: the run exited 2 after saving a clean
# signed report (its credential-bearing workspace was not verified removed).
# The retry would still fail if the helper really re-ran the case.
reviewer_output="$tmp_dir/evidence-reviewer-r"
EVIDENCE_STATUS=2 EVIDENCE_ERROR='temporary controller material cleanup was not verified' run_evidence_case matching_control "$reviewer_output" 1 positive --release-evidence
reviewer_log=$(bundle_for "$reviewer_output")
ledger_has "$reviewer_output" healthy.yaml failed 2 || fail 'the exit-2 attempt was not recorded as failed 2'
EVIDENCE_STATUS=2 run_evidence_case matching_control "$reviewer_output" 1 positive --release-evidence --resume "$reviewer_log"
grep -Fq 'Retrying healthy.yaml' "$tmp_dir/command.out" || fail 'a run that exited 2 was resumed'
! grep -Fq $'\tresumed-verified-pass\t' "$reviewer_log/cases.tsv" || fail 'a run that exited 2 was credited on resume'

# Resume applies the same acceptance. A stored report from the wrong
# build is not resumed as a pass; the case runs again, and once its report is
# accepted a later resume skips it.
resume_output="$tmp_dir/evidence-resume"
run_evidence_case wrong_build "$resume_output" 1 positive --release-evidence
resume_log=$(find "$resume_output/campaign-logs" -mindepth 1 -maxdepth 1 -type d -print -quit)
run_evidence_case matching_control "$resume_output" 0 positive --release-evidence --resume "$resume_log"
grep -Fq 'Retrying healthy.yaml: no matching signed pass-and-cleanup evidence was found.' "$tmp_dir/command.out" || fail 'a wrong-build report was resumed as a pass'
grep -Fq $'healthy.yaml\tpositive\tverified-pass\t0' "$resume_log/cases.tsv" || fail 'the retried case was not credited'
run_evidence_case wrong_node "$resume_output" 0 positive --release-evidence --resume "$resume_log"
grep -Fq 'RESUMED: healthy case healthy.yaml has matching signed pass and cleanup evidence.' "$tmp_dir/command.out" || fail 'an accepted report was not resumed'

# The signed worker digest binds the bytes, not the labels. The same accepted
# fixture, run through an executable that differs from the signed one by a
# comment (so the same version, commit and build date), is refused for its
# executable.
other_wrapper="$tmp_dir/certistack-evidence-other"
{ cat "$evidence_wrapper"; printf '# a different executable\n'; } >"$other_wrapper"
chmod 0700 "$other_wrapper"
other_output="$tmp_dir/evidence-other-executable"
export EVIDENCE_FIXTURE="$fixtures/matching_control.json" EVIDENCE_RUN_STATUS=0
expect_status 1 "$helper" --node node-a --mode positive --cases "$evidence_cases" --case healthy.yaml \
    --certistack "$other_wrapper" --keyring "$fixtures/trusted.pub" --output "$other_output" --release-evidence
grep -Fq 'was produced by executable' \
    "$(find "$other_output/campaign-logs" -name '*.verification.json' -print -quit)" ||
    fail 'a report from another executable than the signed one was credited'
ledger_has "$other_output" healthy.yaml failed 0 || fail 'a report from another executable was recorded as a verified pass'

# Through the real verifier: the three unbound fixtures are accepted by
# verify-report on what they record (an earlier schema, no plan digest) and
# their verdicts list NOT BOUND; the loop above showed the helper refuses to
# credit each. Their verdicts are the verifier's own, not a helper rule.
for unbound in unbound_older_schema unbound_no_plan_digest unbound_fault_older_schema; do
    grep -Fq "$unbound" "$fixtures/fixtures.tsv" || fail "the fixture $unbound was not written"
    kept=$(find "$tmp_dir/evidence-$unbound/campaign-logs" -name '*.verification.unbound.json' -print -quit)
    [[ -n "$kept" ]] || fail "the verifier's own verdict for $unbound was not kept"
    grep -Fq '"verdict":"accepted"' "$kept" || fail "the verifier did not accept $unbound on what it records"
    grep -Fq 'NOT BOUND:' "$kept" || fail "the verifier did not list a NOT BOUND entry for $unbound"
done

# ---------------------------------------------------------------------------
# The same fixtures as the Community Edition writes its reports: the signature
# members removed (the document is otherwise the same), judged by the real
# verifier's --unsigned with the same acceptance rules. Only a verifier that has
# --unsigned can run this; an older one is named in the closing line rather
# than skipped in silence.
# ---------------------------------------------------------------------------
unsigned_note=''
# Read the help into a variable first: under pipefail, grep -q closing the pipe early makes a producer with long output (SIGPIPE) look like a failure.
real_verify_help=$("$real_bin" verify-report --help 2>/dev/null || true)
if grep -Fq -- '--unsigned' <<<"$real_verify_help"; then
    command -v python3 >/dev/null 2>&1 || fail 'python3 is needed to strip the campaign fixtures of their signatures'
    unsigned_fixtures="$tmp_dir/unsigned-fixtures"
    mkdir -p "$unsigned_fixtures"
    python3 - "$fixtures" "$unsigned_fixtures" <<'STRIP'
import json, os, sys
source, target = sys.argv[1], sys.argv[2]
for name in sorted(os.listdir(source)):
    if name.endswith(".json"):
        with open(os.path.join(source, name), encoding="utf-8") as fh:
            report = json.load(fh)
        for member in ("signature", "public_key", "signer_fingerprint", "signature_timestamp"):
            report.pop(member, None)
        with open(os.path.join(target, name), "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
            fh.write("\n")
STRIP
    unsigned_count=0
    while IFS=$'\t' read -r name mode verdict integrity reason; do
        unsigned_count=$((unsigned_count + 1))
        output="$tmp_dir/unsigned-evidence-$name"
        # A report signed by a key nobody trusts has no signer to distrust once its signature members are gone: the unsigned rules judge its contents.
        [[ "$name" == untrusted_control ]] && verdict=accept
        want_status=1 want_outcome=failed
        if [[ "$verdict" == accept ]]; then
            want_status=0 want_outcome=verified-pass
            [[ "$mode" == fault ]] && want_outcome=verified-fault-detection
            [[ "$mode" == guard ]] && want_outcome=verified-guard-denial
        fi
        EVIDENCE_UNSIGNED=1 EVIDENCE_ERROR="$reason" run_evidence_case "$name" "$output" "$want_status" "$mode" --release-evidence
        grep -Fq $'\t'"$mode"$'\t'"$want_outcome"$'\t' "$(ledger_for "$output")" || fail "unsigned $name was not recorded as $want_outcome"
        verification=$(find "$output/campaign-logs" -name '*.verification.json' -print -quit)
        if [[ "$verdict" == accept ]]; then
            grep -Fq '"acceptance":{"verdict":"accepted"' "$verification" || fail "unsigned $name verdict was not retained as accepted"
        else
            grep -Fq '"verdict":"rejected"' "$verification" || fail "unsigned $name verdict was not retained as rejected"
        fi
        if [[ "$integrity" == test ]]; then
            EVIDENCE_UNSIGNED=1 EVIDENCE_ERROR="$reason" run_evidence_case "$name" "$output-skip" 0 "$mode" --skip-integrity
            grep -Fq $'\t'"$mode"$'\tverified-pass\t' "$(ledger_for "$output-skip")" || fail "unsigned $name was not accepted in a test-mode campaign"
        fi
    done <"$fixtures/fixtures.tsv"
    ((unsigned_count >= 13)) || fail "only $unsigned_count unsigned campaign fixtures were run"
    # The same acceptance rules name the same reasons.
    grep -Fq "the failed probe is on VM 90010, not the fault plan's target VM 9001" \
        "$(find "$tmp_dir/unsigned-evidence-fault_vmid_prefix/campaign-logs" -name '*.verification.json' -print -quit)" ||
        fail 'the unsigned VM 90010 fault was not rejected for its VM'
    grep -Fq 'the report was produced on node \"unrequested-node\", not the expected node \"node-a\"' \
        "$(find "$tmp_dir/unsigned-evidence-wrong_node/campaign-logs" -name '*.verification.json' -print -quit)" ||
        fail 'the unsigned wrong node was not named'
    # A signed report is refused when the campaign says its reports are unsigned, and an unsigned one when it pins a keyring: the verifier's
    # refusal, never a credit.
    export EVIDENCE_FIXTURE="$fixtures/matching_control.json" EVIDENCE_RUN_STATUS=0
    expect_status 1 "$helper" --node node-a --mode positive --cases "$evidence_cases" --case healthy.yaml \
        --certistack "$evidence_wrapper" --unsigned --output "$tmp_dir/unsigned-evidence-signed-report" --release-evidence
    ledger_has "$tmp_dir/unsigned-evidence-signed-report" healthy.yaml failed 0 || fail 'a signed report was credited by an unsigned campaign'
    grep -Fq '"verdict":"rejected"' "$(find "$tmp_dir/unsigned-evidence-signed-report/campaign-logs" -name '*.verification.json' -print -quit)" ||
        fail 'a signed report in an unsigned campaign left no rejected verdict'
    export EVIDENCE_FIXTURE="$unsigned_fixtures/matching_control.json" EVIDENCE_RUN_STATUS=0
    expect_status 1 "$helper" --node node-a --mode positive --cases "$evidence_cases" --case healthy.yaml \
        --certistack "$evidence_wrapper" --keyring "$fixtures/trusted.pub" --output "$tmp_dir/keyring-evidence-unsigned-report" --release-evidence
    ledger_has "$tmp_dir/keyring-evidence-unsigned-report" healthy.yaml failed 0 || fail 'an unsigned report was credited by a keyring campaign'
else
    unsigned_note=' (the scenarios through the real verifier'"'"'s --unsigned were NOT run: this CLI'"'"'s verify-report has no --unsigned yet)'
fi

printf 'run-lab-campaign helper tests passed%s\n' "$unsigned_note"
