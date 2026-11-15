#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
# Execute an ordered CertiStack lab campaign from a management controller.
#
# The controller launches its temporary worker on the selected PVE node. The
# reports it leaves are the Community Edition's, which are unsigned, or the
# Enterprise Edition's, which are signed: see --unsigned and --keyring. This
# script never injects faults, deletes artifacts, or performs
# heuristic cleanup. The "positive" suite expects every case to pass and
# completes the selected matrix to give an honest completion ratio. The "fault"
# suite expects every case to fail only after the operator has injected its
# matching fault; expected failures are reported as successful fault-detection
# tests.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  run-lab-campaign.sh --node PVE_NODE [options]

Required:
  --node NODE             PVE node on which CertiStack creates its temporary worker.

Options:
  --mode MODE             positive (default), fault, or guard.
  --cases DIR             Generated case directory (default: .lab/cases).
  --case FILE             Run one named plan instead of the suite.
  --certistack PATH       CertiStack executable (default: certistack). It must be the
                          executable itself, not a wrapper script: every accepted
                          report must carry this file's SHA-256 as its worker digest.
  --env FILE              Allowlisted controller environment file; parsed as literals.
  --keyring FILE          Trusted signer keyring for report verification and resume decisions
                          (reports signed by the Enterprise Edition).
  --unsigned              The reports are unsigned, as the Community Edition writes them: judge
                          them with `verify-report --unsigned` and the same acceptance rules.
                          Exactly one of --keyring and --unsigned is required for an
                          executable campaign.
  --scratch DIR           Remote PVE COW overlay directory (default: /var/lib/certistack/scratch).
  --state-dir DIR         Remote PVE journal directory (default: /var/lib/certistack).
  --output DIR            Local controller report directory (default: /var/lib/certistack/reports).
  --resume DIR            Resume a prior positive campaign directory with matching case content.
  --list-cases            Print the selected cases and exit without contacting a node.
  --skip-doctor           Deprecated no-op; each node worker runs its own authoritative preflight.
  --skip-integrity        Test-only: omit the full mapped-image checksum pass; requires CERTISTACK_ALLOW_TEST_MODE=1 in --env.
  --release-evidence      Require full integrity and a stated way of judging reports (--keyring, which
                          pins the signer, or --unsigned); bind this claim to campaign metadata.
  --fail-fast             Stop after the first unexpected positive-case failure.
  -h, --help              Show this help.

Run this script from the management controller, not directly on PVE. Each
worker performs its own read-only node preflight before it can map a PBS image
or create a sandbox resource.

The positive suite runs all healthy plans serially. It finishes the selected
matrix after an unexpected failure, prints a pass/fail summary, and exits
non-zero when any case failed. Use --fail-fast for immediate triage. The `all`
plan contains healthy workloads only; each dedicated fault fixture is tested
separately in fault mode so an injected fault cannot distort positive coverage.
Before any controller output is created or PVE is contacted, every selected
plan is statically validated. A single rejected plan fails the entire campaign
admission; correct and regenerate the fixture rather than accepting a partial
matrix as evidence.

When a generated `certistack-campaign.manifest` is present, it is authoritative
for case membership. `positive` entries form the default campaign; `selective`
entries may be run only with `--case`; and `fault` entries require fault mode.
This prevents stale plans from a previous inventory from being counted in the
current campaign while retaining deliberate group and full-fleet drills. The
manifest must also contain an `allowed_nodes` row; the requested `--node` must
be listed there before any executable campaign is admitted.

Plans named diagnostic-*.yaml are intentionally excluded from the default
positive matrix because they exercise a known edge condition. Run one with
--case when diagnosing that condition; it must not distort healthy coverage.

A case is credited only when it exited with the status its mode needs (a
healthy case 0; a fault or a capacity guard exactly 1, the status of a failed
validation with verified cleanup; 2 and 130 are never credited) and its signed
report is accepted by the CertiStack binary's own `verify-report`, bound to the
request: the case's plan (its exact VMs, source VMs, and probes with targets),
the --node, this binary's version, commit and build date, the validation mode,
and the expected outcome. A pass needs every planned VM verified with its probes
passed and a guest-level assertion that ran, verified disk integrity, and
cleanup the controller confirmed; a fault needs exactly the fault plan's first
VM and probe to fail; a guard needs the signed failure reason to be the
admission or preflight capacity denial. The report must be the one this case's
run saved: a regular file in the --output directory written after the case
started, among the run log's "report saved to" lines. Each case's plan is copied
beside its log, checked against plans.tsv, and that copy is what runs and is
verified. Verdicts are kept as <case>.verification.json, the verified report as
<case>.report.json, beside the case log.

Use --resume with a prior campaign log directory to skip only positive cases
whose ledger records an attempt that exited 0 and was credited, and whose stored
signed report is accepted the same way. A changed plan, node, build, validation
mode, failed report verification, non-zero recorded status, or incomplete log
is never resumed as a pass; that case runs again.

Every executable campaign requires --keyring or --unsigned because the trust in
a report is decided by the caller and never by the report. With --keyring,
verification is identity-pinned and a report must not establish trust in its own
embedded key. With --unsigned, the reports are the Community Edition's own claim
(verify-report prints "UNSIGNED: the contents are the run's own claim, not
authenticated"), judged by the same acceptance rules, and a report that carries a
signature is refused. The tamper evidence of unsigned reports is not in the
reports: seal the campaign's output directory with the release key afterwards
(the lab's own bundle tool). The two options exclude each other, and a
campaign started with one is never resumed with the other.
Use --release-evidence for a production campaign. It additionally rejects
--skip-integrity and `PVE_TLS_INSECURE`; configure a trusted PVE CA instead.

--skip-integrity is only for disposable lab iteration and requires the exact
CERTISTACK_ALLOW_TEST_MODE=1 opt-in in the allowlisted --env file. Its reports
are marked test_skip_integrity and are not production recovery or compliance
evidence.

Fault mode requires one `--case fault-*.yaml` plan and expects CertiStack to
exit 1. The plan's first VM and that VM's first probe, as written, name
the injected failure; its report must show exactly that one probe failed.
Inject and later clear only that matching fault; this script does not alter a
workload for you.

Guard mode runs admission-*-guard.yaml plans and expects CertiStack to reject
them at either capacity gate—node preflight or admission control—before it
maps a snapshot, creates a COW overlay, or starts a sandbox VM, and to exit 1.
It credits the denial from the signed failure reason (the capacity denial itself,
not any failure before a restore), checked against the controller's own report
line in the log, and makes no workload changes.
EOF
}

mode="positive"
cases_dir=".lab/cases"
case_name=""
certistack_bin="certistack"
env_file=""
keyring_path=""
unsigned=false
scratch_dir="/var/lib/certistack/scratch"
state_dir="/var/lib/certistack"
output_dir="/var/lib/certistack/reports"
node=""
skip_doctor=false
skip_integrity=false
fail_fast=false
release_evidence=false
resume_dir=""
list_cases=false

while (($# > 0)); do
    case "$1" in
        --node) node="${2:?--node requires a value}"; shift 2 ;;
        --mode) mode="${2:?--mode requires a value}"; shift 2 ;;
        --cases) cases_dir="${2:?--cases requires a value}"; shift 2 ;;
        --case) case_name="${2:?--case requires a value}"; shift 2 ;;
        --certistack) certistack_bin="${2:?--certistack requires a value}"; shift 2 ;;
        --env) env_file="${2:?--env requires a value}"; shift 2 ;;
        --keyring) keyring_path="${2:?--keyring requires a value}"; shift 2 ;;
        --unsigned) unsigned=true; shift ;;
        --scratch) scratch_dir="${2:?--scratch requires a value}"; shift 2 ;;
        --state-dir) state_dir="${2:?--state-dir requires a value}"; shift 2 ;;
        --output) output_dir="${2:?--output requires a value}"; shift 2 ;;
        --resume) resume_dir="${2:?--resume requires a directory}"; shift 2 ;;
        --list-cases) list_cases=true; shift ;;
        --skip-doctor) skip_doctor=true; shift ;;
        --skip-integrity) skip_integrity=true; shift ;;
        --release-evidence) release_evidence=true; shift ;;
        --fail-fast) fail_fast=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$node" ]]; then
    printf '%s\n\n' '--node is required.' >&2
    usage >&2
    exit 2
fi
if [[ "$mode" != "positive" && "$mode" != "fault" && "$mode" != "guard" ]]; then
    printf '%s\n' '--mode must be positive, fault, or guard.' >&2
    exit 2
fi
if [[ -n "$resume_dir" && "$mode" != "positive" ]]; then
    printf '%s\n' '--resume is supported only for positive campaigns.' >&2
    exit 2
fi
if [[ "$release_evidence" == true && "$skip_integrity" == true ]]; then
    printf '%s\n' '--release-evidence cannot be combined with --skip-integrity.' >&2
    exit 2
fi
if [[ "$unsigned" == true && -n "$keyring_path" ]]; then
    printf '%s\n' '--unsigned and --keyring contradict each other: the reports are either unsigned or verified against a trusted signer keyring.' >&2
    exit 2
fi
if [[ "$release_evidence" == true && -z "$keyring_path" && "$unsigned" != true ]]; then
    printf '%s\n' "--release-evidence requires --keyring to pin the report signer, or --unsigned when the reports are the Community Edition's unsigned ones." >&2
    exit 2
fi
# What the evidence is called in this campaign's messages: signed (verified against the pinned keyring) or unsigned (accepted by verify-report --unsigned).
evidence_kind=signed
evidence_phrase="a signed"
if [[ "$unsigned" == true ]]; then
    evidence_kind=unsigned
    evidence_phrase="an unsigned"
fi
if [[ ! -d "$cases_dir" ]]; then
    printf 'Case directory does not exist: %s\n' "$cases_dir" >&2
    exit 1
fi
cases_dir=$(cd "$cases_dir" && pwd -P)
blocked_path="$cases_dir/CAMPAIGN-BLOCKED"
if [[ -e "$blocked_path" ]]; then
    printf 'Campaign is blocked pending required lab prerequisites: %s\n' "$blocked_path" >&2
    if [[ -r "$blocked_path" ]]; then
        sed 's/^/  /' "$blocked_path" >&2
    fi
    exit 2
fi
mapfile -t all_cases < <(find "$cases_dir" -maxdepth 1 -type f -name '*.yaml' -printf '%f\n' | LC_ALL=C sort)
if ((${#all_cases[@]} == 0)); then
    printf 'No YAML plans found in %s\n' "$cases_dir" >&2
    exit 1
fi

# A generator-written manifest is authoritative when present. It prevents
# stale files from a prior inventory from being silently included in a new
# healthy campaign. Directly maintained diagnostic and guard plans remain
# selectable by their explicit modes, but are never selected by default.
manifest_path="$cases_dir/certistack-campaign.manifest"
manifest_active=false
allowed_nodes_seen=false
declare -A allowed_node_set=()
declare -A case_mode_by_filename=()
if [[ -e "$manifest_path" ]]; then
    if [[ ! -r "$manifest_path" ]]; then
        printf 'Campaign manifest is not readable: %s\n' "$manifest_path" >&2
        exit 1
    fi
    manifest_line=0
    while IFS=$'\t' read -r declared_mode declared_file extra; do
        ((manifest_line += 1))
        if ((manifest_line == 1)); then
            if [[ "$declared_mode" != "format=2" || -n "$declared_file" || -n "$extra" ]]; then
                printf 'Campaign manifest has an unsupported header: %s\n' "$manifest_path" >&2
                exit 1
            fi
            continue
        fi
        if [[ -z "$declared_mode" && -z "$declared_file" && -z "$extra" ]]; then
            continue
        fi
        if [[ "$declared_mode" == "allowed_nodes" ]]; then
            if [[ "$allowed_nodes_seen" == true || -n "$extra" || -z "$declared_file" ]]; then
                printf 'Campaign manifest contains an invalid allowed_nodes row on line %d.\n' "$manifest_line" >&2
                exit 1
            fi
            IFS=',' read -r -a manifest_allowed_nodes <<< "$declared_file"
            for allowed_node in "${manifest_allowed_nodes[@]}"; do
                allowed_node="${allowed_node#"${allowed_node%%[![:space:]]*}"}"
                allowed_node="${allowed_node%"${allowed_node##*[![:space:]]}"}"
                if [[ ! "$allowed_node" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
                    printf 'Campaign manifest contains an invalid allowed node on line %d.\n' "$manifest_line" >&2
                    exit 1
                fi
                allowed_node_set["$allowed_node"]=1
            done
            allowed_nodes_seen=true
            continue
        fi
        if [[ -n "$extra" || ( "$declared_mode" != "positive" && "$declared_mode" != "selective" && "$declared_mode" != "fault" ) ||
            ! "$declared_file" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.yaml$ ]]; then
            printf 'Campaign manifest contains an invalid entry on line %d.\n' "$manifest_line" >&2
            exit 1
        fi
        if [[ ! -f "$cases_dir/$declared_file" ]]; then
            printf 'Campaign manifest references a missing plan: %s\n' "$declared_file" >&2
            exit 1
        fi
        if [[ -n "${case_mode_by_filename[$declared_file]+present}" ]]; then
            printf 'Campaign manifest lists a plan more than once: %s\n' "$declared_file" >&2
            exit 1
        fi
        case_mode_by_filename["$declared_file"]="$declared_mode"
    done < "$manifest_path"
    if ((manifest_line < 3 || ${#case_mode_by_filename[@]} == 0)) ||
        [[ "$allowed_nodes_seen" != true || ${#allowed_node_set[@]} == 0 ]]; then
        printf 'Campaign manifest contains no plans: %s\n' "$manifest_path" >&2
        exit 1
    fi
    manifest_active=true
fi

if [[ "$manifest_active" != true ]]; then
    printf '%s\n' 'An executable campaign requires a format=2 manifest with an allowed_nodes row.' >&2
    exit 2
fi
if [[ -z "${allowed_node_set[$node]+present}" ]]; then
    printf 'Requested node is not allowlisted by the campaign manifest: %s\n' "$node" >&2
    exit 2
fi

selected_cases=()
if [[ -n "$case_name" ]]; then
    case_name=${case_name##*/}
    if [[ ! -f "$cases_dir/$case_name" ]]; then
        printf 'Case does not exist: %s\n' "$cases_dir/$case_name" >&2
        exit 1
    fi
    declared_mode="${case_mode_by_filename[$case_name]-}"
    if [[ "$manifest_active" == true && -z "$declared_mode" && "$case_name" != diagnostic-* && "$case_name" != admission-*-guard.yaml ]]; then
        printf 'Case is not part of the current generated campaign manifest: %s\n' "$case_name" >&2
        exit 2
    fi
    case "$mode:$declared_mode:$case_name" in
        positive:fault:*)
            printf 'This is an expected-failure case; use its matching campaign mode.\n' >&2
            exit 2
            ;;
        positive::fault-*|positive:*:admission-*-guard.yaml)
            printf 'This is an expected-failure case; use its matching campaign mode.\n' >&2
            exit 2
            ;;
        fault:fault:*) selected_cases=("$case_name") ;;
        fault::fault-*) selected_cases=("$case_name") ;;
        fault:*)
            printf 'Fault mode requires a fault-*.yaml plan.\n' >&2
            exit 2
            ;;
        guard:*:admission-*-guard.yaml) selected_cases=("$case_name") ;;
        guard:*)
            printf 'Guard mode requires an admission-*-guard.yaml plan.\n' >&2
            exit 2
            ;;
        positive:positive:*) selected_cases=("$case_name") ;;
        positive:selective:*) selected_cases=("$case_name") ;;
        positive::*) selected_cases=("$case_name") ;;
    esac
elif [[ "$mode" == "fault" ]]; then
    printf 'Fault mode requires --case fault-<target-vmid>.yaml.\n' >&2
    exit 2
elif [[ "$mode" == "guard" ]]; then
    for filename in "${all_cases[@]}"; do
        case "$filename" in
            admission-*-guard.yaml) selected_cases+=("$filename") ;;
        esac
    done
else
    for filename in "${all_cases[@]}"; do
        if [[ "$manifest_active" == true ]]; then
            if [[ "${case_mode_by_filename[$filename]-}" == "positive" ]]; then
                selected_cases+=("$filename")
            fi
        else
            case "$filename" in
                fault-*|admission-*-guard.yaml|diagnostic-*.yaml) ;;
                *) selected_cases+=("$filename") ;;
            esac
        fi
    done
fi
if ((${#selected_cases[@]} == 0)); then
    printf 'No %s cases found in %s\n' "$mode" "$cases_dir" >&2
    exit 1
fi

if [[ "$list_cases" == true ]]; then
    printf 'CertiStack %s case selection (%d case(s)):\n' "$mode" "${#selected_cases[@]}"
    printf '%s\n' "${selected_cases[@]}"
    exit 0
fi

if [[ -n "$env_file" && ! -r "$env_file" ]]; then
    printf 'Environment file is not readable: %s\n' "$env_file" >&2
    exit 1
fi
if [[ -n "$keyring_path" && ! -r "$keyring_path" ]]; then
    printf 'Trusted signer keyring is not readable: %s\n' "$keyring_path" >&2
    exit 1
fi
if [[ -z "$keyring_path" && "$unsigned" != true ]]; then
    printf '%s\n' "--keyring is required for every executable campaign unless --unsigned says the reports are unsigned (the Community Edition's); reports must have a trusted signer identity or be judged as unsigned." >&2
    exit 2
fi

# The engine permits insecure PVE API TLS only when an operator explicitly
# acknowledges a disposable-lab exception. That exception can never support a
# release-evidence claim. When an env file is supplied it replaces the
# controller connection environment, so inspect its literal assignment rather
# than the caller's inherited value. The controller itself remains the
# authoritative parser and will reject malformed environment files later.
release_evidence_uses_insecure_pve_tls() {
    local value="${PVE_TLS_INSECURE-}"
    if [[ -n "$env_file" ]]; then
        value=""
        local raw_line trimmed_line key raw_value first_line=true
        while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
            # The engine drops a UTF-8 byte order mark (EF BB BF) at the start
            # of the file before it reads the first line, and accepts such a
            # file; a mark left on the first line would hide a leading
            # PVE_TLS_INSECURE from this gate (audit F124).
            if [[ "$first_line" == true ]]; then
                raw_line="${raw_line#$'\xef\xbb\xbf'}"
                first_line=false
            fi
            # Mirror the engine's own parser exactly (cmd/certistack/environment.go
            # parseEnvironmentFile): trim the whole line first, then split on
            # the first '=', then trim each side, then strip a surrounding
            # quote pair. Trimming only around the captured value (as an
            # earlier version of this gate did) can leave whitespace outside a
            # quoted value that later steps fail to recognize, letting a line
            # like `PVE_TLS_INSECURE="true" ` (trailing space after the
            # closing quote) slip past this preview gate while the engine
            # still reads it as true.
            trimmed_line="${raw_line#"${raw_line%%[![:space:]]*}"}"
            trimmed_line="${trimmed_line%"${trimmed_line##*[![:space:]]}"}"
            [[ -z "$trimmed_line" || "$trimmed_line" == \#* || "$trimmed_line" != *=* ]] && continue
            key="${trimmed_line%%=*}"
            key="${key#"${key%%[![:space:]]*}"}"
            key="${key%"${key##*[![:space:]]}"}"
            [[ "$key" == "PVE_TLS_INSECURE" ]] || continue
            raw_value="${trimmed_line#*=}"
            raw_value="${raw_value#"${raw_value%%[![:space:]]*}"}"
            raw_value="${raw_value%"${raw_value##*[![:space:]]}"}"
            value="$raw_value"
        done < "$env_file"
    fi
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
        value=${value:1:${#value}-2}
    elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
        value=${value:1:${#value}-2}
    fi
    # The engine's own boolean readers (e.g. runner.go's envBool) independently
    # TrimSpace the environment variable's value at the point they consume it,
    # after any quoting has already been stripped by the file parser. Mirror
    # that second, separate trim here too, so whitespace left inside a quoted
    # value (a literal " true" with the space inside the quotes) is treated
    # exactly as the engine treats it.
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    value=${value,,}
    [[ "$value" == "1" || "$value" == "true" ]]
}

if [[ "$release_evidence" == true ]] && release_evidence_uses_insecure_pve_tls; then
    printf '%s\n' '--release-evidence forbids PVE_TLS_INSECURE; configure a trusted PVE CA instead.' >&2
    exit 2
fi

certistack_resolved=$(command -v "$certistack_bin" 2>/dev/null || true)
if [[ -z "$certistack_resolved" && ! -x "$certistack_bin" ]]; then
	printf 'CertiStack binary is unavailable: %s\n' "$certistack_bin" >&2
	exit 1
fi
if [[ -z "$certistack_resolved" ]]; then
	certistack_resolved="$certistack_bin"
fi

# Every report is bound to the controller build that produced it. The
# same binary runs each case and verifies its report, so the identity its own
# `version` prints (label, commit, build date) is exactly what every accepted
# report must carry; a report from any other build is never credited.
version_output=""
if ! version_output=$("$certistack_bin" version 2>/dev/null); then
    version_output=""
fi
version_field() {
    local field="$1"
    awk -v field="$field" '
        { line = $0; sub(/\r$/, "", line) }
        line ~ ("^[[:space:]]*" field ":[[:space:]]+[^[:space:]]+[[:space:]]*$") {
            sub("^[[:space:]]*" field ":[[:space:]]+", "", line)
            sub(/[[:space:]]+$/, "", line)
            print line
            exit
        }
    ' <<<"$version_output"
}
version_label=$(awk 'NR == 1 { sub(/\r$/, ""); if ($1 == "certistack" && NF == 2) print $2; exit }' <<<"$version_output")
version_commit=$(version_field commit)
version_built=$(version_field built)
if [[ -z "$version_label" || -z "$version_commit" || -z "$version_built" ]]; then
    if [[ "$release_evidence" == true ]]; then
        printf '%s\n' '--release-evidence requires a controller binary that can report its build identity.' >&2
    else
        printf '%s\n' 'The CertiStack binary did not report its build identity (version, commit, build date); campaign reports cannot be bound to it.' >&2
    fi
    exit 2
fi
# Acceptance is the verifier's decision. A binary whose verify-report cannot
# bind a report to the request would fail every case after it ran; refuse it
# before any PVE contact instead.
verify_help=$("$certistack_bin" verify-report --help 2>/dev/null || true)
if [[ "$verify_help" != *--expect-plan* || "$verify_help" != *--expect-outcome* || "$verify_help" != *--expect-worker-sha256* ]]; then
    printf '%s\n' "The CertiStack binary's verify-report cannot bind reports to a plan, node, build, and executable digest; use this helper with the binary from the same release." >&2
    exit 2
fi
if [[ "$unsigned" == true && "$verify_help" != *--unsigned* ]]; then
    printf '%s\n' "The CertiStack binary's verify-report cannot judge unsigned reports (it has no --unsigned); use this helper with the binary from the same release, or --keyring for signed reports." >&2
    exit 2
fi

# A release report must bind to a reviewed source revision, not merely to a
# byte hash of a convenient local development binary. The normal build embeds
# both a human release label and the abbreviated Git commit. Refuse a
# development, unknown, or dirty identity before any plan validation or PVE
# contact.
if [[ "$release_evidence" == true ]]; then
    if [[ "$version_label" == "dev" || "$version_label" == "unknown" || "$version_label" == *dirty* || ! "$version_commit" =~ ^[0-9a-f]{7,40}$ ]]; then
        printf '%s\n' '--release-evidence requires a clean controller build with an immutable Git commit; build and review the candidate first.' >&2
        exit 2
    fi
fi

# A campaign is an atomic evidence unit. Do not let a malformed or no-longer
# supported plan fail only after earlier cases have created temporary recovery
# resources: validate the complete selected set before creating a ledger or
# contacting PVE. Keep validator output out of the campaign log because a
# plan's diagnostic text may contain site-specific values; the filename is
# enough for the operator to correct and revalidate the fixture.
invalid_plan_count=0
for filename in "${selected_cases[@]}"; do
    if ! "$certistack_bin" validate "$cases_dir/$filename" >/dev/null 2>&1; then
        printf 'Campaign plan validation failed: %s\n' "$filename" >&2
        ((invalid_plan_count += 1))
    fi
done
if ((invalid_plan_count > 0)); then
    printf 'Campaign refused before PVE contact: %d selected plan(s) failed static validation.\n' "$invalid_plan_count" >&2
    exit 2
fi

# The controller uploads its own executable to the node as the worker and records
# that file's SHA-256 in every report (worker_sha256; signed, too, in a report the
# Enterprise Edition signed), so the digest of this
# file is what an accepted report must carry. The label (version, commit, build
# date) names a build; the digest names the bytes.
certistack_worker_sha256=""
if [[ -f "$certistack_resolved" ]]; then
	certistack_worker_sha256=$(sha256sum "$certistack_resolved" | awk '{print $1}')
	certistack_identity="sha256:$certistack_worker_sha256"
else
	# A command that is not a file has no digest to bind. The campaign record
	# names that weaker identity, and the verifier is not given a worker digest.
	certistack_identity="command:$certistack_resolved"
fi
if [[ "$release_evidence" == true && -z "$certistack_worker_sha256" ]]; then
    printf '%s\n' '--release-evidence requires the CertiStack executable as a file, so that every accepted report can be bound to its SHA-256.' >&2
    exit 2
fi
# The identity the campaign is bound to along with the build: the digest of the pinned keyring, or the word unsigned, so a campaign judged one way is
# never resumed the other way.
if [[ "$unsigned" == true ]]; then
    keyring_identity="unsigned"
else
    keyring_identity="sha256:$(sha256sum "$keyring_path" | awk '{print $1}')"
fi
if ! mkdir -p "$output_dir"; then
    printf 'Cannot create controller output directory: %s\n' "$output_dir" >&2
    exit 1
fi
output_dir=$(cd "$output_dir" && pwd -P)

if [[ "$skip_doctor" == true ]]; then
    printf 'Note: --skip-doctor is deprecated; remote node preflight remains mandatory.\n'
else
    printf 'Each temporary node worker will run its authoritative preflight before recovery starts.\n'
fi

if [[ "$skip_integrity" == true ]]; then
    expected_validation_mode="test_skip_integrity"
else
    expected_validation_mode="full_integrity"
fi

run_args=()
if [[ "$skip_integrity" == true ]]; then
    run_args+=(--skip-integrity)
fi
if [[ -n "$env_file" ]]; then
    # Keep dotenv handling inside the controller, which accepts only its
    # documented variables and parses values literally. Never execute a file
    # supplied as test credentials, even when this campaign runs as root.
    run_args+=(--env-file "$env_file")
fi

campaign_fingerprint() {
    {
        printf 'mode=%s\nvalidation_mode=%s\nrelease_evidence=%s\ncertistack=%s\nkeyring=%s\n' \
            "$mode" "$expected_validation_mode" "$release_evidence" "$certistack_identity" "$keyring_identity"
        local filename digest
        for filename in "${selected_cases[@]}"; do
            digest=$(sha256sum "$cases_dir/$filename")
            printf '%s %s\n' "$filename" "${digest%% *}"
        done
    } | sha256sum | awk '{print $1}'
}

campaign_hash=$(campaign_fingerprint)
node_hash=$(printf '%s' "$node" | sha256sum | awk '{print $1}')
if [[ -n "$resume_dir" ]]; then
    if [[ ! -d "$resume_dir" ]]; then
        printf 'Campaign resume directory does not exist: %s\n' "$resume_dir" >&2
        exit 1
    fi
    log_dir=$(cd "$resume_dir" && pwd -P)
    campaign_meta="$log_dir/campaign.meta"
    if [[ ! -r "$campaign_meta" ]]; then
        printf 'Campaign resume metadata is missing: %s\n' "$campaign_meta" >&2
        exit 1
    fi
    if ! grep -Fxq 'format=4' "$campaign_meta" ||
        ! grep -Fxq "campaign_hash=$campaign_hash" "$campaign_meta" ||
        ! grep -Fxq "node_hash=$node_hash" "$campaign_meta" ||
        ! grep -Fxq "release_evidence=$release_evidence" "$campaign_meta" ||
        ! grep -Fxq "certistack_identity=$certistack_identity" "$campaign_meta" ||
        ! grep -Fxq "keyring_identity=$keyring_identity" "$campaign_meta"; then
        printf 'Campaign resume metadata does not match the selected plans, node, or validation mode; start a new campaign.\n' >&2
        exit 1
    fi
else
    campaign_root="$output_dir/campaign-logs"
    if ! mkdir -p "$campaign_root"; then
        printf 'Cannot create campaign log directory: %s\n' "$campaign_root" >&2
        exit 1
    fi
    # Timestamp-only paths collide when an operator retries quickly or two
    # controller processes accidentally use the same output directory. Create
    # the evidence directory atomically so no campaign can overwrite another
    # campaign's metadata, logs, or case ledger.
    if ! log_dir=$(mktemp -d "$campaign_root/$(date -u +%Y%m%dT%H%M%SZ)-$mode-XXXXXX"); then
        printf 'Cannot allocate a unique campaign log directory under: %s\n' "$campaign_root" >&2
        exit 1
    fi
    campaign_meta="$log_dir/campaign.meta"
    printf 'format=4\ncampaign_hash=%s\nnode_hash=%s\nrelease_evidence=%s\ncertistack_identity=%s\nkeyring_identity=%s\n' \
        "$campaign_hash" "$node_hash" "$release_evidence" "$certistack_identity" "$keyring_identity" > "$campaign_meta"
fi

# Keep a durable, independently checkable binding between the campaign ledger
# and the exact reviewed plan bytes. Reports identify a plan ID, but that is
# not enough to prove which plan revision was executed.
plan_inventory="$log_dir/plans.tsv"
expected_inventory="$log_dir/.plans.tsv.expected"
cleanup_expected_inventory() {
    rm -f "$expected_inventory"
}
trap cleanup_expected_inventory EXIT
{
    printf 'case\tplan_sha256\n'
    for filename in "${selected_cases[@]}"; do
        digest=$(sha256sum "$cases_dir/$filename")
        printf '%s\t%s\n' "$filename" "${digest%% *}"
    done
} > "$expected_inventory"
if [[ ! -e "$plan_inventory" ]]; then
    mv "$expected_inventory" "$plan_inventory"
elif [[ $(head -n 1 "$plan_inventory") != $'case\tplan_sha256' ]] || ! cmp -s "$expected_inventory" "$plan_inventory"; then
    rm -f "$expected_inventory"
    printf 'Campaign plan inventory does not match the selected plan bytes: %s\n' "$plan_inventory" >&2
    exit 1
else
    rm -f "$expected_inventory"
fi
case_results="$log_dir/cases.tsv"
if [[ ! -e "$case_results" ]]; then
    printf 'case\tmode\toutcome\texit_status\treport_path\tlog_path\n' > "$case_results"
elif [[ $(head -n 1 "$case_results") != $'case\tmode\toutcome\texit_status\treport_path\tlog_path' ]]; then
    printf 'Campaign case ledger has an unsupported header: %s\n' "$case_results" >&2
    exit 1
fi

printf 'CertiStack %s controller campaign: %d case(s), node=%s\n' "$mode" "${#selected_cases[@]}" "$node"
printf 'Logs: %s\n' "$log_dir"
if [[ -n "$resume_dir" ]]; then
    if [[ "$unsigned" == true ]]; then
        printf 'Resume mode: only cases with matching build, unsigned-report mode, accepted success, and cleanup evidence will be skipped.\n'
    else
        printf 'Resume mode: only cases with matching build, signer keyring, signed success, and cleanup evidence will be skipped.\n'
    fi
fi
if [[ "$skip_integrity" == true ]]; then
    printf 'WARNING: full mapped-image integrity verification is disabled for this disposable lab campaign.\n'
fi
if [[ "$unsigned" == true ]]; then
    printf 'UNSIGNED: the reports are the run'"'"'s own claim, not authenticated; they are judged by verify-report --unsigned, and the campaign directory is made tamper-evident only by sealing it afterwards (bundle_manifest.py).\n'
fi
if [[ "$release_evidence" == true ]]; then
    if [[ "$unsigned" == true ]]; then
        printf 'Release-evidence mode: reports are judged as unsigned and full mapped-image integrity verification is required.\n'
    else
        printf 'Release-evidence mode: signer identity is pinned and full mapped-image integrity verification is required.\n'
    fi
fi

# The report a case saved is named by the controller's own line, printed on
# stdout after it has saved and signed the report. A log can carry other lines
# that look like it: the controller also prints failure text, which may
# include text a guest or plan controls. So every such line is only a
# candidate. A candidate counts only when it is a regular file in the
# campaign's --output directory, written after the case started; a line naming
# anything else is ignored. Exactly one distinct valid report must remain.
report_candidates_from_log() {
    awk '
        { sub(/\r$/, "") }
        index($0, "Controller report saved to: ") == 1 || index($0, "✓ Controller report saved to: ") == 1 {
            path = substr($0, index($0, "saved to: ") + length("saved to: "))
            if (path != "" && !seen[path]++) print path
        }
    ' "$1"
}

# select_case_report LOG STARTED sets case_report_path to the case's one valid
# report, or case_report_problem to why there is none.
case_report_path=""
case_report_problem=""
select_case_report() {
    local log_path="$1"
    local started="$2"
    local candidate report_dir problem=""
    local -a candidates=() valid=()
    case_report_path=""
    case_report_problem=""
    mapfile -t candidates < <(report_candidates_from_log "$log_path")
    if ((${#candidates[@]} == 0)); then
        case_report_problem='The case log does not name a saved controller report.'
        return 1
    fi
    for candidate in "${candidates[@]}"; do
        report_dir=$(cd "$(dirname -- "$candidate")" 2>/dev/null && pwd -P) || report_dir=""
        if [[ -z "$report_dir" || "$report_dir/" != "$output_dir"/* || -L "$candidate" || ! -f "$candidate" || ! -r "$candidate" ]]; then
            problem="The case report is not a readable regular file in the campaign output directory: $candidate"
        elif [[ ! -e "$started" || -z $(find "$candidate" -maxdepth 0 -newer "$started" -print 2>/dev/null) ]]; then
            problem="The case report was not written by this case's run: $candidate"
        else
            valid+=("$candidate")
        fi
    done
    if ((${#valid[@]} == 1)); then
        case_report_path="${valid[0]}"
        return 0
    fi
    if ((${#valid[@]} > 1)); then
        case_report_problem="The case log names more than one report written by this run, so none is credited: ${valid[*]}"
    else
        case_report_problem="$problem"
    fi
    return 1
}

# A case is credited only for the plan bytes this campaign recorded in
# plans.tsv. The plan is copied beside the case log, the copy is checked
# against the recorded digest, and the run and its verification use that copy,
# so the bytes that ran are the bytes that were checked, whatever happens to
# the original afterwards.
case_plan_snapshot() {
    echo "$log_dir/${1%.yaml}.plan.yaml"
}

snapshot_case_plan() {
    local filename="$1"
    local snapshot
    snapshot=$(case_plan_snapshot "$filename")
    cp -- "$cases_dir/$filename" "$snapshot" && chmod 0600 "$snapshot" && snapshot_matches_inventory "$filename"
}

snapshot_matches_inventory() {
    local filename="$1"
    local snapshot digest
    snapshot=$(case_plan_snapshot "$filename")
    [[ -f "$snapshot" ]] || return 1
    digest=$(sha256sum "$snapshot") || return 1
    grep -Fxq "$filename"$'\t'"${digest%% *}" "$plan_inventory"
}

# A refusal is recorded as a rejected verdict beside the case log, so a
# reviewer never finds an accepted verdict for a case the helper did not
# credit, or none at all.
write_refusal() {
    local path="$1"
    local outcome="$2"
    local reason="$3"
    reason=${reason//\\/\\\\}
    reason=${reason//\"/\\\"}
    printf '{"acceptance":{"verdict":"rejected","expected_outcome":"%s","bindings":[],"reasons":["%s"]},"helper_refusal":true}\n' \
        "$outcome" "$reason" >"$path"
}

# The signed report must be the one this case's run saved. The controller's own
# verifier then decides acceptance, against a copy of the report kept beside the
# case log (so the bytes verified are the bytes retained) and the plan copy that
# ran, for the node, build, validation mode, and outcome (pass, fault, or
# denied): the exact planned VM population, every probe, disk integrity, and
# verified cleanup. Its JSON verdict is kept beside the case log as evidence.
# The caller has already required the exit status the mode needs.
accept_case_report() {
    local log_path="$1"
    local filename="$2"
    local outcome="$3"
    local started="$4"
    local verification_path="${log_path%.log}.verification.json"
    local report_copy="${log_path%.log}.report.json"
    local plan_copy verify_error status refusal
    plan_copy=$(case_plan_snapshot "$filename")
    rm -f "$verification_path"
    if ! select_case_report "$log_path" "$started"; then
        printf '%s\n' "$case_report_problem" >&2
        write_refusal "$verification_path" "$outcome" "$case_report_problem"
        return 1
    fi
    if ! snapshot_matches_inventory "$filename"; then
        refusal='The case plan is missing or does not match the digest the campaign recorded, so its report is not evidence for the recorded plan.'
        printf '%s\n' "$refusal" >&2
        write_refusal "$verification_path" "$outcome" "$refusal"
        return 1
    fi
    if ! cp -- "$case_report_path" "$report_copy"; then
        refusal="The case report could not be copied beside the case log: $case_report_path"
        printf '%s\n' "$refusal" >&2
        write_refusal "$verification_path" "$outcome" "$refusal"
        return 1
    fi
    # The caller states how reports are judged: against the pinned keyring, or as the Community Edition's unsigned ones. Never both, never neither.
    local trust_args=(--keyring "$keyring_path")
    if [[ "$unsigned" == true ]]; then
        trust_args=(--unsigned)
    fi
    local verify_args=(verify-report --format json "${trust_args[@]}"
        --expect-plan "$plan_copy" --expect-node "$node"
        --expect-version "$version_label" --expect-commit "$version_commit" --expect-build-date "$version_built"
        --expect-validation-mode "$expected_validation_mode" --expect-outcome "$outcome")
    if [[ -n "$certistack_worker_sha256" ]]; then
        verify_args+=(--expect-worker-sha256 "$certistack_worker_sha256")
    fi
    # verify-report refuses test-mode reports unless told to accept them;
    # without this a --skip-integrity campaign could never credit a case.
    if [[ "$skip_integrity" == true ]]; then
        verify_args+=(--allow-test-mode)
    fi
    set +e
    verify_error=$("$certistack_bin" "${verify_args[@]}" "$report_copy" 2>&1 >"$verification_path")
    status=$?
    set -e
    if ((status != 0)) || ! grep -Fq '"acceptance":{"verdict":"accepted"' "$verification_path"; then
        printf 'The %s report was not accepted as %s evidence (verify-report exit %d); its verdict is in %s\n' "$evidence_kind" "$outcome" "$status" "$verification_path" >&2
        if [[ -n "$verify_error" ]]; then
            sed 's/^/  /' <<<"$verify_error" >&2
        fi
        # verify-report writes a verdict only for a report it trusts (a valid
        # signature from the keyring, or an unsigned report given --unsigned);
        # anything else leaves the refusal and its reason instead.
        if ! grep -Fq '"acceptance":{"verdict":"rejected"' "$verification_path"; then
            write_refusal "$verification_path" "$outcome" "verify-report exit $status: $(head -n 1 <<<"$verify_error")"
        fi
        return 1
    fi
    # An accepted verdict is only as strong as what it bound. A report of an
    # earlier schema, or one the controller signed without the plan's digest, is
    # accepted on what it records and the verdict lists what it could not check
    # (NOT BOUND); that is not evidence a campaign may credit. The helper asks
    # for the full set: the plan's file, probe policy, recovery time objective
    # and admission policy as well as its ID, the node, the build and the
    # validation mode.
    local bindings missing=""
    bindings=$(grep -o '"bindings":\[[^]]*\]' "$verification_path" | head -n 1 || true)
    for required in plan plan_sha256 probe_policy rto_objective admission_policy node build validation_mode; do
        if [[ "$bindings" != *"\"$required\""* ]]; then
            missing+="${missing:+, }$required"
        fi
    done
    if [[ -n "$missing" ]] || grep -Fq 'NOT BOUND:' "$verification_path"; then
        refusal="verify-report accepted the report without binding it to everything a campaign credits (the plan and its file digest, the probe policy, the recovery time objective and the admission policy, the node, the build and the validation mode)${missing:+; not bound: $missing}; a report with a NOT BOUND entry is not evidence for this case."
        printf '%s\n' "$refusal" >&2
        cp -- "$verification_path" "${verification_path%.json}.unbound.json" 2>/dev/null || true
        write_refusal "$verification_path" "$outcome" "$refusal"
        return 1
    fi
    return 0
}

# Resume credits a positive case only when the ledger records that its latest
# real attempt (a row that is not itself a resume) exited 0, was credited as a
# verified pass, and saved this same report; the stored report alone is never
# enough, because the run can fail after its report is saved clean (for
# example when removing its credential-bearing node workspace is not verified).
resume_credit_recorded() {
    local filename="$1"
    local report="$2"
    awk -F'\t' -v f="$filename" -v report="$report" '
        FNR > 1 && $1 == f && $4 != "resumed" { mode = $2; outcome = $3; status = $4; path = $5; seen = 1 }
        END { exit !(seen && mode == "positive" && outcome == "verified-pass" && status == "0" && path == report) }
    ' "$case_results"
}

positive_case_is_verified_success() {
    accept_case_report "$1" "$2" pass "$3"
}

fault_report_records_probe_failure() {
    if ! accept_case_report "$1" "$2" fault "$3"; then
        printf '%s report does not prove exactly the expected VM/probe failure and clean teardown.\n' "${evidence_kind^}" >&2
        return 1
    fi
    return 0
}

record_case_result() {
    local filename="$1"
    local outcome="$2"
    local status="$3"
    local log_path="$4"
    local report_path="$case_report_path"
    if [[ -z "$report_path" && -r "$log_path" ]]; then
        report_path=$(report_candidates_from_log "$log_path" | tail -n 1)
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$filename" "$mode" "$outcome" "$status" "$report_path" "$log_path" >> "$case_results"
}

guard_case_rejected_before_recovery() {
    local log_path="$1"
    local filename="$2"
    local started="$3"
    local verification_path="${log_path%.log}.verification.json"
    local refusal
    # The signed failure reason decides (below); the log is only a second
    # opinion. It must show the controller's own report line for a capacity
    # denial, anchored at the start of the line so text a plan controls, such as
    # its ID in "Starting DR validation plan", cannot satisfy it.
    if ! grep -Eq '^(\[[0-9:]+\] ERROR Report saved at .*; validation failed: |Error: DR validation failed: )(admission control guardrail triggered: |node preflight failed: memory: )' "$log_path"; then
        refusal='Guard case did not show a recognized capacity denial.'
        printf '%s\n' "$refusal" >&2
        write_refusal "$verification_path" denied "$refusal"
        return 1
    fi
    if grep -Eq '\[Storage\] (Mounted|Created volatile COW)|\[Sandbox\] (Registering|Launching)|\[Stage 1\]' "$log_path"; then
        refusal='Guard case reached a recovery-resource phase after admission denial.'
        printf '%s\n' "$refusal" >&2
        write_refusal "$verification_path" denied "$refusal"
        return 1
    fi
    # The signed report must record a clean capacity refusal of this plan on
    # this node and build before any VM was restored.
    if ! accept_case_report "$log_path" "$filename" denied "$started"; then
        printf 'Guard case report does not prove %s, clean failed validation.\n' "$evidence_phrase" >&2
        return 1
    fi
    return 0
}

passed=0
failed_cases=()
total_cases=${#selected_cases[@]}
case_index=0

print_campaign_progress() {
    local completed
    completed=$((passed + ${#failed_cases[@]}))
    printf 'Campaign progress: %d/%d complete — %d passed, %d failed.\n' \
        "$completed" "$total_cases" "$passed" "${#failed_cases[@]}"
}

for filename in "${selected_cases[@]}"; do
    case_path="$cases_dir/$filename"
    log_path="$log_dir/${filename%.yaml}.log"
    case_index=$((case_index + 1))
    printf '\n[%s %d/%d] %s\n' "$mode" "$case_index" "$total_cases" "$filename"

    # Each run's report must postdate this marker, so a report left by an
    # earlier run is never credited to this one. Resume keeps the marker of
    # the attempt whose report it re-verifies.
    started_path="$log_dir/${filename%.yaml}.started"
    case_report_path=""

    if [[ -n "$resume_dir" && -r "$log_path" ]]; then
        # Resume credits a case only if its recorded attempt exited 0 and was
        # credited, and its stored report is accepted again now.
        if select_case_report "$log_path" "$started_path" &&
            resume_credit_recorded "$filename" "$case_report_path" &&
            positive_case_is_verified_success "$log_path" "$filename" "$started_path"; then
            printf 'RESUMED: healthy case %s has matching %s pass and cleanup evidence.\n' "$filename" "$evidence_kind"
            ((passed += 1))
            record_case_result "$filename" "resumed-verified-pass" "resumed" "$log_path"
            print_campaign_progress
            continue
        fi
        case_report_path=""
        printf 'Retrying %s: no matching %s pass-and-cleanup evidence was found.\n' "$filename" "$evidence_kind"
    fi

    if ! snapshot_case_plan "$filename"; then
        printf 'FAILED: case %s changed after the campaign recorded its plan digest; it was not run. Start a new campaign to test the edited plan.\n' "$filename" >&2
        failed_cases+=("$filename (plan changed after the campaign started)")
        record_case_result "$filename" "failed" "not-run" "$log_path"
        print_campaign_progress
        if [[ "$fail_fast" == true ]]; then
            printf 'Stopping because --fail-fast was requested.\n' >&2
            break
        fi
        continue
    fi

    # The run reads the checked copy of the plan, never the original.
    rm -f "${log_path%.log}.verification.json"
    : >"$started_path"
    set +e
    "$certistack_bin" run "$(case_plan_snapshot "$filename")" \
        --node "$node" \
        --scratch "$scratch_dir" \
        --state-dir "$state_dir" \
        --output "$output_dir" \
        "${run_args[@]}" 2>&1 | tee "$log_path"
    status=${PIPESTATUS[0]}
    set -e

    if [[ "$mode" == "positive" && $status -ne 0 ]]; then
        failed_cases+=("$filename (exit $status)")
        printf 'FAILED: healthy case %s returned %d; continuing for campaign coverage.\n' "$filename" "$status" >&2
        if [[ "$fail_fast" == true ]]; then
            printf 'Stopping because --fail-fast was requested.\n' >&2
            record_case_result "$filename" "failed" "$status" "$log_path"
            print_campaign_progress
            break
        fi
    fi
    outcome="failed"
    # A run that failed its validation with verified cleanup exits 1. Any other
    # non-zero status (2: cleanup of the run's credential-bearing material or
    # the node's temporary resources was not verified, or a transport or
    # infrastructure error; 130: interrupted) is never fault detection or a
    # capacity denial, whatever the report says.
    if [[ "$mode" == "guard" && $status -eq 0 ]]; then
        printf 'FAILED: guard case %s unexpectedly passed.\n' "$filename" >&2
        failed_cases+=("$filename (unexpected pass)")
    elif [[ "$mode" == "guard" && $status -ne 1 ]]; then
        printf 'FAILED: guard case %s exited %d, not the validation-failed status 1; a cleanup, transport, or interruption error is never a capacity denial.\n' "$filename" "$status" >&2
        failed_cases+=("$filename (exit $status, not the validation-failed status 1)")
    elif [[ "$mode" == "guard" ]]; then
        if guard_case_rejected_before_recovery "$log_path" "$filename" "$started_path"; then
            printf 'PASS: guard case %s was denied before recovery resources were created.\n' "$filename"
            ((passed += 1))
            outcome="verified-guard-denial"
        else
            printf 'FAILED: guard case %s did not prove safe admission rejection.\n' "$filename" >&2
            failed_cases+=("$filename (non-zero without a safe admission denial)")
        fi
    elif [[ "$mode" == "fault" && $status -eq 0 ]]; then
        printf 'FAILED: fault case %s unexpectedly passed.\n' "$filename" >&2
        failed_cases+=("$filename (unexpected pass)")
    elif [[ "$mode" == "fault" && $status -ne 1 ]]; then
        printf 'FAILED: fault case %s exited %d, not the validation-failed status 1; a cleanup, transport, or interruption error is never fault detection.\n' "$filename" "$status" >&2
        failed_cases+=("$filename (exit $status, not the validation-failed status 1)")
    elif [[ "$mode" == "fault" ]]; then
        if fault_report_records_probe_failure "$log_path" "$filename" "$started_path"; then
            printf 'PASS: fault case %s produced %s failed-probe report.\n' "$filename" "$evidence_phrase"
            ((passed += 1))
            outcome="verified-fault-detection"
        else
            printf 'FAILED: fault case %s ended non-zero but did not prove fault detection.\n' "$filename" >&2
            failed_cases+=("$filename (non-zero without a failed probe report)")
        fi
    elif [[ "$mode" == "positive" && $status -eq 0 ]]; then
        if positive_case_is_verified_success "$log_path" "$filename" "$started_path"; then
            printf 'PASS: healthy case %s completed with %s cleanup evidence.\n' "$filename" "$evidence_kind"
            ((passed += 1))
            outcome="verified-pass"
        else
            printf 'FAILED: healthy case %s returned zero without matching %s pass-and-cleanup evidence.\n' "$filename" "$evidence_kind" >&2
            failed_cases+=("$filename (zero exit without $evidence_kind pass-and-cleanup evidence)")
        fi
    fi
    record_case_result "$filename" "$outcome" "$status" "$log_path"
    print_campaign_progress
done

total=$((passed + ${#failed_cases[@]}))
printf '\nCertiStack %s campaign summary: %d/%d passed, %d failed.\n' \
    "$mode" "$passed" "$total" "${#failed_cases[@]}"
if ((${#failed_cases[@]} != 0)); then
    printf 'Failed cases:\n' >&2
    for failed_case in "${failed_cases[@]}"; do
        printf '  - %s\n' "$failed_case" >&2
    done
    exit 1
fi
printf '\nCertiStack %s campaign completed successfully.\n' "$mode"
