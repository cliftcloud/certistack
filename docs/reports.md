# Reports

Every run writes one JSON report: which backup was restored, what the probes found, and whether the cleanup was
verified. This page shows where it goes, how to read, judge and keep it, and what each field means. Community reports
are unsigned; [signed reports](#signed-reports-enterprise) are at the end.

## Where a report goes

`run` saves the report on the controller and prints its path on a `Controller report saved to:` line:

```text
<output directory>/<plan_id>/<report_id>.json
```

The output directory is `/var/lib/certistack/reports` unless you set `--output` or `CERTISTACK_OUTPUT_DIR`. A run
refuses, before it starts, an output directory or plan directory that group or other users can write: a Community
report is unsigned, so its directory's permissions are what keep it as the run wrote it. Setup and the installer make
it `0700`.

- A failed validation still writes a report. A run that never created evidence (an SSH failure, a busy node) writes none.
- If the report cannot be saved, `run` exits `2` and prints it between `-----BEGIN CERTISTACK REPORT-----` and
  `-----END CERTISTACK REPORT-----` ([Issue 35](troubleshooting.md#issue-35-save-controller-report-fails-and-the-emergency-copy-of-the-unsaved-report-could-not-be-written-either)).
- Files are mode `0600`, directories `0700`. CertiStack never edits, rotates or deletes a report, and
  `compliance.retention_days` prunes nothing: retention is your job.

### A refused worker result is not a report {#a-refused-worker-result-is-not-a-report}

When a worker's result does not match the plan, node, run or report schema, `run` exits `2`, writes no report, and keeps
the bytes at `<output directory>/refused/<run-id>.refused.txt`: mode `0600`, first line `REFUSED, NOT EVIDENCE`, not JSON,
never deleted. See [Issue 34](troubleshooting.md#issue-34-the-node-workers-report-was-refused-and-no-report-was-written).

## Read the evidence

### One report: `report show` {#one-report-report-show}

`report show` prints a report and changes nothing. On the controller:

```bash
certistack report show /var/lib/certistack/reports/<plan_id>/<report_id>.json
```

It prints the outcome, plan, node, build, Proxmox versions, validation mode, recovery time and admission decision, then
each VM (snapshot, disks, what was *not* restored, each probe and where it ran, and under the probes the guest's network
diagnostic when the run captured one) and the teardown. A good report shows:

- `Outcome: PASS` and `Validation: full_integrity`
- every disk `verified` under the VM's `Integrity`
- every probe `PASS`
- `cleanup verified` under `Teardown`

Without `--keyring` no signature is checked. Flags: [Commands](cli-reference.md#report-show). No run yet? `certistack report show examples/sample-report-unsigned.json`, in a
clone of the repository, shows one from a lab run. `ls -t <output directory>/<plan_id>/` lists a plan's reports, newest
first.

## Verify a report

`verify-report` judges a report and sets its exit status, so a script can act on it:

1. Choose the trust source: `--unsigned` for a Community report, a key for a [signed one](#verify-a-signed-report).
2. Add `--expect-outcome pass`, and the other [`--expect-*` flags](#bind-the-verdict-to-your-request) to bind it to your
   request.
3. Read the verdict and the [exit status](#exit-status).

Failure text in the output can come from a guest, so it is stripped of control characters and cut short.

### An unsigned report

`verify-report` refuses a report with no signature by default (exit `2`), so a report whose signature was removed never
reads as verified. For a Community report, on the controller:

```bash
certistack verify-report --unsigned --expect-outcome pass \
  /var/lib/certistack/reports/minimal-single-vm/85a66c2e-439d-4d16-8b78-854395951f5d.json
```

```text
! Audit Certificate NOT SIGNED (--unsigned)
...
  Acceptance:  ACCEPTED on its contents only (UNSIGNED: the run's own claim, not authenticated evidence)
```

Nothing is verified: anyone can write a file that says anything. The acceptance rules and `--expect-*` flags still apply.
`--unsigned` with a trust source is a usage error, and a report carrying any signature member (`signature`,
`public_key`, `signer_fingerprint`, `signature_timestamp`, in any letter case) is refused with it (exit `2`).

### Acceptance

A signature shows only who signed the content. So `verify-report` ends with a verdict, `ACCEPTED` or `REJECTED` as pass
evidence, with reasons. For the default outcome, `pass`, it requires:

- **Schema and mode.** Schema 1.0 up to the newest minor this verifier knows, and mode `full_integrity` (or
  `test_skip_integrity` with `--allow-test-mode`).
- **VMs.** `all_passed`, at least one VM record, each sandbox VM once, `verified` and passing.
- **Probes.** All passed, and each VM has a guest-level assertion that ran: a wire probe (`tcp`, `http`, `dns`, `ldap`,
  `mssql`, `smb`) or a guest-agent probe. Only an optional `qga` probe may be skipped. `qmp` and `screendump` show only
  that the VM runs.
- **Distinct answers.** No wire-probe address passes for two VM records: a wire probe shows its target answered, not
  which guest.
- **Disks.** Every disk `verified`, with an image digest and manifest reference; no slot twice; the boot disk among them.
- **Backup.** Each VM record names a whole `vm/<id>/<time>` snapshot of its own source VM.
- **Teardown.** `all_cleaned`, `orphan_sweep_clean`, `journal_recovery_verified`, and no unresolved cleanup error.

Without `--expect-*` flags the verdict says only that the report is complete and coherent.

### Bind the verdict to your request

The `--expect-*` flags check that the report answers the run you asked for. On the controller:

```bash
certistack verify-report --unsigned --format json \
  --expect-plan /var/lib/certistack/plans/nightly.yaml \
  --expect-node pve-node-01 \
  /var/lib/certistack/reports/<plan-id>/<report-id>.json
```

| Flag | Requires |
| --- | --- |
| `--expect-plan` | The plan's ID and exactly its VMs, each probe in order (type, description, target, timeout, retries, attempts, `require_qga`, `server_name`, source), its RTO objective, admission limits and reservation, the disks its `source_pbs` names, the snapshot it pins, and `plan_sha256` equal to that file's SHA-256: even an edited comment rejects the report. |
| `--expect-node` | The PVE node that ran the worker. |
| `--expect-version`, `--expect-commit`, `--expect-build-date` | The build's labels. |
| `--expect-worker-sha256` | The uploaded executable: for a release, the published checksum of `certistack-linux-amd64`. |
| `--expect-version-support` | `tested` or `untested` as recorded; `unknown` or none is rejected. |
| `--expect-outcome fault` | A fault drill: only the first probe of the plan's first VM failed, cleanup verified. Needs `--expect-plan`. |
| `--expect-outcome denied` | A capacity refusal before any restore (`admission control guardrail triggered:` or `node preflight failed: memory:`). |

All flags: [Commands](cli-reference.md#verify-report). With or without a plan, a pass over its own `rto_target_seconds`,
or admission granted outside its own limits, is rejected.

**Tier soak.** A report of schema 1.7 or later records what the soak of each tier VM checked; `--expect-plan` rejects a
passing VM with no summary, a summary of another length or other probes than the plan's, and a failed check under a pass.

A check a report is too old for is not skipped: its line ends with `NOT BOUND:`, and the report is judged on what it
recorded.

| Report | The line shows |
| --- | --- |
| Before schema 1.6 (no `plan_sha256`) | `NOT BOUND: plan digest` |
| Schema 1.6 or earlier | `NOT BOUND: RTO objective and admission policy` |
| Never recorded probe policy | `NOT BOUND: probe policy (...)` |
| Tier soak repeated no probe | `NOT BOUND: soak service checks (...)`, so a service that stopped during that soak would not show |

### Exit status

| Exit | Meaning |
| --- | --- |
| `0` | The report was read (and a signature is valid, its signer trusted). With any `--expect-*` flag, it is also accepted. |
| `1` | An `--expect-*` flag was given and the report is not accepted. |
| `2` | It cannot be trusted or read: unsigned without `--unsigned` or signed with it, a bad signature or untrusted signer, no trust source or two, a malformed file or `--expect-plan`, a test-mode report without `--allow-test-mode`, or misuse. |

!!! warning "Exit 0 is not acceptance"
    Without an `--expect-*` flag, a report of a failed validation still exits `0`. A script must pass
    `--expect-outcome pass` (or other `--expect-*` flags), or read `acceptance.verdict` from the JSON summary.

### A machine-readable summary

`--format json` prints one line of JSON (abridged here) with no credentials and no screenshots. Its failure text
(`failed_probes`, `failure_reason`, `cleanup_errors`) can come from a guest; it is stripped of control characters and
cut short:

```json
{"report_id":"85a66c2e-439d-4d16-8b78-854395951f5d","plan_id":"minimal-single-vm","validation_mode":"full_integrity","trust_source":"keyring:/secure/certistack/trusted-signers.pub","signature_valid":true,"all_passed":true,"all_cleaned":true,"rto_seconds":42.5,"vm_count":1,"failed_probe_count":0,"incomplete_vm_count":0,"node_fqdn":"pve-node-01","engine_version":"v0.1.0","version_support":"tested","signature_timestamp":{"status":"none","evidence":false},"acceptance":{"verdict":"accepted","expected_outcome":"pass","bindings":[],"authenticated":true}}
```

| Field | Meaning |
| --- | --- |
| `acceptance` | `verdict` (`accepted` or `rejected`), `expected_outcome`, `bindings` (what was checked), `reasons`, and `authenticated` (`false` under `--unsigned`). |
| `signature_valid`, `unsigned` | Under `--unsigned`: `false` and `true`. |
| `all_passed`, `all_cleaned` | The report's verdict and its teardown's. |
| `failed_probes` | Only when a probe failed: `vmid`, `type`, `target`, `description`, `error`, `detail`. |
| Others | Counts, and the report's members of the same name when it has them. |

`all_cleaned: true` with `all_passed: false` is a clean negative result. If `all_cleaned` is `false`, recover the node
before the next run ([Issue 26](troubleshooting.md#issue-26-lost-contact-with-node)).

### Test-mode reports

A report made with the test-only `--skip-integrity` switch says `validation_mode: test_skip_integrity`. `verify-report`
reports it as not passed and exits `2` unless you pass `--allow-test-mode`.

## Keep a report tamper-evident {#keep-a-report-tamper-evident}

An unsigned report cannot show that nobody changed it. When you archive one, record its SHA-256 where nobody can rewrite
it: object-locked or write-once storage, a change ticket, a wiki page only you edit. On the controller:

```bash
sha256sum /var/lib/certistack/reports/<plan_id>/<report_id>.json
```

Never edit a report; run the validation again instead. A signed report needs the hash too, because a signature does not
cover whitespace or member order. Keep the public key that verifies it alongside.

## What a report contains

`report_schema_version` names the schema (currently `1.7`). New members are additive and left out when empty. Times are
numbers or RFC 3339 strings; lists hold strings unless stated.

### Top level

| Field | Meaning |
| --- | --- |
| `report_id`, `run_id`, `timestamp` | The report's UUID, the node journal's run ID, and when the report was built. |
| `plan_id`, `plan_name`, `environment` | From the plan. |
| `plan_sha256` | SHA-256 of the plan file the controller read (as `sha256sum plan.yaml` prints it). |
| `validated_plan_sha256`, `resolved_plan_sha256`, `plan_digest_format` | The worker plan's digests before and after the node resolved the backup's configuration. |
| `pbs_fingerprint`, `pbs_namespace` | What the run used; `repository-sha256:` and a hash when there was no fingerprint, `root` without a namespace. |
| `validation_mode` | `full_integrity`, or test-only `test_skip_integrity`. |
| `node_fqdn`, `engine_version`, `git_commit`, `build_date`, `worker_sha256` | The node, the controller build, and the uploaded worker's SHA-256. |
| `pve_version`, `pbs_version`, `pbs_client_version`, `version_support` | Versions read on the node, and `tested`, `untested` or `unknown` ([Supported versions](compatibility.md#supported-versions)). An unsupported pair never reaches a report: the run is refused first. |
| `frameworks`, `retention_days` | From the plan's `compliance` section. Labels, not a certification. |
| `phase_timings` | Seconds per phase and the total. |
| `rto_seconds`, `rto_target_seconds` | Recovery time: for a passing run, from its start to the last passing probe (an earlier tier's soak included, teardown not); for a failed run, to the end of the run, teardown included. And the plan's objective, if any. |
| `all_passed` | `true` only when every VM and probe passed and cleanup was verified. |
| `failure_reason`, `failure_artifact` | Why the run failed (a refusal, an error, a failed probe, a missed RTO objective or unverified cleanup), and a screenshot (base64 PNG) when no VM record carries one. |
| `vm_records`, `teardown_evidence`, `admission` | Below. |

### `vm_records[]`

| Field | Meaning |
| --- | --- |
| `vmid`, `source_vmid`, `name` | Sandbox VM, source VM, plan name. |
| `verification_status` | `pending`, `booted`, `verified`, `failed`, `unverified` (no probe asserted anything in the guest) or `incomplete` (the run ended before its probes did). |
| `all_passed`, `boot_duration_seconds` | Every probe passed; start to hypervisor readiness. |
| `source_snapshot`, `pbs_verify_status` | The exact snapshot restored, and its PBS verify status. |
| `source_disks[]` | Per disk: `slot`, `archive`, `manifest_reference`, `integrity_status`, `image_digest` (SHA-256 of the whole image), `boot_source`. |
| `source_crypt_mode`, `source_signature_verified` | Weakest crypt mode (`encrypt`, `sign-only`, `none`), and whether the key verified the manifest. |
| `source_consistency` | `quiesced`, `crash-consistent`, `powered-off` or `unknown`, from the backup's log, which PBS does not sign. |
| `omitted_source_disks`, `excluded_source_disks`, `omitted_nics` | What was not restored, so a partial restore never looks whole. |
| `restored_hardware`, `copied_before_boot` | The hardware it ran with (`mac`, `cpu_weight`, `boot_order`), and whether disks were copied locally first. |
| `network_recovery_*` | What guest network recovery did, and in `network_recovery_diagnostic` (at most 16 KiB) a diagnostic when a wire probe failed with `capture_diagnostics`. |
| `failure_artifact` | A screenshot of the failed VM (base64 PNG); `report show` does not display it. |
| `probe_results[]`, `soak` | One entry per probe, and for a tier with `soak_time_sec` its repeated checks (`status_reads` counts PVE state reads). |

A disk's `integrity_status` only moves forward: `not_attempted`, `mapped` or `map_failed`, then `verified` or
`verification_failed` (a UEFI firmware disk: `verified` or `restore_failed`). Any other status is not a pass.

### `probe_results[]`

| Field | Meaning |
| --- | --- |
| `type`, `target`, `description` | As in the plan. |
| `origin` | `worker_host` (wire probes, over the sandbox network), `guest_qga` (inside the guest) or `hypervisor_qmp`. |
| `passed`, `skipped`, `duration` | `skipped`: an optional guest-agent probe found no agent. Duration in nanoseconds. |
| `detail`, `error` | Guest text, cleaned and cut to 4 KiB. |
| `timeout_sec`, `retries`, `attempts`, `require_qga`, `server_name`, `source_interface`, `source_address` | The policy it ran under. |
| `image_sha256` | A `screendump`'s image hash; the image is not kept. |

### `teardown_evidence`

| Field | Meaning |
| --- | --- |
| `vm_stopped_and_destroyed` | The sandbox VMs are gone. |
| `overlay_files_removed`, `loop_devices_unmapped` | Lists of paths and devices. A loop something still holds is named in `cleanup_errors` instead. |
| `sdn_*` | What happened to the sandbox network: removed, or (`preprovisioned`) validated and kept. |
| `orphan_sweep_clean` | Everything **this run** recorded as its own was cleaned ("Owned Resources Clean"). |
| `all_cleaned`, `verified_at` | Everything the run created is verified gone, and when. |
| `journal_recovery_verified` | The controller found the run `cleaned` in the node's journal (a consistency check: the worker writes it too). |
| `cleanup_errors`, `initial_cleanup_errors` | What could not be removed, and what a retry fixed. |

### `admission`

| Field | Meaning |
| --- | --- |
| `max_host_ram_percent`, `max_host_iowait_percent`, `defer_retry_interval_sec`, `max_defer_retries` | The plan's limits and retries as enforced. |
| `max_concurrent_boots`, `boot_settle_sec` | The boot gate, if any. |
| `recovery_reservation_mib`, `_vms`, `_tier` | Memory reserved at the peak, for how many VMs, and the highest tier level it covers. |
| `evaluation` | The last check: `decision` (`granted`, `denied_ram`, `denied_iowait`, `denied_iowait_unmeasured`, `denied_projected_ram`, `never_admissible`, `preflight_denied_memory`, `metrics_unavailable`) and what it measured. |

The controller and `verify-report` recompute this from the plan and refuse a report that contradicts it.

### Schema history

| Schema | Added |
| :--- | --- |
| 1.7 | `validated_plan_sha256`, `resolved_plan_sha256`, `plan_digest_format`; `rto_target_seconds`; `admission`, with `required_available_mib` and the decision `preflight_denied_memory`; `soak` (with `first_sample_at`, `worst_duration`, `status_reads` and more); `restored_hardware.boot_order`; `pve_version`, `pbs_version`, `pbs_client_version` and `version_support`; the optional `signature_timestamp` |
| 1.6 | `run_id`, `plan_sha256`, `worker_sha256`; the probe policy members; a VM record names its backup from the start of its restore |

## Signed reports (Enterprise) {#signed-reports-enterprise}

The Enterprise Edition signs reports ([editions](editions.md)). Anyone can check one with `verify-report`, no licence
needed. Community keeps the verifier but has no signing key or `keygen` command.

### How a report is signed

Enterprise's `certistackd` service, never the node worker, takes the report without its four unsigned members
(`signature`, `public_key`, `signer_fingerprint`, `signature_timestamp`), writes it as canonical JSON
([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)), signs those bytes with Ed25519, and adds the signature, public key
and fingerprint. Every other member is covered. Trust comes from a key you supply, never the embedded one. A valid
signature says the report is exactly what that key's holder signed, not that the recovery is good enough for you.

### The optional signature timestamp

A signature does not show *when* it was made. An optional, **unsigned** `signature_timestamp` carries a timestamp
authority's token over the signature. `verify-report` shows one status:

| Status | Evidence? |
| --- | --- |
| `none` | No timestamp (every Community report). |
| `stub` | **No.** Anyone can write one; for tests. |
| `unverified` | **No.** This build has no verifier for the authority. |
| `verified` | **Yes**: the signature existed at that time. Community ships no verifier. |

A malformed member, or one that does not cover the signature, fails verification.

### Keys

A public key file is one line of 64 hex characters. A keyring is a plain list of such keys (one per line) or JSON, at most
1 MiB:

```json
{"trusted_signers": [{"name": "controller-01", "public_key": "c7c886ebaa4d7722003b19d141d622d635607097e838e9d1c88fe87424ba76a6", "node": "pve-node-01"}]}
```

`node` and `created_at` are labels. A keyring with no entries accepts nothing. One faulty entry (a duplicate key, a key
that is not 32 bytes of hex or cannot anchor trust, an entry marked revoked, such as `"revoked": true` or
`"status": "revoked"`) refuses the whole keyring, naming it. Revocation is not evaluated: remove the entry. Get a key
by a route you trust and compare its fingerprint. Before you rotate, retire or replace a leaked key, read the signer
lifecycle in [How it works](architecture.md#6-signing-and-verification).

### Verify a signed report

Give exactly one trust source: `--keyring <file>`, `--public-key <file>` or `--trusted-key <hex>`. `verify-report` never
takes a key from the report or its directory. On the controller:

```bash
certistack verify-report --keyring /secure/certistack/trusted-signers.pub --expect-outcome pass \
  /var/lib/certistack/reports/minimal-single-vm/85a66c2e-439d-4d16-8b78-854395951f5d.json
```

```text
✓ Audit Certificate Signature VALID
...
✓ Signer Identity: TRUSTED ("controller-01")
...
  Acceptance:  ACCEPTED as pass evidence (internal consistency only; add --expect-plan, --expect-node, and --expect-version/--expect-commit to bind it to your request)
```

The [acceptance rules](#acceptance) and [exit status](#exit-status) are those of an unsigned report.

### Verify without CertiStack

An auditor can check the signature with Python and the `cryptography` and `rfc8785` packages, installed in a virtual
environment (Debian and Ubuntu refuse a system-wide `pip install`, and need `sudo apt install python3-venv` first). Save
the script below as `verify_report.py`, and pass the trusted key from your own records, never from the report:

```bash
python3 -m venv verify-env && verify-env/bin/pip install cryptography rfc8785
verify-env/bin/python verify_report.py report.json c7c886ebaa4d7722003b19d141d622d635607097e838e9d1c88fe87424ba76a6
```

```python
#!/usr/bin/env python3
"""verify_report.py report.json TRUSTED_PUBLIC_KEY_HEX"""
import json
import sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def reject_duplicates(pairs):
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        sys.exit("REJECT: a JSON object repeats a member name")
    return dict(pairs)


report_path, trusted_key_hex = sys.argv[1], sys.argv[2].strip().lower()

try:
    with open(report_path, "rb") as handle:
        report = json.load(handle, object_pairs_hook=reject_duplicates)
except ValueError as error:
    sys.exit(f"REJECT: not valid JSON: {error}")

# Trust comes from your own key, never from the report's embedded public_key.
if str(report.get("public_key", "")).lower() != trusted_key_hex:
    sys.exit("REJECT: the report was not signed by the trusted key")
if not report.get("signature"):
    sys.exit("REJECT: the report is unsigned")

signature = bytes.fromhex(report.pop("signature"))
report.pop("public_key")
report.pop("signer_fingerprint", None)
report.pop("signature_timestamp", None)  # a timestamp of the signature; not signed

try:
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_key_hex)).verify(
        signature, rfc8785.dumps(report)
    )
except InvalidSignature:
    sys.exit("REJECT: the signature does not match the report contents")

print("OK: signature valid")
print("all_passed:", report["all_passed"])
print("all_cleaned:", report.get("teardown_evidence", {}).get("all_cleaned"))
```

It checks the signature only: a signed pass over a failed probe still prints `OK`. Use a real RFC 8785 library;
`json.dumps(sort_keys=True)` writes some numbers differently and fails good reports.

<https://certistack.dev/verify/> does the same in your browser, sending nothing. It names the signer only when you paste
the signer's key or fingerprint, and it does not apply the acceptance rules or verify timestamps.
