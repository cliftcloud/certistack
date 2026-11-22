# Reports

Every run writes one JSON report: which backup was restored, what the probes found, and whether the cleanup was
verified. Community reports are unsigned.

## Where reports go

`run` prints the path on its `Controller report saved to:` line:

```text
<output directory>/<plan_id>/<report_id>.json
```

- The output directory is `/var/lib/certistack/reports` unless you set `--output` or `CERTISTACK_OUTPUT_DIR`. A run
  refuses one that group or other users can write: its permissions are what keep an unsigned report as written.
- A failed validation still writes a report. A run that never created evidence (an SSH failure, a busy node) writes
  none.
- A run refused before any restore, for capacity or for its Proxmox versions, writes a report with no VM, an
  `rto_seconds` of `0` and no memory reserved; `report show` says so.
- If the report cannot be saved, `run` exits `2` and prints it between `-----BEGIN CERTISTACK REPORT-----` and
  `-----END CERTISTACK REPORT-----` lines.
- A worker result that does not match the plan, node or run is kept as
  `<output directory>/refused/<run-id>.refused.txt`. It is not a report and not evidence.
- CertiStack never edits, rotates or deletes a report; `retention_days` prunes nothing.

## Read a report

```bash
certistack report show /var/lib/certistack/reports/<plan_id>/<report_id>.json
```

It prints the outcome, plan, node, build, versions and recovery time, then each VM (snapshot, disks, what was not
restored, probes, and any network diagnostic) and the teardown. A good report shows:

- `Outcome: PASS` and `Validation: full_integrity`
- every disk `verified` under the VM's `Integrity`
- every probe `PASS`
- `cleanup verified` under `Teardown`

With no file named, `certistack report show` shows the newest report. No run yet? In a clone of the repository,
`certistack report show examples/sample-report-unsigned.json` shows one.

## Verify a report

`verify-report` judges a report and sets its exit status. For a Community report, on the controller:

```bash
certistack verify-report --unsigned --expect-outcome pass \
  /var/lib/certistack/reports/minimal-single-vm/85a66c2e-439d-4d16-8b78-854395951f5d.json
```

Without `--unsigned`, an unsigned report is refused. With it, the contents are judged but nothing is authenticated:
anyone can write a file that says anything. For the outcome `pass` (the default), a report is accepted only when:

- its schema is one this verifier knows, and its mode is `full_integrity`;
- every planned VM is there once, `verified` and passing, with a wire or `qga` probe that ran;
- no wire-probe address passes for two VMs;
- every disk is `verified`, the boot disk among them;
- each VM names a whole `vm/<id>/<time>` snapshot of its own source VM;
- the teardown is `all_cleaned`, with no unresolved cleanup error.

| Exit | Meaning |
| --- | --- |
| `0` | The report was read and, with an `--expect-*` flag, accepted |
| `1` | An `--expect-*` flag was given and the report is not accepted |
| `2` | The report cannot be trusted or read |

Without an `--expect-*` flag, a failed validation still exits `0`. Pass `--expect-outcome pass`, or read
`acceptance.verdict` from `--format json`.

### Bind the verdict to your plan

The `--expect-*` flags tie the verdict to the run you asked for:

```bash
certistack verify-report --unsigned --format json \
  --expect-plan my-first-plan.yaml \
  --expect-node pve-node-01 \
  /var/lib/certistack/reports/<plan-id>/<report-id>.json
```

| Flag | Requires |
| --- | --- |
| `--expect-plan` | Exactly this plan: its ID, VMs, probes and their policy, RTO objective, admission limits, disks, pinned snapshot, and the file's SHA-256 (an edited comment rejects the report) |
| `--expect-node` | The PVE node that ran the worker |
| `--expect-version`, `--expect-commit`, `--expect-build-date` | The build's labels |
| `--expect-worker-sha256` | The uploaded executable: for a release, the published checksum of `certistack-linux-amd64` |
| `--expect-version-support` | `tested` or `untested` as recorded |
| `--expect-outcome fault` | A fault drill: only the first probe of the plan's first VM failed, cleanup verified. Needs `--expect-plan` |
| `--expect-outcome denied` | A capacity refusal before any restore: by admission, or by the node's memory check. No outcome accepts a refusal for another reason, such as unsupported versions |

An `--expect-*` check that a report is too old to answer shows as `NOT BOUND`; it is not skipped. All flags:
[Commands](configuration.md#verify-report).

`all_cleaned: true` with `all_passed: false` is a clean negative result. If `all_cleaned` is `false`, recover the node
before the next run ([Issue 35](troubleshooting.md#issue-35)).

## Main fields

The report schema is `1.7`.

| Field | Meaning |
| --- | --- |
| `all_passed` | `true` only when every VM and probe passed and cleanup was verified |
| `failure_reason` | Why the run failed |
| `validation_mode` | `full_integrity`, or test-only `test_skip_integrity`, which is not evidence |
| `rto_seconds`, `rto_target_seconds` | The recovery time (`0` when no VM was restored), and the plan's objective |
| `plan_sha256` | The SHA-256 of the plan file the controller read |
| `node_fqdn`, `engine_version`, `worker_sha256` | The node, the build, and the uploaded worker's SHA-256 |
| `pve_version`, `pbs_version`, `pbs_client_version`, `version_support` | Versions read on the node, and `tested`, `untested` or `unknown`; `unsupported` only in the report of a run refused for them |
| `frameworks`, `retention_days` | From the plan's `compliance` keys |
| `vm_records[].verification_status` | `verified`, `failed`, `unverified` (no probe checked the guest) or `incomplete` |
| `vm_records[].source_snapshot` | The exact snapshot restored |
| `vm_records[].source_disks[]` | Each disk's `integrity_status` and `image_digest` |
| `vm_records[].source_consistency` | `quiesced`, `crash-consistent`, `powered-off` or `unknown`, from the backup's log |
| `vm_records[].omitted_source_disks` | Disks not restored, so a partial restore never looks whole |
| `vm_records[].probe_results[]` | Per probe: `passed`, `skipped`, `detail`, `error` and the policy it ran under |
| `teardown_evidence.all_cleaned` | Everything the run created is verified gone |
| `admission.evaluation` | The last capacity check and its `decision` |

## Keep a report tamper-evident

An unsigned report cannot show that nobody changed it. Record its SHA-256 where nobody can rewrite it, such as
write-once storage or a change ticket:

```bash
sha256sum /var/lib/certistack/reports/<plan_id>/<report_id>.json
```

Never edit a report; run the validation again instead.

## Signed reports (Enterprise)

The [Enterprise Edition](editions.md) signs reports with Ed25519 over canonical JSON (RFC 8785). Community's
`verify-report` checks them, with exactly one key source you supply (`--keyring`, `--public-key` or `--trusted-key`),
never a key from the report:

```bash
certistack verify-report --keyring /secure/certistack/trusted-signers.pub --expect-outcome pass \
  /var/lib/certistack/reports/minimal-single-vm/85a66c2e-439d-4d16-8b78-854395951f5d.json
```

A valid signature shows who signed the report, not that the recovery is good enough: the acceptance rules above still
apply. <https://certistack.dev/verify/> checks a signature in your browser and sends nothing.
