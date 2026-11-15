# Community commitments

What the Community Edition does in a release stays free and open source. The AGPL backs these
commitments: if they are ever broken, anyone can fork the last Community release, and a test in
this repository checks the feature list below against the code.

## The commitments

1. Everything the Community Edition does today, listed under "Community feature list" below and in
   the [editions](editions.md) table, stays in Community under AGPL-3.0-or-later, with no node, VM
   or workload cap and no time limit.
2. We will not move a shipped Community feature behind the Enterprise licence, cap it, or remove it
   to make a paid plan more attractive.
3. Enterprise adds new things around the engine: the daemon, dashboard, API, binders, signed
   reports, notifications, tenants and metering. The engine, the report format and the verifier stay
   in Community, and verifying evidence never needs an account or a licence.
4. New engine capabilities land in Community first. Anything that will be Enterprise-only is
   announced as such before release, never by relabelling an existing feature.
5. No usage statistics are sent unless you opt in, and no feature depends on them. See
   [usage statistics](telemetry.md).
6. Contributors keep the copyright in their work. The
   [contributor licence agreement](https://github.com/cliftcloud/certistack/blob/main/CLA.md) lets
   Clift Cloud license a contribution under the AGPL and the Enterprise licence, and relicense
   it; what has been released under the AGPL stays available under it, and commitments 1 and 2
   cover every feature in a release.

## Community feature list

The list names commands, probe types and flags that exist in this release. The
test `TestCommunityCommitmentsFeatureListMatchesTheCode` fails if one of them
disappears from `cmd/certistack` or `pkg/config`.

- Commands: `init`, `validate`, `plan`, `check`, `setup`, `doctor`, `run`, `verify-report`, `report`, `schema`, `inspect`, `recover`, `telemetry`, `version`
- Probe types: `tcp`, `http`, `dns`, `ldap`, `mssql`, `smb`, `qga`, `qmp`, `screendump`
- Flags: `--env-file`, `--node`, `--ssh-host`, `--ssh-user`, `--ssh-port`, `--ssh-identity`, `--ssh-known-hosts`, `--ssh-sudo`, `--overlay-storage`, `--output`, `--vm`, `--all`, `--inspect`, `--fingerprint`, `--keyring`, `--public-key`, `--trusted-key`, `--unsigned`, `--format`, `--expect-plan`, `--expect-node`, `--expect-version`, `--expect-commit`, `--expect-build-date`, `--expect-worker-sha256`, `--expect-validation-mode`, `--expect-version-support`, `--expect-outcome`, `--debug`

## Moved before the first release

- **`history`.** On 2026-10-08, before the first release, the `history` command (a view, per VM, of the last pass and the recovery-time trend across the reports in a directory) moved from the Community Edition to the Enterprise Edition. It was never in a release. Nothing that shipped in a release has moved.
- **Report signing and key generation.** On 2026-10-08, before the first release, report signing and key generation moved from the Community Edition to the Enterprise Edition. This was never in a release either, and nothing that shipped in a release has moved.
    - Moved: the `keygen` command, the report signing key (its flag, its environment variable, and the `compliance.sign_key_path` that every plan had to name) and the signing of the report.
    - Now: Community writes the report of the run unsigned, and the Enterprise Edition signs it.
    - Stays: The verifier stays in Community. `verify-report` checks a signed report for anyone, and judges an unsigned one (`--unsigned`). A plan that names a `compliance.sign_key_path` is still valid in both editions.

From the first release on, commitment 2 applies to every item in the feature list.
