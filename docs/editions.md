# Editions

- **Community Edition** (this project): a command-line tool on a controller you manage, free and open source under
  AGPL-3.0-or-later. The AGPL's conditions apply only if you distribute the program, or let others use a changed version
  of it over a network ([licensing FAQ](https://github.com/cliftcloud/certistack/blob/main/LICENSING-FAQ.md)).
- **Enterprise Edition**: a commercial product on the same engine, run as a service on each Proxmox VE node
  (`certistackd`) with a dashboard. It is in early access and works node by node. Plans and prices are on
  [certistack.dev](https://certistack.dev/#licensing). An order's contents are set by its order form and the product
  documentation, not by this repository.

## Comparison

| Capability | Community (AGPL-3.0-or-later) | Enterprise (proprietary) |
| --- | --- | --- |
| Restore-test engine: read-only PBS mapping, COW overlays, isolated SDN, admission control, journal, teardown, crash recovery | Yes | The same engine |
| CLI: `init` (also `--inspect`), `validate`, `plan`, `check`, `setup`, `doctor`, `run`, `verify-report`, `report show`, `schema`, `inspect`, `recover`, `telemetry` | Yes | Uses it |
| Probes: tcp, http(s), dns, ldap, mssql, smb, qga, qmp, screendump | Yes | Yes |
| The report of every run: JSON (its RFC 8785 canonical form is what a signature covers), with the cleanup record, read in the terminal with `report show` | Yes, written unsigned | Yes, the same report |
| Signed attestations: the report signed with an Ed25519 key that the `certistackd` service keeps in a root-only file | No | Yes |
| The verifier (`verify-report`, which anyone can run with no license) | Yes | Yes |
| Scheduled runs | Not built in | Built in: schedules in the dashboard, and runs triggered by a new backup (API) |
| Plans | Written in YAML, or drafted by `init` | Also built in the dashboard from a scan of the node's backups |
| Results | One report per run | History and coverage per VM: proven, failing, never tested |
| Self-service file recovery for users without a Proxmox VE login | No | Yes, per tenant, in the dashboard, audited |
| Per-node service (`certistackd`), dashboard, HTTP API | No | Yes |
| HTML and PDF binders, evidence packs | No | Yes |
| Notifications: Slack, Teams, Discord, HaloPSA, webhooks | No | Yes |
| Tenants with their own tokens, roles, plans and reports; a hash-chained audit log | No | Yes |
| Node, VM or workload limit | None | By plan, see [pricing](https://certistack.dev/#licensing) |
| Commercial use | Yes, under the AGPL | A commercial license without copyleft, on the plans that allow it |
| Controller image, appliance template, Terraform RBAC module | Yes | Its own package |
| Support | Best effort on GitHub | Per plan; commitments only in a signed order |

## Community commitments

What the Community Edition does in a release stays free and open source. The AGPL backs this: if a commitment is ever
broken, anyone can fork the last Community release.

1. Everything Community does today, in the feature list below and the table above, stays in Community under
   AGPL-3.0-or-later, with no node, VM or workload cap and no time limit.
2. We will not move a shipped Community feature behind the Enterprise license, cap it, or remove it to make a paid plan
   more attractive.
3. Enterprise adds things around the engine: the service and its dashboard and API, built-in schedules, the plan
   builder, results and coverage, signed reports with binders and evidence packs, self-service file recovery,
   notifications and tenants. The engine, the report format and the verifier stay in Community, and verifying
   evidence never needs an account or a license.
4. Improvements to the restore-test engine land in Community first. Anything Enterprise-only is announced as such
   before release, never by relabeling an existing feature.
5. No usage statistics are sent unless you opt in, and no feature depends on them ([usage statistics](telemetry.md)).
6. Contributors keep the copyright in their work. The
   [contributor license agreement](https://github.com/cliftcloud/certistack/blob/main/CLA.md) lets Clift Cloud license
   a contribution under the AGPL and the Enterprise license, and relicense it. What was released under the AGPL stays
   available under it, and commitments 1 and 2 cover every feature in a release.

## Community feature list

A test checks this list against the code. Commitment 2 applies to every item.

- Commands: `init`, `validate`, `plan`, `check`, `setup`, `doctor`, `run`, `verify-report`, `report`, `schema`, `inspect`, `recover`, `telemetry`, `version`
- Probe types: `tcp`, `http`, `dns`, `ldap`, `mssql`, `smb`, `qga`, `qmp`, `screendump`
- Flags: `--env-file`, `--node`, `--ssh-host`, `--ssh-user`, `--ssh-port`, `--ssh-identity`, `--ssh-known-hosts`, `--ssh-sudo`, `--overlay-storage`, `--output`, `--vm`, `--all`, `--inspect`, `--fingerprint`, `--keyring`, `--public-key`, `--trusted-key`, `--unsigned`, `--format`, `--expect-plan`, `--expect-node`, `--expect-version`, `--expect-commit`, `--expect-build-date`, `--expect-worker-sha256`, `--expect-validation-mode`, `--expect-version-support`, `--expect-outcome`, `--debug`
