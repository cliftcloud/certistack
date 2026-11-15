# Editions

This repository is the open source **Community Edition**. The **Enterprise Edition** is a separate,
commercial product built on the same engine. Plans and prices are on
[certistack.dev](https://certistack.dev/#licensing).

## Community Edition

- Free and open source under the GNU Affero General Public License, version 3 or any later version
  (AGPL-3.0-or-later). No limit on nodes or VMs, and commercial use is allowed. The AGPL's
  conditions apply only if you distribute the program, or let others use a changed version of it
  over a network ([licensing FAQ](https://github.com/cliftcloud/certistack/blob/main/LICENSING-FAQ.md)).
- A command-line tool on a controller you manage. A run uses a temporary worker on the node and
  installs nothing permanent there.
- Support on GitHub, best effort, with no response-time commitment.
- What it does today stays in it: see [Community commitments](community-commitments.md).

## Enterprise Edition

A commercial product that runs the same engine as a service on each Proxmox VE node (`certistackd`),
with a dashboard, an HTTP API, signed reports, HTML and PDF evidence binders, notifications and
webhooks, and tenant separation for MSPs. An order's contents are set by its order form and the
product documentation, not by this repository.

## Comparison

| Capability | Community (AGPL-3.0-or-later) | Enterprise (proprietary) |
| --- | --- | --- |
| Restore-test engine: read-only PBS mapping, COW overlays, isolated SDN, admission control, journal, teardown, crash recovery | Yes | The same engine |
| CLI: `init` (also `--inspect`), `validate`, `plan`, `check`, `setup`, `doctor`, `run`, `verify-report`, `report show`, `schema`, `inspect`, `recover`, `telemetry` | Yes | Uses it |
| Probes: tcp, http(s), dns, ldap, mssql, smb, qga, qmp, screendump | Yes | Yes |
| The report of every run: JSON (its RFC 8785 canonical form is what a signature covers), with the cleanup record, read in the terminal with `report show` | Yes, written unsigned | Yes, the same report |
| Signed attestations: the report signed with an Ed25519 key that the `certistackd` service keeps in a root-only file | No | Yes |
| The verifier (`verify-report`, which anyone can run with no licence) and a script that verifies a signed report without CertiStack | Yes | Yes |
| Node, VM or workload limit | None | By plan, see the pricing page |
| Commercial use | Yes, under the AGPL | A commercial licence without copyleft, on the plans that allow it |
| Controller image, appliance template, Terraform RBAC module, `systemd` and `cron` guidance | Yes | Its own package |
| Per-node service (`certistackd`), dashboard, HTTP API | No | Yes |
| HTML and PDF binders | No | Yes |
| Notifications and webhooks | No | Yes |
| Entitlements, metering, tenant separation, partner operations | No | Yes |
| Support | Best effort on GitHub | Per plan; commitments only in a signed order |

## The boundary

The engine, the plan format, the report format and the verifier are Community. Signing, rendering,
delivery, a built-in scheduler, tenants and entitlements are Enterprise; `cron` and `systemd`
timers work with Community. Enterprise imports Community packages, never the other way round.

The Community source contains no API token, production signing key, customer data or Enterprise
source. The sample report comes from a lab run, and the test signing keys are throwaway.
