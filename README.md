# CertiStack Community Edition

**Prove your Proxmox backups actually restore.** CertiStack boots a VM from its Proxmox Backup Server
backup in an isolated sandbox on your Proxmox VE node, checks that its services answer, removes
everything again, and writes a report. Your backups are only read, and your VMs are never touched.

- **Tested:** 24 of 24 restore tests passed on the final v0.1.0 code, on the author's own
  infrastructure: Active Directory, Windows Server 2022, SQL Server, SMB, Ubuntu 22.04, 16 VMs
  started in dependency order, a batch of UEFI VMs, encrypted backups, PVE 8.4 and PBS 3.x
  ([what was tested](docs/compatibility.md#what-was-tested), and what was not).
- **Why not PBS verify?** Verify checks that the stored data is intact; it boots nothing.
  CertiStack checks that the VM starts and its services answer, the same way every time.
- **Pass or fail:** your probes decide (TCP, HTTP(S), DNS, LDAP, SQL Server, SMB, guest agent), and
  a run passes only if its cleanup was verified too.
- **Licence:** AGPL-3.0-or-later, no node or VM limit, commercial use allowed.

Setup asks before every change it makes on your node and PBS. [What it changes on your node](docs/what-it-changes.md)
lists them all, and [Remove CertiStack](docs/undo.md) takes them back off.

## Quickstart

On a small Linux VM (not the Proxmox VE host), run these one at a time. The first installs the CLI
after checking the release's signature and checksums
([read it](https://github.com/cliftcloud/certistack/blob/main/scripts/install.sh) first, or
[install by hand](docs/going-further.md#install-by-hand)):

```bash
curl -fsSL https://certistack.dev/install.sh | bash
certistack setup
certistack init --env-file /secure/certistack/controller.env
# Lists the VMs that have a backup. Put a small one's VMID after --vm (102 is a sample).
certistack init --env-file /secure/certistack/controller.env --vm 102 -o my-first-plan.yaml
certistack plan my-first-plan.yaml --env-file /secure/certistack/controller.env
certistack run my-first-plan.yaml --env-file /secure/certistack/controller.env
certistack report show "$(ls -t /var/lib/certistack/reports/*/*.json | head -n 1)"
```

A first run on a small VM takes about 6 to 20 minutes. The [quickstart](docs/quickstart.md) walks
through each step with its output. No `sudo`? See
[Install without sudo](docs/going-further.md#install-without-sudo).

## Community and Enterprise

Community is the whole restore-test engine, with no node or VM limit and no time limit, and what it does stays
in Community ([commitments](docs/community-commitments.md)). The Enterprise Edition is a separate,
commercial product that runs the same engine as a service with a dashboard and signed reports
([certistack.dev](https://certistack.dev/#licensing)).

<details>
<summary>The two editions, feature by feature</summary>

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

</details>

## Privacy

Usage statistics are off by default and opt-in (asked once; Enter means no). Otherwise CertiStack
connects only to the PVE, PBS and SSH endpoints you name ([docs/telemetry.md](docs/telemetry.md)).

## Project

Built and maintained by Clift Cloud LLC. Releases are reproducible builds with GPG-signed
checksums and attested provenance ([SECURITY.md](SECURITY.md)); upgrading is a binary swap. If the
project ever stops, the AGPL lets anyone fork it.

**Documentation:** [overview](docs/index.md), [quickstart](docs/quickstart.md),
[FAQ](docs/faq.md), [what it changes on your node](docs/what-it-changes.md),
[when something fails](docs/troubleshooting.md), [tested and supported](docs/compatibility.md),
[changelog](CHANGELOG.md).

Getting help: [SUPPORT.md](SUPPORT.md). Reporting a vulnerability: [SECURITY.md](SECURITY.md).
Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Licence: [LICENSE](LICENSE) and
[LICENSING-FAQ.md](LICENSING-FAQ.md).

"CertiStack" and the CertiStack logo are trademarks of Clift Cloud LLC and are
not covered by the AGPL grant; see [NOTICE](NOTICE).
