<p align="center">
  <img src="docs/assets/icon.png" alt="CertiStack" width="88">
</p>

<h1 align="center">CertiStack</h1>

<p align="center">
  <strong>Restore-test your Proxmox backups in an isolated sandbox.</strong>
</p>

<p align="center">
  <a href="https://github.com/cliftcloud/certistack/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/cliftcloud/certistack"></a>
  <a href="LICENSE"><img alt="License: AGPL-3.0-or-later" src="https://img.shields.io/badge/license-AGPL--3.0--or--later-blue"></a>
  <a href="https://github.com/cliftcloud/certistack/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cliftcloud/certistack/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://certistack.dev/docs/"><img alt="Docs" src="https://img.shields.io/badge/docs-certistack.dev-informational"></a>
</p>

---

Your Proxmox Backup Server says the backup is **verified**. That means the stored chunks are intact.
It does not mean the VM boots, that its disks are whole, or that the database inside it answers.
Without a restore test, you find that out on the day you need the backup.

**CertiStack finds out now.** It restores a VM from your PBS into an isolated sandbox on your
Proxmox VE node, boots it, checks that its services answer, removes everything again, and tells you
whether the VM came back and the probes you chose passed.

```text
$ certistack report show --keyring demo-trusted-signers.pub sample-pass.json
…
Outcome:       PASS
Plan:          recovery-pve-demo-01 "Recovery check of 1 VM(s) on pve-demo-01"
Proxmox:       PVE 9.2.2, PBS 4.2.0, proxmox-backup-client 4.2.0 (tested)
Validation:    full_integrity: every mapped disk image was read back and checksummed

RTO:           5m 43s (342.95 s); no objective set

  VM 9100 "cs-rocky-web"  PASS
    Restored from:     source VM 100, snapshot vm/100/2026-10-05T13:32:03Z
    Network recovery:  ifcfg, sandbox address 192.0.2.10, 3m 34s of offline preparation
    Integrity:         scsi0 verified, sha256 7f59c0196f93…
    Probes (1):
      PASS http http://192.0.2.10:80/  (from the worker host over the sandbox network, 33.1 s, 1 attempt)

Teardown:
  cleanup verified (at 2026-10-05T14:02:59Z)
  sandbox VM destroyed: yes; 1 overlay disk(s) removed; 1 loop device(s) unmapped
  sandbox network: removed: zone csZone1, VNet csVnet1
```

<sub>An excerpt of a real report from a test run on a demo node, signed with a demo key; Community reports are
unsigned. The whole report, its key and how to check it are on the [verify page](https://certistack.dev/verify/).</sub>

## How it works

1. **Maps the backup read-only.** The PBS snapshot is mapped as a block device; nothing can write to it.
2. **Boots a throwaway copy.** The VM starts from a copy-on-write overlay, so every write lands in a scratch file
   that is deleted afterwards. Your real VM is never touched.
3. **Isolates it.** The sandbox gets its own SDN network with no gateway, no NAT and no uplink. A restored domain
   controller cannot reach your production network.
4. **Checks that it works.** Not just "it booted": the probes you choose run against it. They can be TCP, HTTP(S),
   DNS, LDAP, SQL Server, SMB, or commands through the guest agent, in the order your tiers need (a database before
   the app that uses it).
5. **Cleans up, and verifies it.** The VM, the overlays and the network are removed, and the report records that
   nothing is left. **A run passes only if every check passed and the cleanup was verified.** If anything crashes
   mid-run, `certistack recover` finishes the cleanup.

## Why you can point it at a real node

- **Your backups are only read** and your VMs are never written.
- **Nothing reaches production**: the sandbox network has no way out.
- **It asks first.** `certistack setup` shows each change it makes on your node and PBS and waits for a yes.
  [What it changes on your node](https://certistack.dev/docs/manual-setup/#what-it-changes) lists all of it on one page, and
  [Remove CertiStack](https://certistack.dev/docs/manual-setup/#remove-certistack) takes the access back off and lists
  what stays.
- **It holds a run** while the node is short of memory, and runs one test per node at a time.
- **It runs from a small Linux VM**, not on the Proxmox VE host; a short-lived worker does the node's part and is
  removed after each run.

## Quickstart

On a small Linux VM (not the Proxmox VE host), run these one at a time. Use a standalone node, or one you can take out
of service, for a first run: on a cluster, each run applies an SDN change, which reloads the network on every node.

```bash
curl -fsSL https://certistack.dev/install.sh | bash   # checks the release's signature and checksums
certistack setup                                       # connects to your node and PBS, asking before each change
certistack init                                        # lists the VMs that have a backup
certistack init --vm 102 -o my-first-plan.yaml         # a plan for one small VM from that list
certistack run my-first-plan.yaml                      # about 5 to 20 minutes for a small VM
certistack report show
```

`setup` ends with a six-layer check, and the commands after it use the settings it saved, including the reports
directory that `report show` reads. `init --inspect` looks inside a Linux backup and adds a probe for each service it
finds. The [quickstart](https://certistack.dev/docs/quickstart/)
walks through each step with its output. [Read the installer](https://github.com/cliftcloud/certistack/blob/main/scripts/install.sh)
first, or [install by hand](https://certistack.dev/docs/quickstart/#install-by-hand); no `sudo`? See
[Install without sudo](https://certistack.dev/docs/quickstart/#install-without-sudo).

## What it handles

| | |
| --- | --- |
| **Guests** | Linux (its network set to the sandbox's), Windows Server and Active Directory, SQL Server, file servers |
| **Disks** | Every bus (SCSI, VirtIO, SATA, IDE), UEFI with its variable store and TPM state, several disks per VM, each read back and checksummed |
| **Backups** | Plain and encrypted PBS backups, any namespace, the newest snapshot or a pinned one |
| **Scale** | Several VMs per plan, started tier by tier in dependency order |
| **Proxmox** | Proxmox VE 9.x and 8.1 to 8.4, each with PBS 3.x or 4.x, on amd64 ([compatibility](https://certistack.dev/docs/compatibility/)) |
| **Reports** | JSON with the outcome, every probe, each disk's checksum, the recovery time against your objective and the cleanup record; `report show` reads it, `verify-report` judges it |

## How it was tested

CertiStack is used by the Clift Cloud team and its clients to restore-test their Proxmox backups. Before this release it
was tested on a 14-node Proxmox VE lab and standalone hosts:

- **More than 10,000 VM restore tests** in over 4,800 runs, from September to November 2026: 471 different VMs, up to
  100 in one run, on 20 Proxmox VE hosts (PVE 9.2 and 8.4, PBS 4.x and 3.x), with over 15,000 service checks.
- **Windows:** Server 2012, 2016, 2019, 2022 and 2025, Active Directory domain controllers, SQL Server, IIS, SMB file
  servers, Windows 10 and 11.
- **Linux and more:** Rocky Linux, Ubuntu, Debian, Oracle Linux, AlmaLinux, CentOS, RHEL, Amazon Linux, Fedora and
  others, running PostgreSQL, MariaDB, Redis, nginx, DNS and LDAP; FreeBSD; MikroTik RouterOS, pfSense and OPNsense.
- **The release binary itself** passed the full release set: Active Directory forests, Windows Server 2022, SQL Server,
  SMB, Ubuntu, 16 VMs started in dependency order, a UEFI fleet, encrypted backups, PVE 8.4 with PBS 3.x, and a run
  killed halfway and finished by `recover`.
- **Over 7,000 automated tests** on the release commit, **more than 3.6 million fuzzed inputs** to its parsers, and
  **fault injection**: hostile inputs, misbehaving Proxmox servers, corrupt and impossible backups, and runs killed
  midway. In these tests every case was refused before anything was created, or failed safely and left the node clean;
  none passed falsely.

[What was tested, on which build](https://certistack.dev/docs/compatibility/#what-was-tested).

## Community and Enterprise

### Community: the whole engine, free

Everything above is the Community Edition, and it is yours to keep:

- **Free under the AGPL**, with no node, VM or time limit. Commercial use is included, MSPs too.
- **Nothing held back from the engine**: every guest, disk, backup type and probe on this page, the isolated sandbox,
  the verified cleanup and crash recovery.
- **No account and no license key.** Usage statistics are opt-in.
- **What it does stays in Community** ([commitments](https://certistack.dev/docs/editions/#community-commitments)).

You run a test when you choose, from the command line, and read the report in the terminal.

### Enterprise: restore tests that run themselves, and proof you can hand over

Community tells you whether a backup restores when you ask. Enterprise checks for you, on a schedule, for every VM,
and keeps the proof. It is the same engine, run as a service on each Proxmox VE node, with a dashboard and an HTTP API.

<p align="center">
  <a href="https://certistack.dev/#enterprise"><img src="https://certistack.dev/img/enterprise/results.png" width="820" alt="The Enterprise Results screen: each VM with its plan, a Passing, Failing or No pass in 30 days status, the last pass, the last failure and its reason, the recovery time and the pass rate."></a>
</p>

- **Every VM at a glance.** Passing, failing or no pass in 30 days, the last failure and why, the recovery time against
  your objective and the pass rate. The VMs nobody has tested stand out.
- **It runs on its own.** Schedules in your time zone, blackout windows, a rule for runs the node missed, and a run
  whenever a new backup lands (through the API).
- **Plans without YAML.** A read-only scan of the node's backups; pick the VMs, group them, choose the tests, preview,
  save.
- **Proof you can hand over.** Every report is signed with an Ed25519 key. HTML and PDF binders, and evidence packs that
  put a period's signed reports in one file. An auditor, a client or an insurer can check them without a license.
- **Alerts you can test.** Slack, Teams, Discord, HaloPSA or a webhook when a test fails or finishes, set up in a form
  and tested with one button.
- **Self-service file recovery.** A client opens its own backup read-only and downloads a file or a folder, with no
  Proxmox VE login. Every download is audited.
- **Made for MSPs.** A tenant per client, with its own tokens, roles, plans and reports, and a tamper-evident audit log.
- **A commercial license** without copyleft.

<table>
  <tr>
    <td width="50%"><a href="https://certistack.dev/#enterprise"><img src="https://certistack.dev/img/enterprise/plan-builder.png" alt="The plan builder: a read-only scan of the node's backups, which found six VMs with a complete backup."></a><br><sub><b>Plan builder</b>: from a scan of your backups to a saved plan.</sub></td>
    <td width="50%"><a href="https://certistack.dev/#enterprise"><img src="https://certistack.dev/img/enterprise/schedules.png" alt="The Schedules screen: a saved plan put on a calendar."></a><br><sub><b>Schedules</b>: daily, weekly, monthly or every few hours.</sub></td>
  </tr>
  <tr>
    <td width="50%"><a href="https://certistack.dev/#enterprise"><img src="https://certistack.dev/img/enterprise/recover-files.png" alt="Recover files: a backup opened read-only, its folders listed with a download button for each file."></a><br><sub><b>Recover files</b>: a file or a folder from a backup, no Proxmox VE login.</sub></td>
    <td width="50%"><a href="https://certistack.dev/#enterprise"><img src="https://certistack.dev/img/enterprise/alerts.png" alt="The Alerts screen: a route to a Microsoft Teams channel, tested from the page, with the result Delivered."></a><br><sub><b>Alerts</b>: Slack, Teams, Discord, HaloPSA, webhooks.</sub></td>
  </tr>
</table>

Enterprise is in early access, with plans from a homelab to an MSP fleet:
[see it and the plans](https://certistack.dev/#enterprise), or write to
[sales@certistack.dev](mailto:sales@certistack.dev). It is installed node by node; a central fleet
controller is not built yet. The screenshots are the dashboard with demo data.

<details>
<summary>The two editions, feature by feature</summary>

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

</details>

## Documentation and help

- **Docs:** [certistack.dev/docs](https://certistack.dev/docs/): the [quickstart](https://certistack.dev/docs/quickstart/),
  [plans](https://certistack.dev/docs/plan-reference/), [commands and settings](https://certistack.dev/docs/configuration/), [reports](https://certistack.dev/docs/reports/),
  [troubleshooting](https://certistack.dev/docs/troubleshooting/), [your node](https://certistack.dev/docs/manual-setup/), [changelog](CHANGELOG.md).
- **Questions:** [SUPPORT.md](SUPPORT.md). **Vulnerabilities:** [SECURITY.md](SECURITY.md), reported privately.
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md).

## Privacy

Usage statistics are off by default and opt-in (asked once; Enter means no). Otherwise CertiStack
connects only to the PVE, PBS and SSH endpoints you name ([usage statistics](https://certistack.dev/docs/telemetry/)).

## License

AGPL-3.0-or-later ([LICENSE](LICENSE), [licensing FAQ](LICENSING-FAQ.md)). Built and maintained by Clift Cloud LLC.
Releases are reproducible builds with GPG-signed checksums and attested provenance ([SECURITY.md](SECURITY.md));
upgrading is a binary swap. "CertiStack" and the CertiStack logo are trademarks of Clift Cloud LLC and are not
covered by the AGPL grant; see [NOTICE](NOTICE).
