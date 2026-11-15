# Changelog

All notable changes to CertiStack Community Edition are documented in this
file. Enterprise Edition changes are not tracked here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-15

First public release of the Community Edition, under the GNU Affero General
Public License v3.0 or later. Tested on the author's own infrastructure: on
the final 0.1.0 code, 24 restore tests ran and all passed, among them Active
Directory forests, Windows Server 2022, SQL Server, SMB, Ubuntu 22.04, 16 VMs
started in dependency order, a batch of UEFI VMs, encrypted backups, PVE 8.4 and
PBS 3.x, and a recovery after a killed run ([what was tested](https://certistack.dev/docs/compatibility/#what-was-tested)).
Documentation: <https://certistack.dev/docs/>.

### What it does

- Restores VMs from Proxmox Backup Server backups into an isolated sandbox on
  Proxmox VE, checks that their services answer, removes everything again and
  verifies that nothing is left. A run passes only when its probes passed and
  its cleanup was verified.
- Maps every backup read-only and boots the VM from copy-on-write overlays.
  The sandbox network has no gateway and no uplink. Your backups and your VMs
  are never written.
- Runs from a controller (a Linux machine, the unprivileged controller image,
  or a controller VM from the Packer template). A short-lived worker on the
  node does the node-local work and is removed after each run; nothing is
  installed permanently.
- Restores disks on every bus, UEFI VMs with their variable store and TPM
  state, and encrypted backups.
- Boots VMs in dependency order (tiers), reads and checksums every disk once,
  and holds a run while the node is short of memory.
- Keeps a journal on the node, so `certistack recover` can finish the cleanup
  of a run that was interrupted or whose controller crashed.

### Commands

- `setup`: a first-run wizard that connects the controller to a node and its
  PBS. It asks before every change and ends with `check`.
- `init`: writes a first plan from the VMs that have backups, valid as it is
  written, after saying what a run of it will read and reserve. `--inspect`
  looks inside each Linux VM's backup, read-only, and writes a probe for each
  service it finds.
- `check`, `validate`, `plan`, `doctor`: check the controller, a plan and a
  node before a run, without changing anything.
- `run`: runs a plan and writes the report.
- `report show` and `verify-report`: read a report, and judge whether it is
  acceptable evidence.
- `schema`, `inspect`, `recover`, `telemetry`, `version`.

### Probes

`tcp`, `http` and HTTPS, `dns`, `ldap`, `mssql` (including SQL Server's
TDS 8.0 strict encryption), `smb`, and `qga` commands inside the guest through
the QEMU guest agent. `qmp` and `screendump` record supporting evidence.

### Reports

A report is JSON (schema 1.7) with the outcome, every probe, each disk's
checksum, the recovery time, the exact backup used and the proof of cleanup.
The Community Edition writes it unsigned; the Enterprise Edition signs it.
`verify-report` judges a report against what you expected, and a valid
signature alone is never a pass.

### Supported versions

Proxmox VE 9.x and 8.4, each with PBS 3.x or 4.x, on linux/amd64. Other PVE 8
releases, and newer major releases, run with a warning; PVE 7 and PBS 2 are refused.

### Privacy

Anonymous usage statistics are opt-in and off by default: five fields, shown
exactly by `certistack telemetry show`, at most once a day after a completed
run, and never from the PVE node. `CERTISTACK_TELEMETRY=1` keeps its install id
and the time of its last report in `telemetry.json` for that, and sends nothing
where it cannot. The cluster count counts Proxmox VE clusters, by their CA
certificate. `DO_NOT_TRACK=1` turns them off outright.

### Security

- SSH host keys are always verified, and a plan cannot turn off TLS
  verification.
- Credentials and PBS client output are kept out of logs, errors and reports.
- Releases are reproducible builds with a GPG-signed checksum list and build
  provenance.

### Known limits

- The controller's SSH key is root on the node, and on every node of a cluster.
- On a cluster, each run reloads the network on all nodes at its start and end;
  a pre-provisioned sandbox network avoids it.
- The sandbox is one flat network, and probes run from the node's worker.
- One CertiStack operation runs on a node at a time, and the node's clock must
  be within 10 minutes of the controller's.

The full list is in [Tested and supported](https://certistack.dev/docs/compatibility/).
