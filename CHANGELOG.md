# Changelog

All notable changes to CertiStack Community Edition are documented in this file. Enterprise Edition changes are not
tracked here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-18

First public release, under the GNU Affero General Public License v3.0 or later. Documentation:
<https://certistack.dev/docs/>.

Tested on the author's own infrastructure: on the exact v0.1.1 binary, 24 restore tests ran and all passed, among them
Active Directory forests, Windows Server 2022, SQL Server, SMB, Ubuntu 22.04, 16 VMs started in dependency order, a
batch of UEFI VMs, encrypted backups, PVE 8.4 and PBS 3.x, and a recovery after a killed run
([what was tested](https://certistack.dev/docs/compatibility/#what-was-tested)).

### What it does

- Restores VMs from Proxmox Backup Server into an isolated sandbox on Proxmox VE, checks that their services answer,
  removes everything and verifies that nothing is left. A run passes only when its probes passed and its cleanup was
  verified.
- Maps every backup read-only and boots the VM from copy-on-write overlays, on a sandbox network with no gateway and no
  uplink. Your backups and your VMs are never written.
- Runs from a controller: a Linux machine or the unprivileged controller image. A short-lived worker does the node-local
  work and is removed after each run. A Packer template for a controller VM is included; it has not yet been built
  against a live PVE.
- Restores disks on every bus, UEFI VMs with their variable store and TPM state, and encrypted backups.
- Boots VMs in dependency order (tiers), reads and checksums every disk once, and holds a run while the node is short
  of memory.
- Keeps a journal on the node, so `certistack recover` can finish the cleanup of an interrupted run.

### Commands

- `setup`: connects the controller to a node and its PBS, asks before every change, and ends with `check`. Later
  commands use the environment file it wrote, so they need no `--env-file`.
- `init`: writes a valid first plan from the VMs that have backups, and says what a run of it will read and reserve.
  `--inspect` reads each Linux VM's backup and writes a probe for each service it finds.
- `check`, `validate`, `plan`, `doctor`: check the controller, a plan and a node before a run, changing nothing.
- `run`: runs a plan and writes the report.
- `report show`, `verify-report`: read a report, and judge whether it is acceptable evidence.
- `schema`, `inspect`, `recover`, `telemetry`, `version`.

### Probes

`tcp`, `http` and HTTPS, `dns`, `ldap`, `mssql` (including TDS 8.0 strict encryption), `smb`, and `qga` commands run
through the QEMU guest agent. `qmp` and `screendump` record supporting evidence.

### Reports

A report is JSON (schema 1.7) with the outcome, every probe, each disk's checksum, the recovery time, the exact backup
used and the proof of cleanup. The Community Edition writes it unsigned; the Enterprise Edition signs it.
`verify-report` judges a report against what you expected; a valid signature alone is never a pass.

### Supported versions

Proxmox VE 9.x and 8.4, each with PBS 3.x or 4.x, on linux/amd64. Other PVE 8 releases and newer major releases run
with a warning; PVE 7 and PBS 2 are refused.

### Privacy

Anonymous usage statistics are opt-in and off by default: five fields, shown by `certistack telemetry show`, sent at
most once a day after a completed run and never from the PVE node. Clusters are counted by their CA certificate.
`DO_NOT_TRACK=1` turns them off outright.

### Security

- SSH host keys are always verified, and a plan cannot turn off TLS verification.
- Credentials and PBS client output are kept out of logs, errors and reports.
- Releases are reproducible builds with a GPG-signed checksum list and build provenance.

### Known limits

- The controller's SSH key is root on the node, and on every node of a cluster.
- On a cluster, each run reloads the network on all nodes at its start and end; a pre-provisioned sandbox network
  avoids it.
- The sandbox is one flat network, and probes run from the node's worker.
- One CertiStack operation runs on a node at a time, and the node's clock must be within 10 minutes of the
  controller's.

The full list is in [Compatibility](https://certistack.dev/docs/compatibility/#known-limits).

[Unreleased]: https://github.com/cliftcloud/certistack/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/cliftcloud/certistack/releases/tag/v0.1.1
