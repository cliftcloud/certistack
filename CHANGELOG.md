# Changelog

All notable changes to CertiStack Community Edition are documented in this file. Enterprise Edition changes are not
tracked here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2026-11-24

### Fixed

- The verification scan of a mapped backup no longer reads part of the image a second time. A read-ahead worker held
  up on a busy controller could read a part the scan had already hashed and released, again from PBS, and leave it in
  the page cache; it now skips what the scan has passed, and the scan releases the whole image once more at the end.

### Changed

- Built with Go 1.27.4 (the release binary and the controller image's build stage).
- Terraform module: `bpg/proxmox` 0.123.1 (`~> 0.123.1`), which refuses an API redirect to plain http. An existing
  state needs no change: the plan after the upgrade is empty.
- `init`'s next step says the plan is valid as written and that the probes marked `CHANGE` are where to check the
  service a VM provides; `plan`'s version line reads `tested: the pair the release evidence covers`.
- Documentation: that installing setup's packages rebuilds the node's initramfs and boot menu, how to remove them
  with their configuration, the PBS host keys and `/secure` that stay after a removal, and how long a first run takes.

### Privacy

- The opt-in usage statistics are unchanged: off by default; `certistack telemetry show` prints exactly what would be
  sent.

## [0.1.2] - 2026-11-22

### Fixed

- Runs on Proxmox VE 8.1 to 8.3 no longer stop before the restore with `cannot establish whether VM … already exists`.
  These releases answer a request about a missing VM with the error text in the HTTP status line only, which
  CertiStack now reads.
- `check`, and the check that ends `setup`, fail a node that `init`, `plan` or `run` would refuse: a Proxmox VE release
  older than the oldest supported, a node without PVE's SDN API (PVE 8.0 without `libpve-network-perl`), or a
  `proxmox-backup-client` older than version 3. Each failure prints its fix.
- `setup` refuses such a node when it reads it, with the same reason and fix, before it changes anything on the node or
  the PBS; it used to make every change and fail only in its closing check.
- `init --vm` on a node without the SDN API says what is missing and how to add it, and any other PVE API error it
  meets names the request PVE refused.
- The report of a run refused before any restore claims nothing that did not happen: it records the Proxmox versions
  the run read (`version_support` is `unsupported` when they are why it was refused), no recovery time and no sandbox
  VM. `report show` says that no disk image was read and no memory was reserved, and suggests
  `--expect-outcome denied` for a capacity refusal.
- The line of a run waiting for memory names the memory in use plus the reservation, the sum its percentage is taken
  from.
- `setup` shows a PBS certificate fingerprint it takes itself (from the node's PBS storage, from the PBS over `ssh`, or
  from an earlier `controller.env`) and asks whether the PBS dashboard shows the same before it changes anything on
  the PBS or writes `controller.env`; a No stops it there. It also says which checks a usable node passed.
- Messages name documentation pages by their address on certistack.dev instead of a path in the repository.
- Controller appliance: the `certistack-controller` wrapper works with Podman 4.3 (Debian 12), which refused its tmpfs
  options.
- Controller appliance recipe: the build VM finds its disk on Debian's cloud kernel (`scsi_controller`, default
  `virtio-scsi-single`), can take a static address (`build_ip`, `build_gateway`), and waits for the source template's
  first-boot cloud-init. Clones of the template get a cloud-init drive for their key and address and boot with a
  network, and the template carries no SSH host key or journal of the build VM.

### Changed

- Supported versions: Proxmox VE 8.1, 8.2 and 8.3 are tested with PBS 3.x and 4.x, like 8.4 and 9.x. Proxmox VE 8.0
  is refused: it ships `proxmox-backup-client` 2.x and no SDN support; update such a node to 8.1 or later.

- Terraform module: `bpg/proxmox` 0.122, with the ACL and token resources under their current names. `moved.tf` moves
  existing state without replacing anything, which needs Terraform 1.8 or OpenTofu 1.10.
- Controller appliance recipe: `packer validate` refuses a `proxmox_url` without `/api2/json` and a `source_template`
  given as a VM ID. The Packer role in the guide adds `VM.Config.Cloudinit` and `VM.Config.CDROM`.
- The appliance guide covers the whole path, from the build machine's prerequisites to removal, and removes each
  Packer token's grants with the token.
- Documentation: what setup changes on PVE 8 (apt replaces `fuse` with `fuse3`) and what stays after a removal, a
  second PBS for one node, the two kinds of admission refusal, and how to run `doctor` on a node.

### Privacy

- The opt-in usage statistics are unchanged: off by default; `certistack telemetry show` prints exactly what would be
  sent.

## [0.1.1] - 2026-11-18

First public release, under the GNU Affero General Public License v3.0 or later. Documentation:
<https://certistack.dev/docs/>.

Tested with more than 10,000 VM restore tests of 471 different VMs, Windows and Linux, on a 14-node Proxmox VE lab and
standalone hosts. The exact v0.1.1 binary passed the full release set: Active Directory forests, Windows Server 2022, SQL
Server, SMB, Ubuntu, 16 VMs started in dependency order, a batch of UEFI VMs, encrypted backups, PVE 8.4 and PBS 3.x, and
a recovery after a killed run ([what was tested](https://certistack.dev/docs/compatibility/#what-was-tested)).

### What it does

- Restores VMs from Proxmox Backup Server into an isolated sandbox on Proxmox VE, checks that their services answer,
  removes everything and verifies that nothing is left. A run passes only when its probes passed and its cleanup was
  verified.
- Maps every backup read-only and boots the VM from copy-on-write overlays, on a sandbox network with no gateway and no
  uplink. Your backups and your VMs are never written.
- Runs from a controller: a Linux machine or the unprivileged controller image. A short-lived worker does the node-local
  work and is removed after each run. A Packer recipe builds a controller VM template.
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

[Unreleased]: https://github.com/cliftcloud/certistack/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/cliftcloud/certistack/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/cliftcloud/certistack/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/cliftcloud/certistack/releases/tag/v0.1.1
