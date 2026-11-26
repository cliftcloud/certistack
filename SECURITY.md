# Security policy

## Supported versions

Security fixes go into the latest release. There are no backport branches.

| Version | Supported |
| --- | --- |
| Latest `v0.1.x` release | Yes |
| Older releases and unreleased `main` | No |

## Reporting a vulnerability

Report vulnerabilities privately to [security@certistack.dev](mailto:security@certistack.dev) (also published at
`https://certistack.dev/.well-known/security.txt`). Do not open a public issue.

- If the report contains sensitive material, send a first email without the details and ask for a PGP key. We reply
  with one before you send the full report.
- We acknowledge and assess every report. There is no contractual response time.
- Please give us a reasonable opportunity to fix the issue before you disclose it.

Include the steps to reproduce (with a sample plan if relevant), your Proxmox VE and PBS versions, and your assessment
of the impact and possible mitigations.

## Threat model

### Privileges on the node

The controller holds plans, credentials and reports and runs as an ordinary user. A run connects to the node over SSH
with strict host-key verification and uploads a short-lived worker. The worker performs privileged host operations,
among them:

1. Attaching and detaching `/dev/loop*` devices for mapped PBS backups.
2. Setting the sandbox VM's `cpuunits` through the PVE API.
3. Talking to QEMU Machine Protocol sockets (`/var/run/qemu-server/*.qmp`).
4. Creating and removing a temporary SDN zone and VNet through the PVE API (`/cluster/sdn`).
5. Adding and removing the worker's probe address on the sandbox bridge (`ip`), installing a run-scoped `nft` table,
   and turning IPv4 and IPv6 forwarding off for the bridge (`sysctl`, `/proc/sys/net`).
6. Creating qcow2 overlays with `qemu-img`, reading them with `guestfish`, and stopping the `mdadm` and `dmsetup`
   devices that a guest's RAID or LVM builds on the run's own loop devices.
7. Creating the sandbox VM with `qm create` when the PVE API token cannot attach its disks (no `overlay_storage` set)
   or CD-ROM drives.

> [!IMPORTANT]
> **The node login is root-equivalent.** Whether the controller logs in as root or through a sudoers rule, it can run
> any command on the node: a command-matching sudoers rule allows a shell, so it is a convenience, not a limit. Protect
> the controller and its SSH key like any credential that is root on your hypervisors, and start on a node you can
> afford to experiment on.

### Network

CertiStack Community needs no internet connection, analytics service or vendor account, and sends no webhooks. It
connects only to the endpoints you configure: SSH from the controller, the PVE API and PBS from the node worker, and the
sandbox's guest probes. The one exception is opt-in: usage statistics are off by default and sent only if you turn
them on. `DO_NOT_TRACK=1` or `CERTISTACK_TELEMETRY=0` forbids them. See
[Usage statistics](https://certistack.dev/docs/telemetry/).

Restored guests get no gateway and no DNS server. CertiStack does not restrict the node's own DNS resolver or other
connections; air-gapping the node is a deployment decision.

### Secrets in logs and reports

PBS repository strings can contain an API-token identity, and client errors can echo connection details. CertiStack
keeps repository values out of logs and raw PBS client output out of errors and reports. A report may identify a
snapshot, VM, disk slot, verification result and byte count, but never PBS or PVE credentials, repository strings, SSH
identities, private key paths or environment files.

If a secret is disclosed anyway: stop distributing the affected report, rotate the credential, revoke old access, and
run the restore test again with the new credential. Do not edit an old report to make it look clean.

## Release assets

A Community release contains `certistack-linux-amd64`, `SHA256SUMS-bin.txt`, `SHA256SUMS-bin.txt.asc` and
`CONTAINER-IMAGE.txt` (the digest of the matching controller image on GHCR). Releases are linux/amd64 only, because the
controller uploads itself to the node as the worker. An arm64 build (`make build-linux-arm64`) is available from source
but is not released.

The signed checksum manifest covers the binary and `CONTAINER-IMAGE.txt`. Verify it before installing the binary or
using the image digest, then pin the container image by that digest.

### Verifying release integrity

The installer (`curl -fsSL https://certistack.dev/install.sh | bash`, source [`scripts/install.sh`](scripts/install.sh))
does steps 1 to 3 with the fingerprint pinned, and installs nothing unless they pass. By hand:

1. **Download** the binary, `CONTAINER-IMAGE.txt`, `SHA256SUMS-bin.txt` and `SHA256SUMS-bin.txt.asc` from the same
   release. Do not use files from an unofficial mirror.

2. **Verify the signature.** Import the release public key into a keyring of its own and compare its fingerprint with
   this one. Do not trust a key that came only from the release page you are verifying.

   ```text
   Public key:  release/release-public-key.asc (in this repository, at the release tag)
   Fingerprint: C72A BBC9 F354 4A71 FD5D  27A9 5774 80B5 3010 1FD2
   ```

   The key is Ed25519 and kept offline; it only certifies and revokes. Releases are signed by its signing subkey, which
   `gpgv` names by a 40-digit fingerprint ending `F701B3B2C1836DDF`. In the directory that holds the downloads (any
   private directory you own can hold the keyring):

   ```bash
   sudo install -d -m 0700 -o "$USER" /secure/certistack
   git clone --depth 1 --branch v0.1.4 https://github.com/cliftcloud/certistack.git
   gpg --no-default-keyring --keyring /secure/certistack/release-signing-key.gpg --import certistack/release/release-public-key.asc
   gpg --no-default-keyring --keyring /secure/certistack/release-signing-key.gpg --fingerprint
   gpgv --keyring /secure/certistack/release-signing-key.gpg \
     SHA256SUMS-bin.txt.asc SHA256SUMS-bin.txt
   ```

   `gpgv` prints `Good signature` and exits 0 only for a signature made by a key in that keyring.

3. **Verify the checksums** of both downloaded assets:

   ```bash
   sha256sum --strict --check SHA256SUMS-bin.txt
   ```

4. **Optionally, check the build provenance** that GitHub attested for the executable and the image digest:

   ```bash
   gh attestation verify certistack-linux-amd64 --owner cliftcloud
   gh attestation verify oci://ghcr.io/cliftcloud/certistack-controller@sha256:<digest> --owner cliftcloud
   ```

`certistack version` shows the version, commit and build date. A build from a checkout is stamped the same way, but it
is your build, not the release.

### How releases are built

A GitHub Actions workflow builds a release from a commit on the default branch, for a stable tag such as `v0.1.4` only.
A candidate tag (`vMAJOR.MINOR.PATCH-rcN`) starts nothing.

- **Registry.** `release/candidates.txt` lists, for each release, the tag, the full commit and the SHA-256 of
  `certistack-linux-amd64` built from it. A maintainer adds the line in a reviewed change after testing that
  executable. The workflow reads the registry from the default branch, never from the tagged tree, so a tag cannot
  register itself.
- **Reproducible build.** `scripts/release-candidate.sh <tag>` builds from a clean checkout with the Go version in
  `go.mod`. The version is the tag, the commit is the first 12 digits of the commit hash, and the build date is the
  commit's time in UTC, so the same commit gives the same bytes on any machine. Every report records all three, and
  `worker_sha256`, the digest of the executable that ran on the node.
- **Gate.** The workflow rebuilds the executable from the tagged commit and continues only if its digest is the
  registered one. Tests, the race detector, the Terraform checks and `govulncheck` run in a job that holds no secret.
- **Approval and signing.** The signing key lives in a protected `release` environment, and a maintainer must approve
  the run. The approved job checks the executable's digest again, builds the controller image around that executable
  without recompiling it, records the image digest in `CONTAINER-IMAGE.txt`, and signs the checksum manifest.
- **Provenance.** Two further jobs, the only ones that may request an identity token, attest build provenance for the
  executable and the image digest.
- **Draft first.** The workflow creates a draft release with the changelog notes, and a maintainer publishes it. A
  published release is never rebuilt: a fix is a new version.

## Interrupted runs

A run unwinds what it created, in reverse order, on `SIGINT`, `SIGTERM` or a panic. If the process or the host dies
first, the node's journal (`/var/lib/certistack/active.json`) still records what the run created. `certistack recover`
reconciles it ([Issue 35](https://certistack.dev/docs/troubleshooting/#issue-35)); on the node, the kept worker does
the same:

```bash
# Run on the affected PVE node. Use the protected environment retained in
# the exact temporary worker workspace when recovery needs PVE API access.
/var/lib/certistack/workers/<run>/certistack-node recover \
  --state-dir /var/lib/certistack \
  --env-file /var/lib/certistack/workers/<run>/runtime.env
```

Recovery checks kernel process start ticks so it never acts on a reused PID, stops leftover worker processes, and
touches only resources recorded in that journal.

Do not delete a kept worker workspace before recovery completes. Its directory (mode 0700) holds an environment file
(mode 0600) with a copy of the controller's PVE token secret and PBS credential, the same long-lived secrets as
`controller.env`. When a run ends, the controller checks that run's own journal; if it is not clean, the controller
recovers it with that environment, waiting up to 20 minutes while another CertiStack operation holds the host lock.
