# Security Policy & Vulnerability Disclosure

CertiStack is a disaster recovery validation utility designed to verify virtual machine recovery from Proxmox Backup Server (PBS) snapshots on Proxmox VE hypervisors.

Because CertiStack interacts with hypervisor APIs, block loopback devices, and virtualized hardware, security, integrity, and strict isolation are foundational to our architecture.

---

## 1. Supported Versions

Security fixes are published to the latest release; there are no backport
branches.

| Version | Status | Security Updates |
| :--- | :--- | :--- |
| Latest `v0.1.x` release | Current | Supported |
| Older releases and unreleased `main` | Development | Unsupported |

---

## 2. Reporting a Vulnerability

We welcome responsible security research and vulnerability reports. If you discover a security vulnerability in CertiStack, please report it privately:

* **Security Email:** [security@certistack.dev](mailto:security@certistack.dev)
  (also published at `https://certistack.dev/.well-known/security.txt`)
* **Encryption:** If a report contains sensitive material, send a first e-mail
  without the details and ask for a PGP key; we reply with one before you
  send the full report.
* **Response Timeline:** We acknowledge and assess every report. There is no contractual response time.
* **Coordinated Disclosure:** We request that you afford us a reasonable opportunity to address the issue before public disclosure.

Please include:
1. Steps to reproduce the issue (including sample test plan YAML if applicable).
2. Proxmox VE and Proxmox Backup Server environment details.
3. Impact assessment and suggested mitigations.

---

## 3. Threat Model & Privilege Architecture

### Controller and temporary-worker privilege boundary
The Community CLI is installed on a dedicated controller, where it does not
need root to retain plans, credentials, or reports. A run uses
strict SSH host-key verification to transfer a short-lived node worker to the
selected PVE node. The worker may require passwordless sudo for the host-local
operations below. This bootstrap SSH/sudo identity is root-equivalent: the
controller uploads the worker and the worker can invoke privileged operations
such as those listed (the list is not complete), so a command-matching sudoers
rule is an operational restriction, not a least-privilege security boundary:
1. **Loopback Block Devices:** Creating, attaching, and detaching `/dev/loop*` block devices from PBS snapshot chunks.
2. **PVE VM resource weighting:** Setting the ephemeral VM's `cpuunits` through the PVE API for relative CPU scheduling. CertiStack does not move a PVE-managed QEMU process between host cgroups or claim a `memory.max` limit.
3. **QMP Socket Access:** Communicating directly with QEMU Machine Protocol UNIX domain sockets (`/var/run/qemu-server/*.qmp`).
4. **Proxmox SDN Manipulation:** Programmatically configuring transient VNet zones through the PVE API (`/cluster/sdn`).
5. **Host network containment:** Adding and removing the worker's probe address on the sandbox bridge (`ip`), installing a run-scoped `nft` table, and turning IPv4 and IPv6 forwarding off for the bridge (`sysctl`, `/proc/sys/net`).
6. **Overlays and guest inspection:** Creating qcow2 overlays with `qemu-img`, reading them with `guestfish`, and stopping the `mdadm` and `dmsetup` devices that the guest's RAID or LVM builds on the run's own loop devices.
7. **Local `qm create` fallback:** Creating the sandbox VM with a root `qm create` when the PVE API token cannot attach the disks (as when no `overlay_storage` is set) or the CD-ROM drives.

> [!IMPORTANT]
> **The worker is root on the node.** It drives sensitive hypervisor
> interfaces, and the documented sudoers rule is a convenience, not a limit
> (it allows a shell, so the account is root). Protect the controller and its
> SSH key as you would any credential that is root on your hypervisors, and
> start on a node you can afford to experiment on: a standalone node, or one
> with spare capacity.

### Network and telemetry boundary
CertiStack Community needs no internet connection, analytics service or vendor
account, and it sends no webhooks. Its network connections are the
endpoints you configure: SSH from the controller, the PVE API and PBS from the
node worker, and the sandbox's guest probes. The
one exception is opt-in: anonymous usage statistics are off by default, and
nothing is sent unless you turn them on. `DO_NOT_TRACK=1` or
`CERTISTACK_TELEMETRY=off` forbids them outright. See
[docs/telemetry.md](docs/telemetry.md) for the five fields and how to see and
delete them. CertiStack gives the restored guests no gateway and no DNS server,
and does not restrict the node's own DNS resolver or its other connections;
air-gapping the node is a deployment decision. Outbound notifications exist only
in the Enterprise Edition.

### Secret-safe observability

PBS repository strings can contain an API-token identity, and client failures
can echo connection context. CertiStack therefore omits repository values from
logs and withholds raw PBS-client output from errors and reports. Evidence may
identify a snapshot, VM, disk slot, verification result, and byte count, but
must not include PBS/PVE credentials, repository strings, SSH identities,
private key paths, or unredacted environment files.

Treat an accidental secret or repository-context disclosure as an incident:
stop distributing the affected evidence, rotate the relevant token or
credential, revoke obsolete access, and re-run the validation with the rotated
credential. Do not edit an old report to make it appear clean.

---

## 4. Release Verification & Checksums

The Community release contains `certistack-linux-amd64`,
`SHA256SUMS-bin.txt`, `SHA256SUMS-bin.txt.asc`, and `CONTAINER-IMAGE.txt`
(the digest of the matching controller image on GHCR). Releases publish
linux/amd64 only: the controller uploads itself to the PVE node as the
temporary worker, so it must run on the node's architecture. An arm64 build
(`make build-linux-arm64`) is available from source but is not a release
artifact. The signed checksum manifest covers both the binary and
`CONTAINER-IMAGE.txt`. Verify it before installing the binary or using the
image digest, then pin the container image by that digest.

### Verifying Release Integrity

The one-line installer (`curl -fsSL https://certistack.dev/install.sh | bash`, source
[`scripts/install.sh`](scripts/install.sh)) does steps 1 to 3 below for you, with the fingerprint
pinned in the script, and installs nothing unless they pass. These are the steps by hand:
1. **Download the binary, `CONTAINER-IMAGE.txt`, `SHA256SUMS-bin.txt`, and
   `SHA256SUMS-bin.txt.asc` from the same official release.** Do not
   substitute files from an unofficial mirror.

2. **Verify the Clift Cloud GPG release signature before trusting the
   checksum.** Import the release public key into a keyring of its own and
   compare its fingerprint with this one. Do not trust a key that came only
   from the release page you are verifying.
   ```text
   Public key:  release/release-public-key.asc (in this repository, at the release tag)
   Fingerprint: C72A BBC9 F354 4A71 FD5D  27A9 5774 80B5 3010 1FD2
   ```
   The key is Ed25519. Releases are signed by its signing subkey, which this key
   certifies; the key itself only certifies and revokes, and is kept offline.
   `gpgv` names the signing subkey by a 40-digit fingerprint ending `F701B3B2C1836DDF`.
   Run these commands in the directory that holds the downloaded files. The first
   creates the keyring's directory (any private directory you own will do: use its
   path in the keyring argument); the second clones the repository at the release
   tag, which holds the key.
   ```bash
   sudo install -d -m 0700 -o "$USER" /secure/certistack
   git clone --depth 1 --branch v0.1.0 https://github.com/cliftcloud/certistack.git
   gpg --no-default-keyring --keyring /secure/certistack/release-signing-key.gpg --import certistack/release/release-public-key.asc
   gpg --no-default-keyring --keyring /secure/certistack/release-signing-key.gpg --fingerprint
   gpgv --keyring /secure/certistack/release-signing-key.gpg \
     SHA256SUMS-bin.txt.asc SHA256SUMS-bin.txt
   ```
   `gpgv` prints `Good signature` and exits 0 only for a signature made by a
   key in that keyring.

3. **Verify both downloaded assets against the signed manifest:**
   ```bash
   sha256sum --strict --check SHA256SUMS-bin.txt
   ```

4. **Optionally check the build provenance** GitHub attested for the
   executable and for the image digest in `CONTAINER-IMAGE.txt`, which ties
   each to the release workflow run that built it:
   ```bash
   gh attestation verify certistack-linux-amd64 --owner cliftcloud
   gh attestation verify oci://ghcr.io/cliftcloud/certistack-controller@sha256:<digest> --owner cliftcloud
   ```

`certistack version` shows the version, commit and build date of the
executable. A build from a checkout is stamped the same way but is your build,
not the release.

### How releases are built

A release is built by a GitHub Actions workflow, from a commit on the default
branch, for a stable tag such as `v0.1.0` only. A candidate tag
(`vMAJOR.MINOR.PATCH-rcN`) starts nothing.

* **Registry.** `release/candidates.txt` lists, for each release, the tag, the
  full commit and the SHA-256 of `certistack-linux-amd64` built from it. A
  maintainer adds the line in a reviewed change after testing that
  executable. The workflow reads the registry from the default branch, never
  from the tagged tree, so a tag cannot register itself.
* **Reproducible build.** `scripts/release-candidate.sh <tag>` builds from a
  clean checkout with the Go version in `go.mod`. The version is the tag, the
  commit is the first 12 digits of the commit hash and the build date is the
  commit's own time in UTC, so the same commit gives the same bytes on any
  machine. Every report records the three, and the report also records
  `worker_sha256`, the digest of the executable that ran on the node.
* **Gate.** The workflow rebuilds the executable from the tagged commit and
  continues only if its digest is the registered one. Tests, the race
  detector, the Terraform checks and `govulncheck` run in a job that holds no
  secret.
* **Approval and signing.** The signing key lives in a protected `release`
  environment, and a maintainer must approve the run. The approved job checks
  the executable still has the verified digest, builds the controller image
  around that executable (it is not compiled again), records the image digest
  in `CONTAINER-IMAGE.txt`, and signs the checksum manifest.
* **Provenance.** Two further jobs, the only ones that may request an identity
  token, attest build provenance for the executable and for the image digest.
* **Draft first.** The workflow creates a draft release with the changelog
  notes, and a maintainer publishes it. A published release is never re-run:
  a fix is a new version.

---

## 5. Crash Resilience & Orphan Recovery

If the runner process is interrupted or the host experiences an unexpected power loss:
1. **Thread-Safe LIFO Stack:** The engine catches `SIGINT`, `SIGTERM`, and runtime panics to unwind allocated resources in reverse order (terminates test VM, deletes ephemeral COW delta overlay, unmounts loopback device, purges SDN zone).
2. **Crash Recovery Tool:** Run `recover` on the node (the worker's `certistack-node recover`, see
   [Issue 26](docs/troubleshooting.md#issue-26-lost-contact-with-node-)) to reconcile state:
   ```bash
   # Run on the affected PVE node. Use the protected environment retained in
   # the exact temporary worker workspace when recovery needs PVE API access.
   /var/lib/certistack/workers/<run>/certistack-node recover \
     --state-dir /var/lib/certistack \
     --env-file /var/lib/certistack/workers/<run>/runtime.env
   ```
   `recover` inspects `/var/lib/certistack/active.json`, verifies kernel process start ticks to prevent PID reuse, terminates hanging runner processes, and detaches only loop devices recorded in that journal.

   Do not delete a retained worker workspace before recovery completes: its
   mode-0700 workspace holds an environment file (mode 0600) with a copy of the
   controller's PVE token secret and PBS credential (the same secrets as
   `controller.env`, not one-time tokens), required to reconcile only the
   resources in that journal. After
   every run the controller verifies that run's own journal, which the worker
   names after its workspace. It needs no host lock to read it. A journal that
   names a later run also proves this one was reconciled, because a run only
   replaces a clean journal, after recovering it under the host lock. Only a
   journal of its own that is not clean is recovered, with the workspace's
   environment; while another CertiStack operation holds the host lock, the
   controller waits (up to 20 minutes) and checks again rather than reporting
   the cleanup as unverified. Use the node-local command only for emergency
   diagnosis or recovery.
