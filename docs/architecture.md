# How it works

How CertiStack restores a backup into a sandbox, tests it, cleans up, and proves what happened. You do not need this page
to run it; read it to understand a message or a report.

## The parts

```text
Controller (Linux VM, host or container): plans, credentials, reports
        | SSH
        v
Proxmox VE node: /var/lib/certistack/workers/<run UUID>/certistack-node, for one run
        - PBS map, overlay, sandbox VMs, sandbox network, probes, journal
```

- **The controller** is where you run `certistack`. It holds the plans, credentials and reports, and drives the run. It
  can also run as an unprivileged OCI image
  ([`deploy/controller`](https://github.com/cliftcloud/certistack/blob/main/deploy/controller/README.md)) or a
  Packer-built VM template ([`deploy/appliance`](https://github.com/cliftcloud/certistack/blob/main/deploy/appliance/README.md)).
  Neither needs privileges, `/dev/kvm`, a Docker socket or a PVE shell. The container mounts only its state directory, a
  read-only secrets directory and, in the Compose file, a read-only plans directory.
- **The node worker** is the same program, uploaded for one run to do what the PVE API cannot. Nothing of CertiStack
  keeps running on the node (the Enterprise Edition runs `certistackd` there: [Editions](editions.md)).

### Why a node worker exists

The loop device from `proxmox-backup-client map`, the overlay QEMU opens and the QMP socket live in the node's kernel,
out of a controller's reach. So the worker:

- **prepares the guest network:** for wire probes, `guestfish` (from `libguestfs-tools`) writes a MAC-bound profile
  with no gateway into the disposable overlay before boot. It never installs anything in the guest, changes the source
  VM, or falls back to DHCP, Cloud-Init or a production network. For a firewalld guest it may add an allow rule for the
  probe address and ports, on the overlay only. `network_recovery.mode: preserve` skips all of this.
- **runs the wire probes** (TCP, HTTP, DNS, LDAP, SQL Server, SMB) from its own address on the sandbox network, with the
  node's `ip`, `nft` and `sysctl`.
- **gets only what the run needs:** one validated plan and the PVE and PBS connection details, never a signing key. It
  returns unsigned evidence, and the controller writes the report.

### How the controller reaches the node {#access-modes}

The controller connects over SSH with a pinned host key (`known_hosts`), as root or an account with a passwordless sudo
rule for the worker. It uploads its own static binary to a new root-owned directory, `<state-dir>/workers/<uuid>`
(default `/var/lib/certistack/workers/<uuid>`), because hardened nodes often forbid running programs from `/run`.

- Missing state and `workers` directories are created with mode `0700`. An existing state directory must already belong
  to root, have mode `0700` and be reached through no symbolic link, or the run stops before it stages anything.
- `/tmp`, `/var/tmp` and `/dev/shm` are refused as state or scratch directory.

What this access means for your node, and how to limit it: [What it changes](what-it-changes.md).

### Where secrets live

The PVE token and CA, the PBS credential and fingerprint, and each node's SSH key and `known_hosts` belong only in the
controller's environment file or secret mount: never in plans, committed Terraform variables, container layers, command
lines, Compose files or PVE environment files. A plan has no password field (the plan loader refuses an unknown `storage.pbs_password`), and the SSH
command line never carries a secret.

A run copies what it needs (`runtime.env`, and the PBS encryption key and PVE CA when set) into its root-only workspace
on the node, and removes the workspace at the end.

Keep TLS verification on (mount a CA file), pin container images by digest (the Packer template accepts only
`registry-host/repository@sha256:<digest>`), and keep reports on encrypted, backed-up storage.

## A run, step by step

1. **Admission.** The worker waits while the node's memory or I/O wait is over the plan's limits.
2. **Sandbox network.** It creates an SDN zone and VNet (next section).
3. **Map.** `proxmox-backup-client map --repository <repository> [--ns <namespace>] [--keyfile <file>] <snapshot>
   <drive_archive>` exposes each disk of the snapshot as a read-only block device such as `/dev/loop0`, fetching blocks
   from PBS on demand.
4. **Overlay.** A qcow2 file on top of it takes every guest write:

    ```bash
    qemu-img create -f qcow2 -o lazy_refcounts=on -b /dev/loop0 -F raw /var/lib/vz/certistack-scratch/images/9001/certistack-delta-vm9001-scsi0-<timestamp>-0.qcow2
    ```

    It lives in `images/<vmid>/` of the overlay storage (or the `0700` scratch directory). Mapping instead of restoring
    spares a 2 TB VM 2 TB of disk and hours of transfer. When disks exceed the page cache, `copy_before_boot: auto`
    copies them to local storage during the scan; plan room for copies and overlay growth (`storage.max_copy_gib: 0`
    means no cap).
5. **Integrity scan.** Every mapped disk is read in full and its SHA-256 recorded.
6. **Boot.** A temporary PVE VM boots from the overlay, attached by volume ID, for example
   `scsi0: certistack-scratch:9001/certistack-delta-vm9001-scsi0-<timestamp>-0.qcow2,discard=on,iothread=1,backup=0,cache=unsafe`.
7. **Probes** (below), then **teardown** (below).

### The isolated network

A restored VM on a production network could cause IP conflicts or a rogue domain controller, so each run gets its own
PVE SDN network:

- **One node:** a `simple` zone (such as `csSb01`) and a VNet (`csVnet01`), created through `/cluster/sdn` and applied.
  The bridge has no physical interface, so frames stay in the node's memory.
- **A cluster:** a `vxlan` zone with an explicit peer list; its VNI is checked against every existing VNet. Traffic is
  UDP between the peers you list, so list only addresses of a private interconnect you control.
- **No way out:** subnets have no gateway, and there is no SNAT or masquerade, so restored VMs cannot reach DNS, the
  internet or your network.
- **Containment on the node:** the worker checks that forwarding is off on the bridge and adds a run-scoped `nft` table
  that drops new traffic from the VNet to the node and through it. Restored NICs have the PVE firewall on.

A network reload (PVE reloads every node at each SDN apply, whoever makes it) removes the probe address and turns
forwarding back on. The run's guard checks both and the `nft` table every 2 seconds and before each wire probe, and
repairs them with one warning. If the table cannot be restored, the run fails closed.

With `network.lifecycle: preprovisioned`, the worker checks a VNet you made (no gateway, no SNAT, no other guest on it)
and never changes it.

### Probes

The verdict never rests on reading the screen. Stage 1 gates the rest; stages 2 and 3 then run in the plan's order, and a
failed probe does not stop the others.

| Stage | Checks |
| --- | --- |
| 1. Hypervisor | QMP (`/run/qemu-server/<id>.qmp`) reports `running` within 60 seconds |
| 2. Wire probes, from the worker | TCP connect; HTTP or HTTPS status (with certificate checks); DNS over UDP 53; LDAP rootDSE; SQL Server PRELOGIN; SMB2 NEGOTIATE |
| 3. Inside the guest, through the guest agent | `guest-exec` of a command such as `systemctl is-active <svc>`: exit code `0` and an output match. Skipped without an agent |

On a failure, CertiStack embeds a QMP `screendump` in the report as a PNG (a kernel panic, a Windows stop code, a GRUB
error). A passing `screendump` probe keeps only the image's SHA-256.

## Cleanup and recovery

Each resource registers its cleanup when it is created. Cleanup runs in reverse order on success, failure, `SIGINT`,
`SIGTERM` or a panic:

1. The VMs are stopped and destroyed.
2. The overlays are deleted.
3. Each PBS map is released, only while its loop device still backs the file recorded at map time (loop numbers are
   reused). The map's daemon is stopped first, only if it is the run's own; one that ignores `SIGINT` for 20 seconds is
   reported, not killed, and its loop stays.
4. The address guard stops; the probe address and its `nft` table are removed.
5. The SDN VNet and zone are deleted and the configuration applied.

Anything not removed is named in the run's journal on the node, and the next run or a recovery finishes it.

### What "clean" means {#what-clean-means}

Cleanup releases a resource only when it can show the resource is the run's own and is gone.

- **A VM** is gone only when PVE says it does not exist. Before every stop and destroy, the run's markers in its
  configuration are checked, because VM IDs are reused.
- **Files** are removed only if they are the file the run created (same device and inode); another is left and
  reported as "not the file this run created".
- **The probe address and `nft` table** are removed by kernel identity, not by name.
- **The VNet and zone** are deleted even if a VM survived, so a VM CertiStack lost control of is left on no network.
- **Recovery** touches only resources recorded for the interrupted run. It never sweeps the host.

A VM not confirmed destroyed keeps what it uses (overlays, maps, the probe address), and the journal stays unclean.

### When a run is interrupted {#crash-and-lease-recovery}

Nothing on the node depends on the controller surviving.

- A failed or killed worker's supervisor recovers the journal at once.
- If cleanup is incomplete, the controller retries the journal. If that cannot be proven, the workspace is kept, its PBS
  encryption key removed at once, and the command fails.
- A lease watch recovers the journal and removes the workspace once the controller's lease is 90 seconds old, or 30
  minutes after the worker ended.
- The next run on the node recovers an earlier journal before it changes anything.

| Event | What happens |
| --- | --- |
| The lease watch cannot recover | It removes the credentials (`runtime.env`, PBS key, worker binary), keeps logs and journal, and writes `credentials-removed.txt`. The next run recovers the journal. |
| A process survives `SIGKILL` for 30 seconds | Nothing is recovered while it may run. After an hour, only the credentials are removed. |
| The node reboots | The next run removes the credentials of any workspace whose controller has been silent for 15 minutes. |

These times run on the node's boot clock, so changing its clock does not affect them. To recover by hand:
[Issue 26](troubleshooting.md#issue-26-lost-contact-with-node).

## What the controller verifies before it writes the report

The worker is the less-trusted part. The controller writes its report only after two checks.

**Cleanup.** `teardown_evidence.journal_recovery_verified` (and with it `all_cleaned` and `orphan_sweep_clean`) is true
only when the node's own journal, or the record a later run kept of it, shows this run in phase `cleaned`. Otherwise the
report is saved with the cleanup fields false, the command fails with
`DR validation ended with unverified temporary resource cleanup`, and the node workspace is kept. This stops faulty,
replayed or mismatched records. It cannot stand against root on the node, which writes the journal too.

**The report** must be what was requested:

- it names this run, node, plan, validation mode and schema;
- its timestamp lies within the run, allowing 10 minutes of clock difference (the node's clock is read first);
- its frameworks, retention, RTO objective, admission limits and reservation are the plan's;
- its VM records are unique, in the plan, and each names its snapshot and disks;
- a claimed pass has a SHA-256 of every disk and a passed guest-level assertion.

`verify-report` applies the same rules. A report that fails them is refused after cleanup is verified, and no report is
written. The worker's raw result is kept, unsigned and marked `REFUSED, NOT EVIDENCE`, as
`<output>/refused/<run-id>.refused.txt` (troubleshooting Issue 34), where nothing that reads reports looks.

What only the worker saw (probe results, image digests, hardware, timings) stays its own word. A probe's expected output
and TLS settings are bound only through `plan_sha256`.

## Backup jobs and VM IDs

A backup job that selects all VMs (`vzdump --all`) picks up a sandbox VM that exists when the job starts. Every overlay
is attached with `backup=0`, so the job stores only the VM's configuration, never restored data, but it still creates a
backup group under the sandbox VM ID and briefly locks the VM. Exclude the sandbox VM IDs, select VMs by pool, or run
validations outside the backup window.

Reserve the sandbox VM IDs for CertiStack. Recovery checks the run's marker before it stops or destroys a VM, but
Proxmox VE has no conditional stop or delete: a VM another tool creates at that ID in between would be stopped or
destroyed.

## Signing and verification {#6-signing-and-verification}

Community reports are unsigned: their contents are the run's own claim. The Enterprise Edition signs them, and
`verify-report` checks a signed report for anyone. A signed report is tamper-evident and attributable to the key holder,
not a certification, and its signature does not show when it was made (item 9). How to verify: [Reports](reports.md).

1. **Canonical form.** The report is serialised as RFC 8785 JSON: sorted keys, one number format, no whitespace.
2. **Ed25519 signature.** In Enterprise, `certistackd` signs with the operator's private key, a root-only file the node
   worker never receives. Community has no signer: no code reads a private key, makes a key pair or signs.
3. **Pinned signers.** The report embeds its signature and public key, but the verifier also needs a trusted keyring or
   key. A report cannot vouch for its own key, and an empty trusted set accepts nothing. A key that cannot anchor trust
   (not a canonical Ed25519 point, or a small-order point such as all zeros, which anyone can forge for) is refused.
4. **What the signature covers.** Every member except `signature`, `public_key`, `signer_fingerprint` and the optional
   `signature_timestamp`, which are checked separately. Changing any signed value invalidates it; a repeated member name
   is refused. An integer of 2^53 or more is refused when signed and verified (store it as a string). Whitespace and
   member order are not signed, so a re-indented copy still verifies: record a file's SHA-256 to prove it is byte for byte
   the one CertiStack wrote.
5. **Acceptance is separate from the signature.** A valid signature shows its holder signed this content, not that the
   recovery succeeded. `verify-report` adds an acceptance verdict, and `--expect-plan` binds it to `plan_sha256`.
   `acceptance.Evaluate` does not look at a signature.
6. **Unsigned reports fail closed.** Every verifier refuses a report with no signature unless told `--unsigned`, so a
   removed signature never reads as verified.
7. **Key, keyring and report files.** Formats are in [Reports](reports.md#keys). Each must be a regular file within its
   limit: public key 4 KiB, keyring 1 MiB, report 128 MiB, PVE CA file (`CERTISTACK_PVE_CA_SOURCE`) 1 MiB of PEM. A
   faulty keyring is refused whole, naming the entry (`entry 2`, `line 3`). Two keys may share a name, so a rotation can
   keep both. Errors never quote a key.
8. **Report size and structure.** A report outside these limits is refused before it is decoded, and signing and saving
   apply the same check, so the controller never writes a report that cannot be checked:

    | Limit | Value | Real reports |
    | --- | --- | --- |
    | Size | 128 MiB (twice the 64 MiB the controller accepts from a worker) | - |
    | Nesting depth | 32 levels | 6 |
    | Members in one object | 256 | 26 |
    | Elements in one array | 65,536 | about 130 |
    | Values in all | 2,097,152 | under 7,000 in a 5 MiB report |
    | Member name / string | 256 bytes / 64 MiB | a screenshot is about 0.5 MiB |

    An error reads like `report exceeds a size or structure limit: it has an object of more than 256 members at
    $.x_future`. Verifying allocates about 25 times the report's size (about 90 times for millions of one-digit values),
    so give the verifier memory for several times the file.
9. **Signer Lifecycle: Rotation, Retirement and Compromise.** A keyring is the set of keys the verifier accepts today, and
   it keeps no dates. A key in it authorizes every report signed with that key, whatever the report says about when: a
   keyring entry's `created_at`, `name` and `node` are labels the verifier does not evaluate, a report's `timestamp` is
   chosen by whoever signed it, and a member that marks a key revoked is refused, not honored. There is no validity
   window, revocation list or trusted timestamp in this release. So:

    - **Keeping a key in a keyring keeps trusting it for everything**: reports signed after it was replaced, dated before
      it existed or dated to look old all verify.
    - **Deleting a key from a keyring stops the verification of everything it ever signed**, genuine history included
      (exit status 2). Do not re-sign old reports with a new key; keep the old public key in a separate historical keyring
      instead.

    **Rotate without losing verification.**

    1. Make the new key pair at new paths (in Enterprise); never overwrite the old key. Note both fingerprints.
    2. Add the new public key to the keyring every verifier uses, keeping the old entry, and roll that keyring out to every
       verifier (CI gates, scripts, auditors) before the controller changes.
    3. Point the controller at the new key, run a plan, and verify its report against the keyring.
    4. Keep the old entry until every report it signed is archived with a record made at the time: the file's SHA-256 in
       storage nobody can rewrite, or a trusted timestamp. The report's own `timestamp` proves nothing.
    5. Move the old entry to a separate historical keyring, used only for archived reports whose record predates the
       retirement. Destroy the old private key or seal it offline.

    **If a signing key may have been exposed** (its file read by someone else, or the signing host compromised): treat
    every report signed since the earliest possible exposure as unproven. Remove the key from every active keyring at
    once, make a new pair on a clean host and roll out the new keyring. Keep the old public key only in the historical
    keyring, for reports with an archive record from before the exposure. Run the plans again for the evidence you need;
    never edit or re-sign old reports. Back up a private key as any secret; a lost one costs no verification: make a new
    pair and add it.
