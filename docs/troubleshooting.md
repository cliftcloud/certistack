# When something fails

Use this page when a `certistack` command stops with an error, or a report says `FAIL`. Find your message and
apply its fix.

## Start here {#start-here}

1. On the controller, run the check. Add your plan file to check the plan and its sandbox range too:

    ```bash
    certistack check --env-file /secure/certistack/controller.env my-first-plan.yaml
    ```

    It stops at the first layer that fails and prints its fix ([the layers](cli-reference.md#check)).

2. If `check` passes and a command still fails, search this page for a few words of the message. Many messages name
   their issue ("Troubleshooting, Issue 26").
3. For a failed run, `certistack report show <report.json>` names the VM, the probe and the reason.
4. To ask for help, add `--debug`, and keep the plan ID, the report ID and the state directory.

Issue numbers never change; issues are grouped by when they happen.

## Find your message {#find-your-message}

| When | Issue |
| --- | --- |
| Setup, SSH, environment file, PVE or PBS | [setup messages](#setup-messages), [1](#issue-1-the-run-cannot-start-or-cannot-reach-the-node) |
| Before a run starts | host lock [2](#issue-2-another-certistack-operation-holds-the-host-lock), memory [3](#issue-3-admission-denied-ram-usage-xx-exceeds-max-yy), MAC or wire-probe target [4](#issue-4-a-mac-address-or-a-wire-probe-target-is-refused-before-anything-is-created), unapplied SDN changes [12](#issue-12-the-clusters-sdn-configuration-has-changes-that-have-not-been-applied), node clock [33](#issue-33-the-clock-of-node-is-about-ahead-of-the-controllers-or-behind), a backup refused [46](#issue-46-a-backup-is-refused-before-the-run-starts), sandbox range [39 to 44](#the-sandbox-range) |
| During the run | loop devices [5](#issue-5-map-pbs-backup-image-client-output-withheld-n-bytes-and-no-free-loop-device), disk size [6](#issue-6-the-mapped-pbs-image-is-n-bytes-but-the-snapshots-manifest-records-m-bytes-for-this-disk), PVE 8 and namespaces [8](#issue-8-a-pve-8-node-reads-the-wrong-backups-or-says-a-backup-is-encrypted-when-it-is-not), SDN permissions [9](#issue-9-failed-to-create-sdn-zone-or-failed-to-create-sdn-vnet-pve-api-error-http-403-or-http-400), existing zone or VNet [10](#issue-10-certistack-does-not-own-or-reuse-pre-existing-resources), worker output [30](#issue-30-node-worker-returned-an-unusable-result), [31](#issue-31-this-script-was-altered-by-the-program-that-started-it-so-it-cannot-run-refusing-to-start), [32](#issue-32-n-progress-lines-were-not-shown-because-the-progress-output-did-not-keep-up) |
| Probes and guests | LDAP [15](#issue-15-ldap-base-search-returns-nosuchobject-or-no-entry), [16](#issue-16-ldap-listener-times-out-after-a-successful-sandbox-boot), DC without DNS [17](#issue-17-a-restored-domain-controller-answers-ldap-and-kerberos-but-not-dns), skipped mount [18](#issue-18-a-service-is-inactive-because-its-data-mount-was-skipped), Windows services [19](#issue-19-a-windows-guests-agent-or-services-never-start-in-the-sandbox), Windows clock [20](#issue-20-a-windows-sandbox-vms-clock-is-hours-off), SQL Server [21](#issue-21-an-mssql-probe-fails-after-it-also-tried-tds-80-strict-encryption), soak [22](#issue-22-service-check-n-of-the-soak-failed-or-vm-ns-state-could-not-be-read-from-pve-so-its-liveness-is-unknown), `SKIPPED` [23](#issue-23-stage-3-probe-marked-as-skipped), guest-exec [24](#issue-24-qga-is-connected-but-the-report-says-guest-exec-is-unavailable), screenshot [25](#issue-25-forensic-framebuffer-capture-completed-for-vm-the-failure_artifact-in-the-report), `bind: cannot assign requested address` [38](#issue-38-a-wire-probe-fails-with-bind-cannot-assign-requested-address) |
| Cleanup and recovery | lost node [26](#issue-26-lost-contact-with-node), VM not destroyed [27](#issue-27-kept-in-place-sandbox-vm-was-not-confirmed-destroyed-or-cannot-be-confirmed-gone-still-exists), stuck worker [28](#issue-28-the-node-worker-cannot-be-stopped-is-still-running-after-sigkill), cleanup not verified [29](#issue-29-the-controller-cannot-verify-that-this-run-cleaned-up-after-itself), PBS map left [7](#issue-7-pbs-map-process-n-of-recovery-left-it-running-or-but-nothing-proves-it-is-recovery-left-it), unconfirmed allocation [11](#issue-11-cannot-safely-reconcile-unconfirmed-allocation), zone or VNet left [13](#issue-13-sandbox-vnet-exists-but-certistack-cannot-show-that-it-is-the-interrupted-runs), SDN lock [14](#issue-14-a-request-for-pves-sdn-configuration-lock-got-no-definite-answer) |
| Reports | refused [34](#issue-34-the-node-workers-report-was-refused-and-no-report-was-written), not saved [35](#issue-35-save-controller-report-fails-and-the-emergency-copy-of-the-unsaved-report-could-not-be-written-either), keyring or file refused [36](#issue-36-a-keyring-public-key-or-report-file-is-refused), `verify-report` rejects [37](#issue-37-verify-report-rejects-a-report-for-the-plan-you-gave-it) |

## Setup and connection

### Setup messages {#setup-messages}

A failed `check` layer at the end of setup is [Issue 1](#issue-1-the-run-cannot-start-or-cannot-reach-the-node).

| You see | Fix |
| --- | --- |
| `setup asks questions and needs a terminal`, `--yes does not trust the node's host key by itself` | Run it at a terminal, or pass at least `--yes`, `--node-host` and `--fingerprint` ([setup](cli-reference.md#setup)). |
| `not confirmed, so nothing was written`, `the node offered SHA256:..., not the SHA256:... you expected`, `already holds a different ED25519 key` | Nothing was written. Type the whole word `yes`, or give `--fingerprint` the ED25519 key's fingerprint (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the node). A changed key means a reinstalled node or an impostor: find out which first. |
| `no PBS namespace was given, and --yes does not let the PBS user read every namespace` | Unattended, give `--pbs-namespace NAMESPACE` for the namespace that holds the backups, or `--pbs-namespace /` to grant the whole datastore. |
| `--fingerprint "..." is not an SHA-256 fingerprint` | Give the whole `SHA256:...` line that `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` prints on the node. |
| `the key still does not sign in to root@...` | `ssh-copy-id` needs a root password the node accepts over SSH. Otherwise answer `n`, append the printed line to `/root/.ssh/authorized_keys` on the node, and run setup again. |
| `ssh to root@...:22 failed, and not because the key is not authorized` | Fix the reason ssh gives at the end (address, port, host key). |
| `Connection reset by ... port 22` | After failed sign-ins, OpenSSH 10 (PVE 9) blocks the controller for up to 10 minutes (`PerSourcePenalties`). Wait, then run setup again. Unattended, authorize the key first. |
| `apt-get cannot install libguestfs-tools and nftables` | Check the node's repositories in `/etc/apt/sources.list.d/` ([Set up by hand](manual-setup.md)). |
| `the storage ... is limited to node(s) ...`, `the node's storage ... is disabled` | Run the `pvesm set` command the message gives, or pick another storage with `--overlay-storage`. |
| `is on the root disk of a cluster node` | Overlays there can cost the node its cluster membership. Give a directory on another disk (`--overlay-path`). |
| `controller.env.partial holds what an unfinished setup kept` | Run setup again and keep the secret it offers. |
| `nothing was installed, because apt-get would remove ...` | Setup removes nothing without your yes, and `--yes` does not give it. On the node, `apt-get -s install libguestfs-tools nftables` lists what apt would do. Find out why it removes those packages; answer yes only if that is what you want. |
| `a run needs guestfish and nft`, `a run needs a file-based storage`, `a run needs the PVE token` | You said no to a needed change. Run setup again and say yes, or do it by hand ([Set up by hand](manual-setup.md)). |
| `the token's secret is needed`, `the PBS token's secret is needed` | The token exists and its secret cannot be read back. Run setup again and replace the token (the old secret stops working, for a scheduled job or another controller too), or put the secret you kept in the file. |
| `The PBS part did not finish over ssh` | `ssh` to the PBS failed. Paste the `pbs-access.sh` setup writes into the PBS web shell, after typing `sh` there (then `exit`). Unattended, pass `--pbs-ssh root@HOST`. |
| `setup wrote ..., but certistack check did not pass` | Apply the fix printed above it, then run `certistack check --env-file` with that file. |

### Issue 1: The run cannot start or reach the node {#issue-1-the-run-cannot-start-or-cannot-reach-the-node}

`run`, `plan`, `init` or `check` stops before it creates anything, and the message names the cause.

| Message | Fix |
| --- | --- |
| `open controller environment file: ... no such file or directory` | The file is not there yet: run `certistack setup`, which writes it ([quickstart step 2](quickstart.md#2-run-the-setup)), or write it by hand ([Set up by hand](manual-setup.md)). `check` says the same at layer 1. |
| `controller secret environment variable PVE_URL is required` (or another variable) | Set it in the environment file. With `--env-file`, only the file counts. |
| `this host is not a PVE node ..., and no SSH host is set` | Pass `--env-file /secure/certistack/controller.env`, or add `CERTISTACK_SSH_HOST` to the file. |
| `unsupported controller environment variable`, `duplicate controller environment variable`, `invalid controller environment line N` | Write each [variable](configuration.md#variables) once, as `NAME=value`, in capitals, without `export`. `NAME is not a CertiStack setting` means the name is not in that list (`PATH` from a shell profile, say): the file holds only those settings and is never run as a shell script. |
| `invalid controller environment variable "NAME" on line N`, `values in FILE are not shaped as they should be` | Fix the value as the message says (`PVE_URL` starts with `https://`, `PVE_TOKEN_ID` is `user@realm!tokenname`). |
| `controller environment file must not be accessible by group or other users` | Run `chmod 600` on the file. |
| `prepare controller report directory`, `controller report directory ... is not writable` | Run `sudo install -d -m 0700 -o "$USER" /var/lib/certistack/reports`, or set `CERTISTACK_OUTPUT_DIR`. |
| `controller report directory ... can be written by group or other users` | Another user could replace a report there. Run the `chmod 700 DIR` the message gives (for every directory it names, one run at a time). |
| `invalid PVE node name`, `this host is PVE node X, but the node name given ... is Y`, `reaches PVE node X, but CERTISTACK_NODE names node Y` | Set `CERTISTACK_NODE` to the short name PVE shows, in the same case and without a domain. |
| `an absolute SSH known_hosts path is required` | Set `CERTISTACK_SSH_KNOWN_HOSTS` to the absolute path setup wrote. |
| `can be written by group or other users`, `who is neither root nor the user CertiStack runs as` | The `known_hosts` file or SSH key could be changed by another user, who could then answer as the node or sign in as the controller. Run the fix the message gives: `chmod 600 FILE`, or `sudo chown $USER FILE`. In the controller container the files belong to UID `65532`. |
| `SSH known_hosts path ... is not a regular file`, `SSH identity path ... is not a regular file` | Point `CERTISTACK_SSH_KNOWN_HOSTS` or `CERTISTACK_SSH_IDENTITY` at the file itself, not a named pipe or a device: ssh would wait on one forever. |
| `--output linger/reports is not an absolute path; use /root/linger/reports` (also `--scratch`, `--state-dir`, `--ssh-known-hosts`, `--ssh-identity`; `is not a clean path`) | Give the path the message names. `--output`, `--ssh-known-hosts` and `--ssh-identity` are paths on the controller; `--scratch` and `--state-dir` are paths on the node and start with `/`. A path has no `..`, `//`, `./` or trailing `/`. The same settings in `controller.env` are `CERTISTACK_OUTPUT_DIR`, `CERTISTACK_SCRATCH_DIR`, `CERTISTACK_STATE_DIR`, `CERTISTACK_SSH_KNOWN_HOSTS` and `CERTISTACK_SSH_IDENTITY`. |
| `Host key verification failed.` | If the key is missing, run `certistack setup trust-node --host <your CERTISTACK_SSH_HOST>`; the entry must match that spelling (a name is not found by IP address). If it changed, find out why first: a reinstalled node has a new key, and so does an impostor. |
| `Permission denied (publickey,...)` | The account in `CERTISTACK_SSH_USER` must exist (stock nodes have `root`, not `certistack`) and hold the public key of `CERTISTACK_SSH_IDENTITY`. |
| `create protected node workspace` then `Permission denied`, `sudo: a password is required` | Connect as `root`, or give the account passwordless `sudo` and set `CERTISTACK_SSH_SUDO=true`. |
| SSH from the controller to the node: `Could not resolve hostname`, `Connection timed out`, `Connection refused` | Check `CERTISTACK_SSH_HOST`, `CERTISTACK_SSH_PORT` and firewalls. A probe that fails inside the sandbox is [Issue 45](#issue-45-a-probe-fails-on-a-first-run). |
| `x509: certificate signed by unknown authority` | Run `certistack setup` again, or `certistack setup pve-ca --env-file <file>` and add the line it prints. For Terraform, run `apply` with `SSL_CERT_FILE=/secure/certistack/pve-root-ca.pem`. |
| `PBS's TLS certificate was not confirmed` | Set `PBS_FINGERPRINT` (PBS dashboard, Show Fingerprint). |
| `list PBS snapshots for vm/...:` and `PBS refused the login`, `PBS_FINGERPRINT does not match`, `PBS denied access`, `no such namespace or datastore path` or `the connection to the PBS server failed` | Check `PBS_PASSWORD`, `PBS_FINGERPRINT`, the `DatastoreReader` role, `PBS_NAMESPACE`, or the host and port. For `client output withheld`, run `proxmox-backup-client snapshot list --repository <your PBS_REPOSITORY>` on the node. |
| `reports architecture "aarch64"` | The controller copies itself to the node, and releases are amd64 only: arm64 nodes are not supported. |
| `node preflight failed` | The text names the check (a missing `guestfish`, no `/dev/kvm`). [`certistack doctor`](cli-reference.md#doctor) on the node lists them all. |
| `cannot hold overlays on node`, `which needs overlay storage`, `No such storage` | Run setup, which adds a storage; or name one in `storage.overlay_storage`, run `certistack setup rbac --node <node> --overlay-storage ID`, and run the PVE part it prints on the node as root. |

## Before a run starts

### Issue 2: "another CertiStack operation holds the host lock"

**Cause:** A node runs one CertiStack operation at a time (a run from any controller, or a recovery). A second is
refused, not queued, and writes no report. `plan`, `check` and `init` without `--inspect` take no lock.
`init --inspect` does: while another operation holds the lock, it maps nothing and still writes its plan.

**Fix:** On the node, `pgrep -af certistack-node` shows the running worker. Wait, then run again; stagger scheduled
runs ([Run it on a schedule](automation.md)). The lock, `/run/certistack.lock`, ends with its process; do not delete
it.

### Issue 3: "admission denied: RAM usage XX% exceeds max YY%"

**Message:** one of:

- `Host admission deferred: RAM 88.4% exceeds the 85.0% limit.` The run waits and retries, then fails after
  `max_defer_retries`.
- `recovery reservation 2304 MiB plus current host usage would reach 25.04% ...`: the plan's VMs would push the node
  over. It waits the same way.
- `the plan can never be admitted on this node`: the plan's VMs alone exceed the limit. It fails at once.

**Cause:** Admission control protects your other VMs. The reservation is each sandbox VM's memory plus 256 MiB; a
balloon does not reduce it.

**Fix:** Check `free -m` on the node, and wait or move load. If memory is truly free, raise the limit in the plan's
`admission_control` block (keep its other three fields):

```yaml
admission_control:
  max_host_ram_percent: 90.0
```

Or lower `hardware_overrides.memory_mb`, or split the plan.

### Issue 4: A MAC address or a wire-probe target is refused {#issue-4-a-mac-address-or-a-wire-probe-target-is-refused-before-anything-is-created}

**Message:** before anything is created, one of:

- `"00:00:00:00:00:00" (VM 9001 net0) is not a usable MAC address`, or `a multicast (group) address cannot name an
  interface`;
- `VM 9901 net0 and VM 9900 net0 both use 00:11:22:33:44:55` (or `VM 9900 net1 and VM 9900 net0`), usually clones;
- `... keeps its guest's network as backed up (network_recovery.mode preserve), but its mac … is not its backup's`;
- `wire probe target 192.0.2.10 is named by VMs 9001, 9002`.

**Fix:** Remove the `mac` (the VM takes its backup's) or set a unicast one no other NIC uses. Restore clones in
separate runs. In `preserve` mode, leave out `mac` and `nic_model`. Give each VM its own wire-probe address.

### Issue 12: "the cluster's SDN configuration has changes that have not been applied"

**Cause:** Someone left an SDN change unapplied. PVE applies SDN all at once, so applying the sandbox would push that
change into production too. The run stops before it creates anything.

**Fix:** Ask whoever changed SDN to apply or discard the change (Datacenter > SDN), then run again. Do not apply
someone else's change yourself.

- If a change appears during a run, the run leaves its zone and VNet in place. Once the change is settled, run the
  recovery ([Issue 26](#issue-26-lost-contact-with-node)). Recovery says `changes that are not the interrupted run's`
  until then.
- PVE 8 has no SDN lock, so CertiStack only checks for pending changes. Keep SDN changes off the cluster during a run,
  and run on one node of a PVE 8 cluster at a time. With over 64 other VNets, or other pending objects, use a
  pre-provisioned sandbox (`network.lifecycle: preprovisioned`).

### Issue 33: "the clock of node … is about … ahead of the controller's" {#issue-33-the-clock-of-node-is-about-ahead-of-the-controllers-or-behind}

**Cause:** The node stamps its report, and a report is accepted only when its timestamp is within 10 min of the run on
the controller's clock. So `run` reads the node's clock before it starts anything; `certistack plan` reads it too.

- A node **ahead** of the controller by more than 10 minutes plus the time the controller can take between the stamp
  and the check (at most 30 minutes) has its report refused whatever the run's length. The message ends `Nothing was
  started on the node.`
- A node **behind** the controller is never refused first, however far. The warning says the report is accepted only
  if the run lasts at least about N min; a shorter run ends with its report refused and no evidence written.
- 5 minutes or more is warned of, and the run goes on. A clock that cannot be read is said; the end of the run decides.

**Fix:** Set the node's time from a reliable source (`chronyc tracking` shows the offset), then run again.

### Issue 46: A backup is refused before the run starts {#issue-46-a-backup-is-refused-before-the-run-starts}

`plan`, `doctor` and `run` read each backup's VM configuration (`qemu-server.conf`) and its list of disks before they
create anything, and refuse a backup that is not one PVE made of a VM. `init` leaves such a backup out and says why.
Each message names the backup it is about.

| You see | Fix |
| --- | --- |
| `is not a Proxmox VE configuration: it holds binary data` | The snapshot's `qemu-server.conf` is not text: it holds a NUL byte, or invalid text or a control character on a line that is not part of the VM's description (the `#` lines, which may hold any character). Choose another snapshot of the VM, and check this one in PBS (`proxmox-backup-client snapshot files`). |
| `the backup holds no VM configuration (qemu-server.conf)` | The snapshot has no `qemu-server.conf.blob`, so a Proxmox VE backup job did not make it of a VM. Choose another snapshot, or back the VM up with a PVE backup job. Setting `use_backup_config: false` does not help: every run reads the configuration. |
| `the backup's configuration has cores 512, more than PVE allows (1 to 256)` (also `sockets`, `memory`, `balloon`, `cpuunits`) | The backup's configuration holds a value PVE cannot take. Only `use_backup_config: true` reads the hardware from it. Set `use_backup_config: false` and give the value in the plan (`hardware_overrides.cores`, `.sockets`, `.memory_mb`, `.balloon_mb` or `.cpu_weight`), or restore from a backup made before the value changed. |
| `the backup holds a container's file archive (root.pxar), not a VM disk` | The snapshot is a container's backup (an LXC `root.pxar`), even under `vm/`. CertiStack restore-tests VMs only. Choose a VM's backup. `init` leaves such a backup out of its list. |
| `is a container backup (ct/...): containers are not supported` | `source_pbs.snapshot` names a `ct/` group. Give `latest` (with `source_vmid`) or `vm/<vmid>/...` of a VM. |
| `the snapshot holds drive-scsi0 but its configuration lists no scsi0` | The configuration does not describe the disk the snapshot holds, so it is not that VM's configuration. Choose another snapshot. Setting `use_backup_config: false` does not help: every run reads the configuration. |

## Before a run starts: the sandbox range {#the-sandbox-range}

During a run, the node routes all of `network.ip_range` into the sandbox, so the range must hold nothing the node
uses. `plan`, `check`, `doctor` and the run refuse one that does.

The fix is another range, such as `192.0.2.0/24`, which nothing real uses. Change `network.ip_range`,
`network.probe_ip` and each probe's `target_ip` together. `ip -4 route` on the node lists what it uses.

### Issue 39: The sandbox range contains the PVE API or the PBS server

```text
network.ip_range 10.42.10.0/24 contains the PBS server (pbs.example.com, 10.42.10.5). ...
```

**Fix:** Choose a range without the host of `PVE_URL` or `PBS_REPOSITORY`. `getent hosts <name>` on the node shows a
name's address.

### Issue 40: The sandbox range overlaps a network of the node {#issue-40-the-sandbox-range-overlaps-a-network-an-address-or-a-gateway-of-the-node}

```text
network.ip_range 10.42.15.0/24 overlaps the node's real network 10.42.15.0/24 (on interface vmbr4): ...
```

Other forms name a gateway, an address of the node, or another routing table (Tailscale uses table 52).

**Fix:** Choose a range outside every network, address and gateway the node has (`ip route show table all`). A range
inside a larger routed network (`10.99.0.0/24` with a route for `10.0.0.0/8`) is refused too.

- `Interface csVnet1 is the plan's own VNet`: a run is going (wait), or one left it: run the recovery
  ([Issue 26](#issue-26-lost-contact-with-node)).
- A guest in `network_recovery.mode: preserve` needs its own subnet as the range. Run it on a node with no address or
  route in that subnet, or re-address the guest.

### Issue 41: The probe address is an address of the node

```text
network.probe_ip 10.42.15.36 is an address of the node itself (on interface vmbr4): ...
```

**Fix:** Set `network.probe_ip` to an unused address in a range the node does not use, such as `192.0.2.1`.

### Issue 42: The sandbox range is IPv6, has host bits set or is not canonical {#issue-42-the-sandbox-range-is-an-ipv6-range-has-host-bits-set-or-is-not-written-canonically}

```text
network.ip_range: "fd00::/64" is an IPv6 range, and IPv6 sandbox ranges are not supported: ...
network.ip_range: 192.0.2.5/24 has host bits set: ... did you mean 192.0.2.0/24?
network.ip_range: "10.0.0.0/08" is not written in its canonical form (...): write it as 10.0.0.0/8
```

**Fix:** Write an IPv4 network, as the message says. Fix this first; the other checks need it.

### Issue 43: "could not check the node's routes"

**Cause:** The worker could not read the node's routes (a restricted `/proc`, a failing `ip`). That is not a pass: a
run does not go ahead; `plan`, `check` and `doctor` warn (`!`).

**Fix:** On the node, check that nothing in `ip route show table all` or `ip -4 -o address` overlaps the range. Then
let the worker read `/proc/net/route` as root.

### Issue 44: The sandbox range holds an address the node needs {#issue-44-the-sandbox-range-holds-an-address-the-node-needs-the-ssh-client-a-dns-server-a-vxlan-peer}

```text
network.ip_range 198.51.100.0/24 contains 198.51.100.7, the address this SSH session reaches the node from (the controller): ...
```

Or `a DNS server in /etc/resolv.conf`, or `a VXLAN peer in network.peers`.

**Fix:** Choose a range that holds none of them. If the controller's network is large (all of `10.0.0.0/8`), go
outside it.

## During the run

### Issue 5: "map PBS backup image: …" and no free loop device {#issue-5-map-pbs-backup-image-client-output-withheld-n-bytes-and-no-free-loop-device}

**Message:** `map PBS backup image: ... (client output withheld; N bytes)`. The output is withheld because it can hold
credentials. A common cause is no free loop device.

**Fix:** `losetup -a` lists loop devices. Never detach one because it looks unused: run the recovery
([Issue 26](#issue-26-lost-contact-with-node)), which frees only what its journal records.

- **`stale_loops` warning** (from `doctor` or a preflight): a dead PBS map. Run the commands it gives, in order. If
  it names a FUSE connection, abort that first: `echo 1 > /sys/fs/fuse/connections/<N>/abort`.
- **It names `md126`, `md127` or `dm-0`:** the node assembled a guest's RAID or LVM from the loop. Check that nothing
  mounts them and they are not the node's own (`lsblk`), then run the warning's commands, such as:

    ```bash
    mdadm --stop /dev/md126 /dev/md127
    losetup -d /dev/loop0 /dev/loop1
    ```

    For device-mapper, use `dmsetup remove <name>`.

- **Cleanup says `PBS loop device … remains attached` or `… is still the attachment this run made`:** something holds
  the loop. `fuser -v /dev/loopN` and `lsblk /dev/loopN` show what; once it lets go, the next recovery frees it.

### Issue 6: "the mapped PBS image is N bytes, but the snapshot's manifest records M bytes …" {#issue-6-the-mapped-pbs-image-is-n-bytes-but-the-snapshots-manifest-records-m-bytes-for-this-disk}

**Cause:** The mapped disk is not the size the backup records, or reading it ended early. The disk is never reported
as verified.

**Fix:** Run again. If it repeats, verify the snapshot in PBS, or back the VM up again. A different `size=` in the
VM's configuration is not this error; `qm disk rescan --vmid <id>` fixes that. `(qemu-server.conf.blob) at N bytes`
means a corrupt snapshot: choose another. `the PBS client wrote more output than CertiStack accepts`: check the
repository and the client.

### Issue 8: A PVE 8 node reads the wrong backups or claims encryption {#issue-8-a-pve-8-node-reads-the-wrong-backups-or-says-a-backup-is-encrypted-when-it-is-not}

**Cause:** With a PBS namespace, PVE 8's `proxmox-backup-client` 3.x ignores `PBS_NAMESPACE` and reads the root
namespace, so it can take another backup or say `is encrypted`.

**Fix:** None needed: CertiStack passes `--ns` itself. If a report names the wrong backup, run the plan again.

### Issue 9: "failed to create SDN zone …" or "failed to create SDN VNet …" {#issue-9-failed-to-create-sdn-zone-or-failed-to-create-sdn-vnet-pve-api-error-http-403-or-http-400}

**Cause:** The token lacks SDN permissions (`HTTP 403`), or SDN is unavailable.

**Fix:** `pvesh get /cluster/sdn/zones` must answer on the node. Give the token the role setup creates, not
`Administrator` ([Set up by hand](manual-setup.md)). The plan's `zone_id` and `vnet_id` must not already exist.

### Issue 10: "CertiStack does not own or reuse pre-existing resources" {#issue-10-certistack-does-not-own-or-reuse-pre-existing-resources}

**Cause:** The plan's zone or VNet already exists, and this run did not make it.

**Fix:** If an interrupted run left it, run the recovery ([Issue 26](#issue-26-lost-contact-with-node)). Otherwise
leave it and settle the name clash with its owner.

### Issue 30: "node worker returned an unusable result"

**Cause:** The worker's output was empty, cut off or not a result. Its journal is recovered and no report is written.

**Fix:** Run again; if it repeats, keep the node's log. `output exceeded 67108864 bytes` means a result over 64 MiB:
split a plan that may have over a hundred failing VMs (each carries a screenshot).

### Issue 31: "this script was altered by the program that started it …" {#issue-31-this-script-was-altered-by-the-program-that-started-it-so-it-cannot-run-refusing-to-start}

**Cause:** The node's `systemd-run` changed the worker's script, so nothing started.

**Fix:** Run this on the node. A good `systemd-run` prints `${x##*y}%h`; report anything else, with
`systemctl --version`.

```bash
systemd-run --wait --pipe --quiet --collect /bin/sh -c 'printf "%s\n" "$1"' sh '$${x##*y}%h'
```

### Issue 32: "N progress lines were not shown …" {#issue-32-n-progress-lines-were-not-shown-because-the-progress-output-did-not-keep-up}

**Cause:** Whatever reads the output (a pipe, a pager, a job log) was too slow. The run went on.

**Fix:** Check that reader. The report holds every result. The node keeps the whole progress in
`/var/lib/certistack/logs/<run>.log` only when it recovered the run itself.

## Probes and guests

### Issue 45: A probe fails on a first run {#issue-45-a-probe-fails-on-a-first-run}

**You see:** the report shows `Outcome: FAIL`, and under the VM a probe such as `FAIL tcp 192.0.2.10:22`
with `connection refused` or a timeout.

**Cause:** the VM booted, but the service did not answer the sandbox. The probe comes from the plan's
`network.probe_ip` (`192.0.2.1` in a plan `init` wrote), inside `network.ip_range` (`192.0.2.0/24`). Almost
always it is the guest itself:

- `connection refused`: nothing listens on the port, for example `sshd` is not enabled at boot. A
  crash-consistent backup taken while the guest was still writing (during its first boot, say) can
  also hold empty files, such as `sshd`'s host keys, so the service cannot start in the copy.
- A timeout: the guest's firewall drops it, for example a rule that allows SSH only from your LAN.

**Fix:** in the **source VM** (the sandbox is a copy of its backup), enable the service at boot and allow
the port from `network.ip_range`. Then back the VM up again and rerun the plan. To see what the guest did,
set `network_recovery.capture_diagnostics: true` for the VM in the plan and read the `Network diagnostic`
block under the probes in `report show`: it lists the enabled services that were not running, and
`condition=no` marks one that systemd skipped. `init --inspect` lists the services the backup has enabled.

### Issue 15: LDAP base search returns `noSuchObject` or no entry

**Cause:** The `base_dn` in the plan is missing from the backup, or anonymous clients may not read it.

**Fix:** If the application needs that DN, look at the backup's data. To check only that the directory works, use
`base_dn: auto`. For Active Directory (often `operationsError`), use `naming_context: DC=example,DC=com`. Leave out
`base_dn` only for a listener check.

### Issue 16: LDAP listener times out after sandbox boot {#issue-16-ldap-listener-times-out-after-a-successful-sandbox-boot}

**Cause:** The guest booted, but nothing answered on port 389: the directory did not start, or a firewall blocks it.

**Fix:** Read the VM's `Network diagnostic` block, under its probes, in `report show`. In the source VM, check `systemctl status slapd`,
`ss -lntup` and the firewall. Fix it there, back up, and run again.

### Issue 17: A restored DC answers LDAP and Kerberos but not DNS {#issue-17-a-restored-domain-controller-answers-ldap-and-kerberos-but-not-dns}

**Cause:** The DNS Server service missed its start deadline.

**Fix:** As for [Issue 19](#issue-19-a-windows-guests-agent-or-services-never-start-in-the-sandbox). If the DC's DNS
listens only on its own address (`ListeningIPAddress`), keep that address in the sandbox.

### Issue 18: A service is "inactive": its data mount was skipped {#issue-18-a-service-is-inactive-because-its-data-mount-was-skipped}

**Message:** The diagnostic shows `Timed out waiting for device` and `Dependency failed for` a mount.

**Cause:** The disk's first read was slower than the mount's timeout, so a `nofail` mount was skipped.

**Fix:** As for Issue 19, or run when PBS is less busy. Lengthen a short `x-systemd.device-timeout` in the source VM.

### Issue 19: A Windows guest's agent or services never start {#issue-19-a-windows-guests-agent-or-services-never-start-in-the-sandbox}

**Message:** The guest answers its wire probes, but `qemu-guest-agent is not running in the guest`, or a service is
`STOPPED`. Its System log shows events 7009 and 7000.

**Cause:** A cold boot: Windows read each block from PBS, and services missed their 30-second start deadline. If the
node cannot keep a tier's disks cached, `copy_before_boot: auto` copies them to the overlay storage first. When it
cannot copy (overlays on the cluster database's disk, too little room, `storage.max_copy_gib`), the plan warns: `The
tier's disks (N GiB together) are more than this node can keep cached`.

**Fix:**

- Put the overlay storage on its own disk, with room for the tier's disks.
- Set `copy_before_boot: always` on every VM of the tier; it fails before boot when there is no room.
- Leave free memory of at least the tier's total disk size, or split the tier.
- Run Windows plans outside the backup window. Do not use `--skip-integrity`.

### Issue 20: A Windows sandbox VM's clock is hours off

**Cause:** PVE starts Windows with the clock in local time, and the sandbox has no time source.

**Fix:** Restore the domain's time source (a DC) in the same tier, or keep time-sensitive checks relative to the
guest's clock.

### Issue 21: An `mssql` probe fails after trying TDS 8.0 {#issue-21-an-mssql-probe-fails-after-it-also-tried-tds-80-strict-encryption}

**Message:** `the cleartext TDS PRELOGIN failed (...); ... and that failed too (...)`.

**Cause:** The server answered neither plain TDS nor TDS 8.0 strict encryption, or had not finished starting.

**Fix:** Raise `startup_grace_period_sec` or `timeout_sec`. To check the service itself:

```yaml
- type: qga
  command: "sc query MSSQLSERVER" # MSSQL$<instance> for a named instance
  require_qga: true
  timeout_sec: 60
  description: SQL Server service is running
- type: tcp
  target_ip: 192.0.2.20
  port: 1433
  timeout_sec: 60
  description: SQL Server accepts connections
```

`did not select ALPN protocol tds/8.0` means another TLS service (HTTPS) holds the port. With `server_name`
set, `x509: certificate signed by unknown authority` means the node lacks the CA.

### Issue 22: "service check N of the soak failed" or "… liveness is unknown" {#issue-22-service-check-n-of-the-soak-failed-or-vm-ns-state-could-not-be-read-from-pve-so-its-liveness-is-unknown}

**Cause:** During `soak_time_sec`, the run checks each VM's probes every 30 seconds and PVE's status every 10.

- `service check N of the soak failed`: a service stopped answering after it passed. Find out why in the guest, or
  raise the probe's `timeout_sec` to the outage you accept.
- `... so its liveness is unknown`: PVE's status could not be read for two minutes, or the token lacks access (it
  needs `VM.Audit` on the VM, as setup's role gives). Read `first_status_error` in the report.

### Issue 23: Stage 3 probe marked as SKIPPED

**Cause:** The QEMU guest agent is not running in the guest. A skip is never evidence: a VM with only skipped probes
fails as `unverified`.

**Fix:** Install the agent in the source VM (`apt-get install qemu-guest-agent`; on Windows, from the VirtIO ISO), or
set `require_qga: true` to fail instead of skip.

### Issue 24: QGA is connected but guest-exec is unavailable {#issue-24-qga-is-connected-but-the-report-says-guest-exec-is-unavailable}

**Message:** `QGA guest-exec error: Command guest-exec has been disabled`.

**Cause:** The guest's agent policy forbids commands. On Rocky, Alma, RHEL and Oracle Linux, that is the default.

**Fix:** Probe the service over the network instead (`tcp` or `http`).

### Issue 25: "Forensic framebuffer capture completed for VM …" {#issue-25-forensic-framebuffer-capture-completed-for-vm-the-failure_artifact-in-the-report}

**Message:** The report holds a screenshot of the failed VM (`failure_artifact`). On the controller, save it as a PNG:

```bash
jq -r '[.. | objects | .failure_artifact? // empty] | first' \
  /var/lib/certistack/reports/plan-id/report-uuid.json | base64 -d > failure.png
```

`report show` does not show it. Look for a kernel panic, a Windows stop code, or a GRUB prompt.

### Issue 38: A wire probe fails with "bind: cannot assign requested address"

**Cause:** A network reload on the node (every cluster-wide SDN apply reloads every node) removed the probe address.
The run puts it back within seconds.

**Fix:** Run the plan again. Keep SDN changes away from your validation times. If the log says the address could not
be put back, the node may now have an address or route in the range.

## Cleanup and recovery

### Issue 26: "Lost contact with node …"

**The node answers.** When the connection ends and the node answers again at once, the node is up and the message
says so: `The node worker on node … ended without a result (killed or crashed); the node itself answered`. Only
the worker's process ended, for example by a kill, a crash or the kernel's out-of-memory killer. The controller
recovers the run's resources before it returns, and no report is written. The message names the worker's log:
on the node, `journalctl -u certistack-worker-<run id>`. Read it, then run again. `The ssh connection to node …
ended while the node worker was still running` means only the connection was cut: the controller stopped the worker
and recovered its resources.

**Cause:** Otherwise the node did not answer for 60 seconds: it crashed, rebooted or lost its network.
`Cannot reach node … to renew the worker's lease` warns of it earlier.

**Fix:** If the node answers within 20 minutes, the controller cleans up by itself; the run ends with an error and
no report. Otherwise the controller prints a recovery command: run it on the node, or let the node's next run
recover. If only the network failed, the node stops the run itself once the controller's 90-second lease runs out,
and cleans up. If the node rebooted, its next run recovers this run's resources before it starts. Check the node
(`journalctl -b -1`) before the next run.

To recover now, run this on the node, as root:

```bash
/var/lib/certistack/workers/<run>/certistack-node recover \
  --state-dir /var/lib/certistack \
  --env-file /var/lib/certistack/workers/<run>/runtime.env
```

`ls /var/lib/certistack/workers` shows `<run>`. Other issues call this "run the recovery". After it succeeds, the
workspace stays as a record of the run; the next run removes its credentials, and you may delete it. If the workspace has
`credentials-removed.txt`, run `certistack run` once more from the controller instead; it recovers first.

### Issue 27: "kept … in place: sandbox VM … was not confirmed destroyed" {#issue-27-kept-in-place-sandbox-vm-was-not-confirmed-destroyed-or-cannot-be-confirmed-gone-still-exists}

**Cause:** A sandbox VM may still exist, so CertiStack keeps its disks, maps and probe address. The message before
it says why.

**Fix:** Fix what blocked the removal (the token's permissions, a lock on the VM, the API), then run the recovery
([Issue 26](#issue-26-lost-contact-with-node)). Do not delete the kept files by hand while the VM exists.

| Related message | What to do |
| --- | --- |
| `reported success, but sandbox VM … still exists` | PVE's task and the VM disagree. Check `qm status <vmid>` and the node's task log. |
| `does not carry this run's CertiStack ownership markers` | The VM is not marked as the run's, so it was left alone. If it is not the run's, delete its entry from `vms` in `active.json` in the state directory; if it is, destroy it by hand. Then run the recovery. |
| `is not the file this run created`, `is not the file the interrupted run created there` | CertiStack never removes such a file. Remove it if you do not need it, or delete its line from `delta_files` in the journal; then run the recovery. |
| `is not named as a disk file CertiStack makes` | The journal names a file it has no proof of: CertiStack removes it only by its own names (`certistack-delta-…`, `certistack-copy-…`). Check the file, remove it if it is the run's, and delete its line from `delta_files` in the journal; then run the recovery. |
| `left /dev/loopN attached: ... which is not a PBS map file` | The journal names a loop on a file a run never maps (runs map only into `/run/pbs-loopdev`), so recovery leaves it and what uses it. Check it with `losetup -l`, detach it yourself only if it is the run's, delete its entry from `loops` in the journal; then run the recovery. |

### Issue 28: "The node worker … cannot be stopped" {#issue-28-the-node-worker-cannot-be-stopped-is-still-running-after-sigkill}

**Cause:** The worker outlived SIGKILL: it is stuck in the kernel (state `D`), usually on hung storage. It keeps the
host lock, so no run or recovery can start.

**Fix:** `ps -o pid,stat,wchan:32,cmd -p <PID>` shows what it waits on. Fix that storage, or reboot the node; its
next run recovers the journal. Do not run the recovery while the process exists.

### Issue 29: "The controller cannot verify that this run cleaned up after itself"

**Cause:** The node's journal does not show that this run left nothing behind. The report is saved but is not
evidence, and the command exits with an error, even on a pass.

**Fix:** On the node, as root, read the journal: `cat /var/lib/certistack/active.json`. (While the workspace still has
`certistack-node`, `/var/lib/certistack/workers/<run>/certistack-node inspect --state-dir /var/lib/certistack` prints
the same; the node removes it about 90 s after the controller leaves.) Look for this run's sandbox VM (its ID is in the report), overlays and PBS maps, and remove only what this run made.
Then run again.

### Issue 7: "PBS map process N of … recovery left it running" {#issue-7-pbs-map-process-n-of-recovery-left-it-running-or-but-nothing-proves-it-is-recovery-left-it}

**Cause:** An interrupted run left a `proxmox-backup-client map`, and recovery stops a map only when it can prove the
run started it. The node starts no new run until this is settled.

**Fix:** Do what your message needs, then run the recovery ([Issue 26](#issue-26-lost-contact-with-node)).

| Message | What to do |
| --- | --- |
| `still runs after SIGINT and SIGKILL`, `has not exited after 20s`, `cannot read the command line of process N` | It is stuck: `cat /proc/N/stack` shows on what. State `D` needs a reboot. |
| `nothing shows the run started it`, `cannot tell whether the interrupted run started`, `cannot be bound to a pidfd` | If the run started process N, run `kill -INT N`. |
| `/dev/loopN looks like the interrupted run's PBS map` | If nothing uses it, run `proxmox-backup-client unmap /dev/loopN`. |
| `a leftover PBS map file … looks like the interrupted run's` | If no loop or client uses it, `umount -l` it and remove it and its `.pid` file. |
| `cannot establish that /dev/loopN is still the run's PBS map` | Check `losetup -l`; release the loop only if it backs the run's map. |

### Issue 11: "cannot safely reconcile unconfirmed allocation"

**Cause:** CertiStack was interrupted, or got no reply, before PVE confirmed something it asked for. The journal keeps
the name (`allocation_pending`) and does not guess.

**Fix:**

1. Read the journal: `cat /var/lib/certistack/active.json`. (While the workspace still has `certistack-node`,
   `/var/lib/certistack/workers/<run>/certistack-node inspect --state-dir /var/lib/certistack` prints the same; the
   node removes it about 90 s after the controller leaves.)
2. If it names an SDN zone or VNet, or a host probe address (`host probe address <cidr> on <vnet>`), run the recovery
   of step 4 first; if it refuses, go on with step 3.
3. Otherwise, confirm in PVE that the object is the sandbox's (run ID, task history), then delete it: subnets, then
   VNet, then zone.
4. Run the recovery ([Issue 26](#issue-26-lost-contact-with-node)). New runs wait until the journal is clean.

What recovery settles itself:

- **A zone or VNet.** The run journals the name (`allocation_pending` reads `SDN zone <id>` or `SDN VNet <id>`) before
  it sends the request that creates it. A zone created and never applied, or a VNet with the run's alias, is deleted,
  and the pending allocation is cleared once PVE's lists show nothing of it is left. When PVE has neither, the request
  had no effect. On PVE 8, which has no SDN lock to hold other clients off, a zone that PVE lists as created and never
  applied is not shown to be the run's either: delete it in PVE if it is the sandbox's.
- **The host probe address.** The host probe address is settled from the host: the run journals "host probe address
  <cidr> on <vnet>" before it adds the address. Table and address both there: both are the run's and are removed.
  Only the address, with no table: the run never installed one, so it never added the address, which was there
  before; it is left alone. When the host cannot be read, or a VM of the run may still run, the allocation stays.

### Issue 13: "… cannot show that it is the interrupted run's" {#issue-13-sandbox-vnet-exists-but-certistack-cannot-show-that-it-is-the-interrupted-runs}

**Message:** `sandbox VNet … exists, but CertiStack cannot show that it is the interrupted run's` (or `sandbox zone …`),
or `left SDN zone … in place`.

**Cause:** Recovery deletes a VNet only while it carries the run's alias (`certistack <run id>`). A zone has no such
field, so recovery deletes it only while PVE still shows it is the run's: a VNet in it carries the alias (also one whose
deletion is not yet applied), or the zone was never applied. Otherwise, such as an empty zone of the same name made after
the run's VNet was gone, the reason is `no VNet in it carries the run's marker`, and the zone stays, as it does whenever
recovery left the VNet. A journal from an older version says `the run's journal names no owner marker, as the journals
of earlier versions do not`: recovery then deletes no VNet and no zone that PVE lists for it. `certistack plan` lists
such objects as left in place.

**Fix:** If the object is the sandbox's, delete it in PVE (subnets, then VNet, then zone), then run the recovery again
([Issue 26](#issue-26-lost-contact-with-node)).

### Issue 14: "a request for PVE's SDN configuration lock got no definite answer"

**Cause:** PVE may hold an SDN lock under a token CertiStack never received. The lock never expires.

**Fix:** Run the recovery ([Issue 26](#issue-26-lost-contact-with-node)). If it reports a standing lock and no one else
is changing SDN (`pvesh get /cluster/sdn/zones --pending 1`), release it on a node and run the recovery again.
CertiStack never forces this itself, because the lock may be another tool's.

```bash
pvesh delete /cluster/sdn/lock --force 1
```

## Reports

### Issue 34: "The node worker's report was refused, and no report was written"

**Cause:** The worker's report contradicts the request: usually a worker of another version, another node, a plan
changed during the run, or a node clock that is off
([Issue 33](#issue-33-the-clock-of-node-is-about-ahead-of-the-controllers-or-behind)).

**Fix:** Fix the listed contradictions and run again.

**The kept result.** The worker's raw result is kept at `<output>/refused/<run-id>.refused.txt`, first line
`REFUSED, NOT EVIDENCE: this worker result failed the controller's checks and was never signed`. It is never in the
directory's root and never beside a plan's reports, and has mode 0600. Its name ends in `.refused.txt` and its content
is not JSON, so nothing that reads reports takes it. A result with no report in it is not kept, and neither is a
report that was saved. It holds guest text, so protect it; CertiStack never deletes it.

### Issue 35: "save controller report" fails {#issue-35-save-controller-report-fails-and-the-emergency-copy-of-the-unsaved-report-could-not-be-written-either}

**Cause:** The report directory could not be written (a full disk, a quota, a permission). The run exits `2`.

**Fix:** Free space or point `--output` elsewhere. Save the JSON printed between `-----BEGIN CERTISTACK REPORT-----`
and `-----END CERTISTACK REPORT-----` on the progress output (or on standard output, after `the emergency copy of the
unsaved report could not be written either`). If nothing was printed, run again.

### Issue 36: A keyring, public key or report file is refused

Keyrings and public keys are for reports the Enterprise Edition signs.

| Message | Fix |
| --- | --- |
| `is not a valid set of trusted signers` | Fix each listed entry: a key is 64 hex digits, a `fingerprint` is `SHA256:` and 64 hex digits. |
| `no "trusted_signers" list`, `holds no trusted signer keys` | Add the list and the signer's public key. |
| `member "Public_Key" reads as "public_key"` | Spell the member name exactly. |
| `marks a key as revoked` (a member named `revoked`, or a value such as `"status": "revoked"`) | Remove a revoked signer by deleting its entry, but that also stops the verification of every genuine report the key signed: keep a historical keyring (see the [signer lifecycle](architecture.md#6-signing-and-verification)). |
| `is not a usable Ed25519 key` | Use the signer's real public key, not a placeholder. |
| `not a regular file`, `is larger than the N bytes` | Give the right file. Limits: public key 4 KiB, keyring 1 MiB, report 128 MiB. |
| `report exceeds a size or structure limit` | Another tool or a damaged file wrote it. |
| `unsupported validation mode` | Run the plan again with this release. |
| `.new already exists` | If nothing is running, delete the `.new` file and retry. |

### Issue 37: `verify-report` rejects a report for the plan {#issue-37-verify-report-rejects-a-report-for-the-plan-you-gave-it}

`verify-report --expect-plan plan.yaml` prints `REJECTED` and a reason ([Reports](reports.md)).

| Reason | Fix |
| --- | --- |
| `the report is for a plan file with SHA-256 …` | Give it the exact plan file that ran; a changed comment changes the digest. |
| `ran under a timeout of N s; the plan configures M s`, or another setting that differs | The plan changed after the run. Give it the plan that ran. |
| `records no source snapshot`, or another snapshot than the plan's | The report was changed or is another plan's. Run again. |
| `VMs A, B each record a passing wire probe of ADDRESS` | Give each VM its own wire-probe address. |
| `NOT BOUND: plan digest`, `probe policy`, `soak service checks` or `RTO objective and admission policy` | Not a rejection: the report predates that check, so it was not compared. Run the plan again for full evidence. |
