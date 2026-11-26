# Troubleshooting

## Start here

1. On the controller, `certistack check my-first-plan.yaml` stops at the first failing layer and prints the fix. It
   checks the environment file setup recorded; `--env-file FILE` checks another.
2. For a failed run, `certistack report show` (the newest report in your reports directory) names the VM, the probe and
   the reason.
3. On the node, the worker logs to `journalctl -u certistack-worker-<run id>`, and a run the node recovered itself to
   `/var/lib/certistack/logs/<run>.log`.
4. "Run the recovery" below means the command in [Issue 35](#issue-35).
5. For help, rerun with `--debug`, and keep the plan ID, report ID and state directory.

## Setup and connection

### Setup messages

| You see | Fix |
| --- | --- |
| `the node offered SHA256:...` | A changed host key means a reinstalled node or an impostor: find out which. |
| `Connection reset by ... port 22` | OpenSSH 10 blocks the controller for up to 10 minutes after failed sign-ins. Wait. |
| `apt-get cannot install`, `apt-get would remove` | `apt-get -s install libguestfs-tools nftables` on the node shows why. On PVE 8, replacing `fuse` with `fuse3` is expected and safe: run setup again and answer `y` ([why](manual-setup.md#1-prepare-the-node)). |
| `this node has no SDN API` | PVE 8.0 without `libpve-network-perl`. As root on the node, `apt update; apt install libpve-network-perl ifupdown2`, or update the node to PVE 8.1 or later. Then run setup again (`certistack check` after a finished setup). |
| `/var/lib/vz is on the node's root disk`; later `Put overlay storage on a disk of its own` | Expected on a standalone node with one disk, such as a mini PC, and safe to ignore there. On a cluster node, use [a disk of its own](manual-setup.md#plan-around). |
| `the token's secret is needed` | Put the secret you kept in the file, or run setup again to replace the token (the old secret stops working). |
| `The PBS part did not finish` | In the PBS web shell, type `sh`, paste `pbs-access.sh`, then `exit`. |

<a id="issue-1"></a>

### Issue 1: Cannot start or reach the node

| Message | Fix |
| --- | --- |
| `open controller environment file` | Run `certistack setup`, or [write it by hand](manual-setup.md#set-up-by-hand). |
| `PVE_URL is required` | Set it in the file. With `--env-file`, only the file counts. |
| `invalid controller environment` | One [setting](configuration.md#variables) per line, `NAME=value`, no `export`. |
| `report directory ... is not writable` | Run `sudo install -d -m 0700 -o "$USER" /var/lib/certistack/reports`, or set `CERTISTACK_OUTPUT_DIR`. |
| `Host key verification failed.` | Missing: `certistack setup trust-node --host <CERTISTACK_SSH_HOST>`. Changed: find out why first. |
| `Permission denied (publickey,...)` | The `CERTISTACK_SSH_USER` account must exist and hold the key. |
| `sudo: a password is required` | Connect as `root`, or add a [sudoers rule](manual-setup.md#the-sudoers-rule-for-a-non-root-account). |
| `Could not resolve hostname`, `Connection timed out` | Check `CERTISTACK_SSH_HOST`, `CERTISTACK_SSH_PORT` and firewalls. |
| `x509: certificate signed by unknown authority` | Run `certistack setup pve-ca`, and add the line it prints. |
| `PBS's TLS certificate`, `list PBS snapshots` | Check `PBS_FINGERPRINT`, `PBS_PASSWORD`, `PBS_NAMESPACE` and the `DatastoreReader` grant. |
| `No such storage` | Run setup, which adds one. |

## Before a run starts

<a id="issue-2"></a>

### Issue 2: Host lock held

**Cause:** A node runs one operation at a time (a run, a recovery, `init --inspect`).

**Fix:** Wait for it (`pgrep -af certistack-node` on the node), then rerun. Never delete `/run/certistack.lock`.

<a id="issue-3"></a>

### Issue 3: Admission denied (RAM)

**Cause:** The plan's VMs, each reserving its memory plus 256 MiB, would push the node over its RAM limit
(`max_host_ram_percent`). Neither refusal creates anything:

- `the plan can never be admitted on this node`: the VMs need more than the limit of the node's whole memory, so
  `plan` and `run` refuse at once.
- `max admission retries exceeded`: the plan fits the node, but not beside what runs on it. The run waited and
  checked again (`init` writes 10 retries 30 s apart: 5 minutes), then gave up.

**Fix:** Lower `hardware_overrides.memory_mb`, split the plan, or raise the limit (keep the block's other fields):

```yaml
admission_control:
  max_host_ram_percent: 90.0
```

Freeing memory or running later helps only when the wait ran out.

<a id="issue-4"></a>

### Issue 4: MAC or wire-probe target refused

**Cause:** A zero, multicast or shared MAC (clones), a changed `mac` in `preserve` mode, or a wire-probe address
several VMs use.

**Fix:** Remove `mac` or make it unique; in `preserve` mode, leave out `mac` and `nic_model`. Restore clones in
separate runs. Give each VM its own probe address.

<a id="issue-5"></a>

### Issue 5: Unapplied SDN changes

**Cause:** Applying the sandbox would also apply someone else's pending SDN change.

**Fix:** Have its owner apply or discard it; never apply it yourself. On PVE 8 (no SDN lock), keep SDN changes off
the cluster during runs, and run one node at a time.

<a id="issue-6"></a>

### Issue 6: Node clock ahead or behind

**Cause:** A report counts only if stamped within 10 minutes of the run by the controller's clock.

**Fix:** Sync the node's clock (`chronyc tracking` shows the offset).

<a id="issue-7"></a>

### Issue 7: Backup refused before the run

**Cause:** It is not a PVE backup of a VM (a missing or broken `qemu-server.conf`, a container's), or it holds a value
PVE refuses (`cores 512`).

**Fix:** Choose another snapshot of a VM. For a refused value, set `use_backup_config: false` and give it in
`hardware_overrides`.

## The sandbox range

A run routes all of `network.ip_range` into the sandbox, so it must hold nothing the node uses. Pick an unused range
such as `192.0.2.0/24`, and move `network.probe_ip` and each `target_ip` with it.

<a id="issue-8"></a>

### Issue 8: Range contains PVE or PBS

**Cause:** The range holds the PVE or PBS host.

**Fix:** Choose another range.

<a id="issue-9"></a>

### Issue 9: Range overlaps a node network

**Cause:** It overlaps a network, address or gateway of the node.

**Fix:** Choose a range outside `ip route show table all`. If it names `csVnet1`, a run is going or left it: wait, or
run the recovery. A `preserve`-mode guest needs a node with nothing in its subnet.

<a id="issue-10"></a>

### Issue 10: Probe address is the node's

**Cause:** `network.probe_ip` is an address of the node.

**Fix:** Use an unused one, such as `192.0.2.1`.

<a id="issue-11"></a>

### Issue 11: Range not canonical IPv4

**Cause:** The range must be a canonical IPv4 network, such as `192.0.2.0/24`.

**Fix:** Write it as the message suggests.

<a id="issue-12"></a>

### Issue 12: Could not check the node's routes

**Cause:** The worker could not read the routes, so a run stops.

**Fix:** Let root read `/proc/net/route`, and check `ip route show table all` for overlaps.

<a id="issue-13"></a>

### Issue 13: Range holds a needed address

**Cause:** It holds the controller's SSH address, a DNS server or a VXLAN peer.

**Fix:** Choose a range that holds none of them.

## During the run

<a id="issue-14"></a>

### Issue 14: Map PBS backup image fails

**Cause:** Mapping failed, often for lack of a free loop device.

**Fix:** Never detach a loop because it looks unused: run the recovery, which frees only what its journal records. For
a `stale_loops` warning, run its commands in order, first aborting any FUSE connection it names
(`echo 1 > /sys/fs/fuse/connections/<N>/abort`). Check with `lsblk` that `md` or `dm` devices it names are not the
node's own.

<a id="issue-15"></a>

### Issue 15: Mapped image size differs

**Cause:** The mapped disk is not the size the backup records, or reading it ended early.

**Fix:** Run again. If it repeats, verify the snapshot in PBS, or back up again.

<a id="issue-16"></a>

### Issue 16: PVE 8 reads the wrong backups

**Cause:** PVE 8's `proxmox-backup-client` 3.x ignores `PBS_NAMESPACE`.

**Fix:** Nothing to do: CertiStack passes `--ns` itself. If a report still names the wrong backup, report it as a bug
with the `--debug` output.

<a id="issue-17"></a>

### Issue 17: Failed to create SDN zone or VNet

**Cause:** The token lacks SDN permissions (`HTTP 403`), or SDN is unavailable.

**Fix:** `pvesh get /cluster/sdn/zones` must answer on the node. Give the token
[setup's role](manual-setup.md#the-pve-role-and-its-permissions).

<a id="issue-18"></a>

### Issue 18: Pre-existing zone or VNet

**Cause:** The plan's zone or VNet exists, and this run did not make it.

**Fix:** If an interrupted run left it, run the recovery; otherwise settle the clash with its owner.

<a id="issue-19"></a>

### Issue 19: Unusable worker result

**Cause:** The worker's output was empty, cut off or over 64 MiB.

**Fix:** Run again. Split a plan with over a hundred failing VMs.

<a id="issue-20"></a>

### Issue 20: Script altered by systemd-run

**Cause:** The node's `systemd-run` changed the worker's script, so nothing started.

**Fix:** Run this on the node. A good `systemd-run` prints `${x##*y}%h`; report anything else.

```bash
systemd-run --wait --pipe --quiet --collect /bin/sh -c 'printf "%s\n" "$1"' sh '$${x##*y}%h'
```

<a id="issue-21"></a>

### Issue 21: Progress lines not shown

**Cause:** The output's reader (a pipe, a pager) was too slow; the run went on.

**Fix:** Check that reader; the report holds every result.

## Probes and guests

<a id="issue-22"></a>

### Issue 22: Probe fails on a first run

**Cause:** The VM booted, but the service did not answer: `connection refused` if nothing listens (not enabled at
boot, or a backup taken mid-write), a timeout if the guest's firewall drops it.

**Fix:** In the source VM, enable the service and allow the port from `network.ip_range`; back up and rerun.
`network_recovery.capture_diagnostics: true` shows what the guest did.

<a id="issue-23"></a>

### Issue 23: LDAP base search finds nothing

**Cause:** The plan's `base_dn` is not in the backup, or anonymous clients may not read it.

**Fix:** Use `base_dn: auto`, or for Active Directory `naming_context: DC=example,DC=com`.

<a id="issue-24"></a>

### Issue 24: LDAP listener times out

**Cause:** Nothing answered on port 389: the directory did not start, or a firewall blocks it.

**Fix:** In the source VM, check `systemctl status slapd`, `ss -lntup` and the firewall.

<a id="issue-25"></a>

### Issue 25: Restored DC has no DNS

**Cause:** The DNS Server service missed its start deadline.

**Fix:** As for [Issue 27](#issue-27). A DNS that
listens only on its own address needs that address in the sandbox.

<a id="issue-26"></a>

### Issue 26: Data mount skipped

**Cause:** The disk's first read outlasted the mount's timeout, so a `nofail` mount was skipped (`Timed out waiting for
device`).

**Fix:** As for [Issue 27](#issue-27), or lengthen a
short `x-systemd.device-timeout` in the source VM.

<a id="issue-27"></a>

### Issue 27: Windows services never start

**Cause:** On a cold boot Windows reads each block from PBS, and services (the guest agent too) miss their
30-second deadline (events 7009 and 7000).

**Fix:**

- Put the overlay storage on its own disk, with room for the tier's disks.
- Set `copy_before_boot: always` on every VM of the tier.
- Leave free memory of at least the tier's total disk size, or split the tier.
- Run Windows plans outside the backup window. Do not use `--skip-integrity`.

<a id="issue-28"></a>

### Issue 28: Windows clock hours off

**Cause:** PVE starts Windows in local time, and the sandbox has no time source.

**Fix:** Restore a DC in the same tier.

<a id="issue-29"></a>

### Issue 29: mssql probe fails

**Cause:** The server answered neither plain TDS nor TDS 8.0, or was still starting.

**Fix:** Raise `startup_grace_period_sec` or `timeout_sec`.

<a id="issue-30"></a>

### Issue 30: Soak check failed or liveness unknown

**Cause:** A service stopped answering during `soak_time_sec`, or PVE's status was unreadable for two minutes.

**Fix:** Find out why in the guest, or raise the probe's `timeout_sec`. For liveness, read `first_status_error`; the
token needs `VM.Audit`.

<a id="issue-31"></a>

### Issue 31: Probe SKIPPED

**Cause:** The QEMU guest agent is not running. A VM with only skipped probes fails as `unverified`.

**Fix:** Install `qemu-guest-agent` in the source VM, or set `require_qga: true` to fail instead.

<a id="issue-32"></a>

### Issue 32: guest-exec disabled

**Cause:** The guest's agent policy forbids commands, the default on Rocky, Alma, RHEL and Oracle Linux.

**Fix:** Probe the service over the network (`tcp` or `http`).

<a id="issue-33"></a>

### Issue 33: Framebuffer capture

**Cause:** The report holds a screenshot of the failed VM (`failure_artifact`); `report show` does not show it.

**Fix:** Save it, then look for a kernel panic, a stop code or a GRUB prompt:

```bash
jq -r '[.. | objects | .failure_artifact? // empty] | first' \
  /var/lib/certistack/reports/plan-id/report-uuid.json | base64 -d > failure.png
```

<a id="issue-34"></a>

### Issue 34: bind: cannot assign requested address

**Cause:** A network reload (any cluster-wide SDN apply) removed the probe address.

**Fix:** Run again.

## Cleanup and recovery

<a id="issue-35"></a>

### Issue 35: Lost contact with node

**Cause:** The node did not answer for 60 seconds: it crashed, rebooted or lost its network. If it answered, the
controller has already cleaned up; the worker's log says why.

**Fix:** The controller cleans up a node that comes back within 20 minutes; a cut-off node stops the run itself; a
rebooted node's next run recovers first. To recover now, as root on the node (`ls /var/lib/certistack/workers` shows
`<run>`):

```bash
/var/lib/certistack/workers/<run>/certistack-node recover \
  --state-dir /var/lib/certistack \
  --env-file /var/lib/certistack/workers/<run>/runtime.env
```

If the workspace has `credentials-removed.txt`, run `certistack run` from the controller instead.

<a id="issue-36"></a>

### Issue 36: Sandbox VM not confirmed destroyed

**Cause:** A sandbox VM may still exist, so its disks, maps and probe address are kept.

**Fix:** Fix what blocked removal, then run the recovery. Never delete the kept files while the VM exists. Something
without the run's markers is left alone: remove it yourself if it is the run's, otherwise delete its entry from
`active.json` in the state directory.

<a id="issue-37"></a>

### Issue 37: Worker cannot be stopped

**Cause:** The worker is stuck in the kernel (state `D`), usually on hung storage.

**Fix:** `ps -o pid,stat,wchan:32,cmd -p <PID>` shows on what. Fix that storage or reboot the node; never run the
recovery while it exists.

<a id="issue-38"></a>

### Issue 38: Cleanup not verified

**Cause:** The journal does not show that the run left nothing behind, so its report is not evidence.

**Fix:** As root on the node, read `/var/lib/certistack/active.json`, remove only what this run made, and run again.

<a id="issue-39"></a>

### Issue 39: PBS map process left running

**Cause:** An interrupted run left a `proxmox-backup-client map` that recovery cannot prove it started.

**Fix:** If the run started process N, `kill -INT N`; unmap a loop nothing uses with
`proxmox-backup-client unmap /dev/loopN`. State `D` needs a reboot. Then run the recovery.

<a id="issue-40"></a>

### Issue 40: Unconfirmed allocation

**Cause:** PVE never confirmed something the run asked for (`allocation_pending`).

**Fix:** Run the recovery. If it cannot settle the object, confirm in PVE that it is the sandbox's, delete it
(subnets, VNet, zone), and run the recovery again.

<a id="issue-41"></a>

### Issue 41: Zone or VNet ownership unproven

**Cause:** Recovery deletes a zone or VNet only while PVE shows it is the run's.

**Fix:** If it is the sandbox's, delete it in PVE (subnets, VNet, zone), and run the recovery again.

<a id="issue-42"></a>

### Issue 42: SDN lock request unanswered

**Cause:** PVE may hold an SDN lock, which never expires, under a token CertiStack never received.

**Fix:** Run the recovery. If it reports a standing lock and nothing else is changing SDN
(`pvesh get /cluster/sdn/zones --pending 1`), release it, then run the recovery again:

```bash
pvesh delete /cluster/sdn/lock --force 1
```

## Reports

<a id="issue-43"></a>

### Issue 43: Worker's report refused

**Cause:** It contradicts the request: another version or node, a plan changed mid-run, or a node clock that is off.

**Fix:** Fix the listed contradictions, and rerun. The raw result kept in `<output>/refused/` holds guest text:
protect it.

<a id="issue-44"></a>

### Issue 44: Report not saved

**Cause:** The report directory could not be written (a full disk, a quota, a permission).

**Fix:** Free space or use another `--output`, and save the JSON printed between `-----BEGIN CERTISTACK REPORT-----`
and `-----END CERTISTACK REPORT-----`.

<a id="issue-45"></a>

### Issue 45: Keyring, key or report file refused

**Cause:** A keyring or key for [signed reports](reports.md#signed-reports-enterprise) is malformed, or a file is too
large.

**Fix:** A key is 64 hex digits; a `fingerprint` is `SHA256:` and 64. Limits: key 4 KiB, keyring 1 MiB, report
128 MiB. Revoke a signer by deleting its entry; keep the old keyring to verify its reports.

<a id="issue-46"></a>

### Issue 46: verify-report rejects a report

**Cause:** The report does not match the `--expect-plan` file, its settings or its snapshot.

**Fix:** Give it the exact plan that ran (a changed comment changes the digest), or run again. `NOT BOUND` is not a
rejection.
