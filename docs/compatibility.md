# Tested and supported

## Supported versions

| Proxmox VE | PBS | Status |
| --- | --- | --- |
| 9.x | 4.x | tested |
| 8.4 | 4.x | tested |
| 8.4 | 3.x | tested |
| 9.x | 3.x | tested |
| 8.x | 4.x | untested |
| 8.x | 3.x | untested |
| 7.x and older | any | unsupported |
| any | 2.x and older (server or client) | unsupported |

`9.x` means every PVE 9 release: 9.2 was tested, and 9.x is supported. `8.x` means a PVE 8 release other than 8.4.
Any other pair, such as a newer major release, is `untested`, as is a `proxmox-backup-client` of another major than
tested (3.x on PVE 8.4, 4.x on PVE 9). `doctor`, `plan` and `run` check the versions: `untested` and `unknown`
(unreadable) warn; `unsupported` fails `doctor`, and `plan` and `run` refuse before creating anything. The report
records `version_support`.

## What was tested

On the author's own infrastructure: a 14-node PVE 9.2 cluster and standalone hosts, with about 20 other VMs running on
the test nodes.

| What | How much | Build |
| --- | --- | --- |
| Automated tests | Over 7,000 tests and subtests in 43 packages, none failing | The v0.1.1 release commit |
| Fuzzing | 11 fuzz targets: the plan, environment-file and report readers, 17 parsers of PBS client output, and the DNS, LDAP, SQL Server and SMB reply parsers; more than 3.6 million generated inputs | Builds of 15 November |
| Chaos testing | Hostile inputs, fake Proxmox peers that lie, and impossible backups: 44 flaws found, each fixed with a test that failed before the fix. In the lab, 14 impossible backups and 9 fault drills: each was refused before anything was made, or failed cleanly and left its node clean. No false pass anywhere | Builds of 15 November |
| Restore-test campaign | 622 planned cases, 617 passed, including a 96-VM fleet restored in one run (about 17 hours) and a PBS outage in the middle of a run | A pre-release build |
| The broad set | 24 restore tests, all passed (below) | The exact v0.1.1 binary; before it, builds of 8 and 16 November |
| The release | Built twice, byte for byte the same; the release workflow replayed with 17 failure scenarios; the installer's 16 checks | The v0.1.1 release commit |

**The broad set on the exact v0.1.1 binary: 24 restore tests, all passed.** Each ended with its cleanup verified and its
node left as it found it.

| Area | What ran |
| --- | --- |
| Windows | Active Directory forests (two runs), Windows Server 2022, SQL Server, SMB |
| Linux | Ubuntu 22.04, Rocky Linux 9 |
| Scale | 16 VMs started in dependency order (tiers), and a batch of UEFI VMs |
| Proxmox versions | PVE 9.2 with PBS 4.x; PVE 9.2 with PBS 3.x; PVE 8.4 with PBS 3.x (with an ephemeral SDN zone) |
| Backups and networks | Encrypted backups, all-NIC and preserved network backends |
| Nodes and failure | Runs on four other cluster nodes, and a run killed midway and then finished by `recover` |

`certistack setup` ran end to end on new installs of PVE 9.2 with PBS 4.2 and PVE 8.4 with PBS 3.4. **Not tested:**
mini PCs and other small consumer hardware, the smallest single-node home setups, ARM, and the controller VM template
(Packer), which has not yet been built against a live PVE.

## How long a run takes

In the author's lab, 392 passing single-VM runs took 12 minutes at the median, 21 at the 90th percentile. A 12 GiB
Rocky 9 VM took 6 minutes 20 seconds on a small nested node. Most of it goes to:

- **Guest network preparation:** about 2 minutes per VM on bare metal, several on a nested node. `preserve` skips it.
- **The integrity scan:** every disk is read once, in full, from PBS: about 3 hours per TiB on the lab's older Xeon E5
  v2 nodes.

For a slow-starting service, raise that probe's `timeout_sec`.

<a id="known-limits"></a>

## Guests and limits

- **Hardware:** controller and node must be amd64. The node needs `/dev/kvm` (nested virtualization if it is a
  VM).
- **Storage:** any VM storage works (ZFS, LVM-thin, Ceph), because restores come from PBS.
- **Guest network:** a Linux guest gets a sandbox address, written to its overlay. Windows and unrecognized guests keep
  their own: `init` sets `network_recovery.mode: preserve` for them.
- **Not restored:** LXC containers. **Refused before boot:** a LUKS-encrypted root, or a network configuration that
  cannot be read offline.
- **One run per node:** a second `run` or `recover` on a busy node is refused. Different nodes may run at once if their
  plans use different sandbox VM IDs and network names.
- **No way out:** a plan's VMs share one VNet with no gateway. A service that needs a default route (k3s) does not
  start.
- **Network probes** run from the worker: they prove it reached the guest, not that the guest reaches anything. HTTPS
  certificates must verify.
- **Clocks:** a report more than 10 minutes from the run's time is refused
  ([Issue 6](troubleshooting.md#issue-6)).
- **PVE 8** has no SDN lock: do not run on two nodes of one PVE 8 cluster at once.
