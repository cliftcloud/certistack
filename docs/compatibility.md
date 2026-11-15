# Tested and supported

What CertiStack was tested on, which versions it supports, how long a run takes, and its limits. Read it before you pick
a node and a VM.

## What was tested {#what-was-tested}

Everything below ran on the author's own infrastructure: two sites, with a 14-node Proxmox VE 9.2 cluster as the test
bed and standalone hosts. The test nodes keep about 20 other VMs running during every run.

**The final v0.1.0 code: 24 restore tests, all passed.** Each ended with its cleanup verified and its node left as it
found it.

| Area | What ran |
| --- | --- |
| Windows | Active Directory forests (two runs), Windows Server 2022, SQL Server, SMB |
| Linux | Ubuntu 22.04, Rocky Linux 9 |
| Scale | 16 VMs started in dependency order (tiers), and a batch of UEFI VMs |
| Proxmox versions | PVE 9.2 with PBS 4.x; PBS 3.x; PVE 8.4, including an ephemeral SDN zone |
| Backups and networks | Encrypted backups, all-NIC and preserved network backends |
| Nodes and failure | Runs on four more cluster nodes, and a run killed midway and then finished by `recover` |

**An earlier build: 617 of 622 planned restore-test cases passed**, including a 96-VM fleet restored in one run (about
17 hours) and a PBS outage in the middle of a run. The engine changed after that campaign and every later build was
re-tested; the 24 tests above ran on the final code.

**`certistack setup`** ran end to end on freshly installed Proxmox VE 9.2 with PBS 4.2, and Proxmox VE 8.4 with PBS 3.4:
from nothing to a passing restore test, then removed again with [Remove CertiStack](undo.md).

**Not tested:** mini PCs and other small consumer hardware, the smallest single-node home setups, and ARM (releases are
amd64 only). LXC containers are not restored at all.

## What a guest gets {#guest-coverage}

Only QEMU VM backups (`vm/<id>`) are restored, each disk mapped read-only under a copy-on-write overlay, on any bus
(SCSI, VirtIO, SATA, IDE).

| Your guest | What happens | Tested on the final code |
| --- | --- | --- |
| Linux (`ifcfg`, NetworkManager, Netplan, systemd-networkd, ifupdown) | Its network is set to the sandbox address on the overlay, with all its restored disks opened together; probe it with tcp, http, dns, ldap and the guest agent. Initramfs rules and NetworkManager command-line overrides are not modelled | Ubuntu 22.04, Rocky Linux 9 |
| Windows, or a guest CertiStack does not recognise | Keeps its own network (`preserve`); probe it over the wire or with the guest agent. With wire probes and the default mode, the plan is refused with `unsupported guest network layout` | Windows Server 2022, Active Directory, SQL Server, SMB |
| UEFI, TPM | `efidisk0` and `tpmstate0` restored as disposable raw copies (needs `overlay_storage`) | A UEFI fleet |
| Encrypted PBS backup | Restored with the key on the controller (`CERTISTACK_PBS_KEYFILE`) | Yes |
| Several NICs | `attach_all_nics` on one flat VNet | All-NIC backend |
| VM settings | CPU, memory, firmware, machine type, SCSI controller, MAC and NIC model come from the backup, and the boot order limited to the restored disks. Tags, bridge, VLAN, firewall, hooks, startup rules, extra QEMU arguments and passthrough are never replayed | - |
| Disks the plan leaves out; Cloud-Init and other media not in the backup | Listed as omitted in the report; not recovered | - |
| LXC container | Not listed and not restored | - |
| Refused before boot, with the reason | A LUKS-encrypted root; a network configuration that cannot be evaluated offline; an OS that needs a disk the plan leaves out; several operating systems in one plan's disks | - |
| Not supported | Routed multi-VLAN topologies, DHCP fallback, production networks | - |

## Supported versions

CertiStack reads the Proxmox VE, PBS server and `proxmox-backup-client` versions and checks the pair: `doctor` as its
`version_support` check, `plan` first, `run` before it reads a backup. The report records `version_support`.

| Status | Meaning | What CertiStack does |
| --- | --- | --- |
| `tested` | A run passed on this pair | Nothing: the check passes |
| `untested` | In range, but not covered by the evidence | Warns; `run` goes on |
| `unknown` | A version could not be read (no PVE API answer, no `proxmox-backup-client`, PBS unreachable) | Warns, as for `untested` |
| `unsupported` | Older than this release supports | `doctor` fails; `plan` and `run` refuse before creating anything |

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

`8.x` means a PVE 8 release other than 8.4. Any other pair, such as a newer major release, is `untested`. The table is the
code's (`internal/support`).

- A `proxmox-backup-client` of another major than the evidence used is `untested`. Each PVE release was tested with the
  client it ships (3.x on 8.4, 4.x on 9) against PBS 3 and PBS 4.
- To see all three versions, run `doctor` on the node with a run's `--env-file`: the PBS server is read only through
  the client.
- The controller and the node must be amd64. An arm64 build from source runs only the offline commands (`validate`,
  `verify-report`, `report show`, `schema`).

## How long a run takes {#how-long-a-run-takes}

In the author's lab the median single-VM run took 12 minutes, 90 % finished within 21 minutes, and a 12 GiB Rocky 9 VM
took 6 minutes 20 seconds on a small nested node. Guest network preparation and the integrity scan take most of it.

| Step | What it depends on | Lab measurement |
| --- | --- | --- |
| Admission, sandbox network, mapping, overlay | Mostly the node's SDN reload | Under 10 seconds |
| **Guest network preparation** | libguestfs rewrites the guest's network on the overlay; slower on a node that is itself a VM. `network_recovery.mode: preserve` skips it | 116 s median (90 % under 185 s) on bare metal; 4 m 10 s (Rocky 9) and 2 m 46 s (Debian 12) on a small nested node |
| **Image integrity scan** | Every disk is read once, in full, from PBS and hashed | 385 s median (90 % under 669 s); 84 s for 12 GiB on the small nested node |
| Boot and registration | The hypervisor | About 5 seconds |
| **Probes** | How long the service takes to start. A plan without `startup_grace_period_sec` (as `init` writes it) stops at the first success | SSH answered 34 s after boot (Rocky 9) and 20 s (Debian 12); Java stacks (OpenSearch, Graylog) took several minutes |
| Teardown | The number of VMs | About 10 seconds |

The whole run, as the report's recovery time (`rto_seconds`):

| Measurement | RTO |
| --- | --- |
| One 12 GiB Rocky 9 VM, SSH probe, small nested single-node PVE | 6 m 20 s |
| That VM and a 6 GiB Debian 12 VM in one plan | 9 m 04 s |
| 392 passing single-VM runs in the lab (mixed Linux and Windows images of different sizes), median | 12 m 06 s |
| The same 392 runs, 90th percentile / largest | 21 m / 56 m |

All rows but the first two ran on bare metal. The lab's plans set a start grace (110 s or 180 s) that an `init` plan
does not, so an `init` plan finishes a little faster. The time ends at the last passing probe; it does not include
copying a VM back to production storage.

To estimate your own:

- **Scan:** total disk size divided by your node's PBS read speed. The lab's older Xeon E5 v2 nodes hash at roughly
  100 MB/s, about 3 hours per TiB. A plan can restore only some disks ([The plan file](plan-reference.md)).
- **Preparation:** about two minutes per VM on bare metal, several on a nested node. VMs are prepared one at a time.
- **Everything else:** usually under a minute, apart from a slow service.

`report show` lists both steps under "Where the time went". During a run, `Still working: ...` repeats every half minute
and `full mapped-image integrity scan: N GiB verified.` counts up. The first Ctrl-C stops the run and
waits for cleanup; a second abandons it.

For a slow-starting service, raise that probe's `timeout_sec`, not the start grace. A busy node makes the run wait while
it is over the plan's RAM or I/O wait limits. Skipping the scan is a test-only mode that `verify-report` refuses.

## Known limits

| Limit | What it means for you |
| --- | --- |
| **One operation per node** | A second `run` or `recover` on a busy node is refused ([scheduled runs](automation.md#rules-for-scheduled-runs)) |
| **A node needs `/dev/kvm`** | Without it the `kvm` preflight fails and nothing is created. A node that is itself a VM needs nested virtualization |
| **One flat sandbox network per plan** | All of a plan's VMs share one PVE `simple` or `vxlan` VNet with no gateway, SNAT or uplink, and reach each other as far as their firewalls allow. Measured from inside a restored guest: it reached nothing outside the sandbox (not the node, its gateway, the PBS or the internet), even with a default route added by hand through the node's probe address |
| **No gateway in the sandbox** | A service that needs a default route does not start. k3s exits with "no default routes found" and restarts every few seconds, so a probe of its API fails. Services that only listen are not affected |
| **Services can start slowly** | Grafana took several minutes to listen: give such a service's probe a longer `timeout_sec` |
| **Probes start on the worker** | A wire probe proves the worker reached the guest, not that the guest reaches anything; use a guest-agent probe for that. HTTPS certificates must verify; there is no bypass |
| **Clock within 10 minutes** | A report whose timestamp is more than 10 minutes from the run is refused. `plan` and `run` warn from 5 minutes, and refuse up front only a node more than about 40 minutes ahead. A node behind is not refused, but a run shorter than its lag less 10 minutes ends with its report refused ([Issue 33](troubleshooting.md#issue-33-the-clock-of-node-is-about-ahead-of-the-controllers-or-behind)) |
| **A pre-provisioned VNet holds only the run's VMs** | `plan` and `run` refuse one that another VM or container is on, in PVE's guest list or on the VNet's bridge on the run's node, and a run fails a tier if one is added before its probes and soak end ([pre-provisioned sandbox](plan-reference.md#use-a-pre-provisioned-sandbox)) |
| **PVE 8 has no SDN lock** | Do not run on two nodes of one PVE 8 cluster at once, and keep other SDN changes off it during a run. Before each SDN write and apply, CertiStack reads the pending zones, VNets, controllers and subnets: all that an apply carries on PVE 8 (IPAM and DNS settings take effect without one). If an unapplied change is possible, use `network.lifecycle: preprovisioned`, which changes no SDN object |
| **A held loop device fails the cleanup** | The node assembles a guest's software RAID and LVM on the mapped disk; CertiStack stops only those it can prove are the run's. A loop that such a device, a process or a mount still holds is never called released: the cleanup fails and names it (before Linux 5.15, so does any loop attached to `/`) ([Issue 5](troubleshooting.md#issue-5-map-pbs-backup-image-client-output-withheld-n-bytes-and-no-free-loop-device)) |
| **A large multi-VM tier needs room** | When a tier's disks exceed the page cache, `copy_before_boot: auto` copies them all to local storage. If it cannot (overlay storage on the cluster database's disk, too little room, `storage.max_copy_gib`), the run warns and a VM can time out late. Give overlay storage its own disk, or split the tier ([Issue 19](troubleshooting.md#issue-19-a-windows-guests-agent-or-services-never-start-in-the-sandbox)) |
| **`mssql` proves the engine answers** | Not that a login works. On a TDS 8.0 strict server it does not verify the certificate (detail: "certificate not verified") unless the probe sets `server_name` |

What CertiStack changes on your node: [What it changes](what-it-changes.md).
