# Plan reference

A plan is the YAML file that tells CertiStack which backups to restore, how to check each guest, and
how busy the node may be. This page explains every key, the probes, guest network recovery, and
complete example plans.

## A first plan

This is a plan like the one `certistack init` wrote in the [quickstart](quickstart.md), with its comments cut:

```yaml
version: "v1"
plan_id: "recovery-pve-node-01"
name: "Recovery check of 1 VM(s) on pve-node-01"
use_backup_config: true

compliance:
  frameworks: [NONE]
  retention_days: 90

admission_control:
  max_host_ram_percent: 85.0
  max_host_iowait_percent: 12.0
  defer_retry_interval_sec: 30
  max_defer_retries: 10

network:
  mode: "simple"
  zone_id: "csZone1"
  vnet_id: "csVnet1"
  ip_range: "192.0.2.0/24"
  probe_ip: "192.0.2.1"

storage:
  overlay_storage: "certistack-scratch"

tiers:
  - level: 1
    name: "Recovery check"
    vms:
      - vmid: 9100
        source_vmid: 100
        name: "cs-web-01"
        source_pbs:
          storage_id: "pbs"
          snapshot: "latest"
        probes:
          - type: "tcp"
            target_ip: "192.0.2.10"
            port: 22
            timeout_sec: 300
            description: "SSH answers on the sandbox address"
```

| Block | What it does | What you change |
| --- | --- | --- |
| `version`, `plan_id`, `name` | The format, and the plan's ID and title in reports | Nothing |
| `use_backup_config` | Each sandbox VM takes its disks and hardware from its backup | Nothing |
| `compliance` | The labels and retention the report records | Nothing; replace `NONE` to name a standard |
| `admission_control` | How busy the node may be before a run waits | Usually nothing |
| `network` | The isolated sandbox network; the guest gets `192.0.2.10` | Only if the node uses `192.0.2.0/24` |
| `storage` | Where the sandbox's disk writes go | Nothing |
| `tiers` | The VMs to restore, in boot order, with the probes that check each | The probe: check the service the VM is for |

`certistack validate my-first-plan.yaml` checks a plan without credentials; `certistack plan` then
shows what a run would do, and changes nothing.

### Editor completion and checks

An editor with a YAML language server (VS Code with the Red Hat YAML extension, Neovim, JetBrains
IDEs) can complete keys and mark mistakes as you type. On the controller, save the schema next to
the plan:

```bash
certistack schema > certistack-plan.schema.json
```

Then make this the plan's first line:

```yaml
# yaml-language-server: $schema=./certistack-plan.schema.json
```

The schema checks each value on its own, and matches the binary that printed it: print it again
after an upgrade. `validate` also checks rules that span keys (an address inside
`network.ip_range`, a MAC or `vmid` used twice) and how addresses, URLs and names are spelled, so
run it as well.

## The keys

- An unknown key is refused, and the error names the key you probably meant: `line 4: unknown key
  "grace" in tiers[]; did you mean "startup_grace_period_sec"?`.
- A plan is one YAML document of at most 10 MiB.
- An **alias** is an older spelling, still read. If a plan gives both spellings, they must agree.
- A **rejected** key parses but fails validation, so a setting that would do nothing is never
  ignored in silence.
- An `int` takes a whole number: `2555.9` is refused.
- A key whose text has a set form (`plan_id`, `zone_id`, `vnet_id`, `overlay_storage`, a VM's `name`,
  `mac` and `machine`, `interface_name`, `snapshot`, a drive's `slot` and `archive`) takes quoted
  text only: `name: 2026` is refused, `name: "2026"` is read.
- Text that is printed (`name`, `environment`, a tier's `name`, a probe's `description`,
  `expected_output` and `domain`, the PBS repository and namespaces) holds no control character,
  escape sequence or bidirectional control. A `description` and an `expected_output` may run over
  lines.
- Durations in seconds are at most `604800` (7 days).
- A plan is literal: `${VAR}` and shell syntax are not expanded. Credentials never go in a plan;
  they go in the environment file ([settings and files](configuration.md)).

### Top level

| Key | Type | Required / default | What it does |
| :--- | :--- | :--- | :--- |
| `version` | string | required | `v1`; `certistack/v1` is an alias |
| `plan_id` | string | required | 1 to 128 letters, digits, `_` and `-`; names the report folder |
| `name` | string | required | The plan's title in reports |
| `environment` | string | optional | A free-text label for the report |
| `use_backup_config` | bool | optional, default `false` | Take each VM's disks and hardware from its backup ([what it takes](#what-the-sandbox-vm-gets)) |
| `compliance` | map | required | [`compliance` keys](#compliance-keys) |
| `admission_control` | map | required | [`admission_control` keys](#admission_control-keys); `admission` is an alias |
| `network` | map | required | [`network` keys](#network) |
| `storage` | map | optional | [`storage` keys](#storage-keys) |
| `tiers` | list | required | At least one tier: [`tiers` keys](#tiers-keys) |

### `compliance` keys

| Key | Type | Required / default | What it does |
| :--- | :--- | :--- | :--- |
| `frameworks` | list of strings | required | Labels the report prints: `NONE` (alone), `DORA`, `DORA-Article-12`, `SOC2`, `SOC2-Type2-CC7.4`, `HIPAA`, `HIPAA-164.308-A7`, `ISO27001`, `ISO27001-A8.13`, `ISO27001-A.12.3`, `ISO27001-A12.3` or `CIS_V8`. A label is not a certification. It is a list, so write `[NONE]`, not `NONE`. `init` writes `[NONE]`. `CHANGE`, which an earlier `init` wrote, is refused |
| `retention_days` | int | required | `1` to `36500`: how long you keep each report (`2555` is seven years). `0` is refused |
| `rto_target_seconds` | float | optional | A recovery time objective above `0`; a slower run fails |
| `sign_key_path` | string | optional | The Enterprise Edition's signing key. The Community Edition accepts it, so one plan works in both, and ignores it |

The recovery time (`rto_seconds` in the report) runs from the start of a passing run to its last
passing probe, with admission, the integrity scan and the grace periods included. Teardown and the
last tier's [soak](#tier-soak-what-it-checks) are not part of it; an earlier tier's soak is, because
the next tier starts only after it. For a run that fails it runs to the end of the run, teardown
included. Set `rto_target_seconds` from a measured run
([how long a run takes](compatibility.md#how-long-a-run-takes)).

#### What a report records of its policy

A report records the plan's `rto_target_seconds`, its admission limits, the admission check it
passed and the plan's SHA-256 digests; `verify-report --expect-plan` checks them against the plan
([Reports](reports.md)).

### `admission_control` keys

A run starts only while the node is under both limits. Otherwise it waits
`defer_retry_interval_sec` and checks again, up to `max_defer_retries` times, then fails with
`max admission retries exceeded` before it creates anything.

| Key | Type | Required / default | What it does |
| :--- | :--- | :--- | :--- |
| `max_host_ram_percent` | float | required | Above `0`, at most `100`: the most memory in use, with the run's reservation (`init`: `85.0`) |
| `max_host_iowait_percent` | float | required | Above `0`, at most `100`: the most CPU I/O wait (`init`: `12.0`). `max_host_io_wait_percent` is an alias |
| `defer_retry_interval_sec` | int | required | `1` to `604800`: the wait between checks (`init`: `30`) |
| `max_defer_retries` | int | required | `1` to `10000`: how many times the run checks again before it gives up (`init`: `10`) |
| `max_concurrent_boots` | int | optional, default `0` | `0` (no limit) to `64`: how many sandbox VMs may boot at once |
| `boot_settle_sec` | int | optional, default `180` | `0` to `3600` (`0` means 180): how long a started VM counts as booting. Needs `max_concurrent_boots` |

- **Memory.** The run reserves every VM's memory plus 256 MiB each, since every tier stays up. A
  plan whose reservation alone is over the limit is refused at once (`never_admissible`).
- **I/O wait** is measured over half a second. When it cannot be measured, the run waits, as for a
  limit exceeded.
- **Concurrent boots.** When the overlay storage shares a disk with the cluster database (the run
  warns), VMs booting together can delay corosync and cost a cluster node its membership; on a
  standalone node they slow its other services. Set `max_concurrent_boots` to `1` or `2` to space
  the starts out:

```yaml
admission_control:
  max_concurrent_boots: 1
```

### `network` keys {#network}

The sandbox is an SDN zone and VNet with no gateway, no SNAT and no uplink, so a restored guest
reaches no other network. What it changes on the cluster is on
[What it changes on your node](what-it-changes.md).

| Key | Type | Required / default | What it does |
| :--- | :--- | :--- | :--- |
| `mode` | string | required | `simple` (one node) or `vxlan` (a zone across cluster nodes) |
| `lifecycle` | string | optional, default `ephemeral` | `ephemeral`: each run creates and removes the zone and VNet. `preprovisioned`: [your own sandbox](#use-a-pre-provisioned-sandbox) |
| `zone_id` | string | required | A letter, then 1 to 7 letters or digits (`csZone01`) |
| `vnet_id` | string | required | Same form; must differ from `zone_id` when `ephemeral` |
| `tag` | int | required for `vxlan` | The VNI, `1` to `16777215`, unused by other VNets. Refused for `simple` |
| `peers` | string | required for `vxlan` | Comma-separated peer IP addresses, none inside `ip_range`. Refused for `simple` |
| `ip_range` | string | required | The sandbox subnet as an IPv4 network address (`192.0.2.0/24`, not `192.0.2.5/24`). `subnet_cidr` is an alias. [Choose the range](#choose-the-sandbox-range) |
| `probe_ip` | string | required | The node's address in the sandbox: inside `ip_range`, not its network or broadcast address, and not an address the node already has |
| `gateway` | string | rejected | Must be empty |
| `ipam` | string | rejected | Not implemented |
| `mtu` | int | rejected | Not implemented |

A run that finds its zone or VNet ID already in use stops before it changes anything, so it never
takes over a network ([Issue 10](troubleshooting.md#issue-10-certistack-does-not-own-or-reuse-pre-existing-resources)).
It applies only its own SDN change, under PVE's SDN lock, and is refused when the cluster has SDN
changes nobody applied
([Issue 12](troubleshooting.md#issue-12-the-clusters-sdn-configuration-has-changes-that-have-not-been-applied)).
PVE 8 has no SDN lock; there the run checks for pending changes itself.

`probe_ip` sits on the VNet bridge only while the run lasts. Wire probes leave from it, bound to the
VNet, so no host service can answer them. A network reload removes it: the run checks every 2
seconds and puts it back, with a warning
([Issue 38](troubleshooting.md#issue-38-a-wire-probe-fails-with-bind-cannot-assign-requested-address)).

#### Choose the sandbox range

`ip_range` must be a network in which the node has no address and no route: while a run lasts the
node routes the whole range into the sandbox. `ip -4 route` on the node lists the networks it uses.
The examples use `192.0.2.0/24`, a range reserved for documentation that almost every node leaves
free. A guest that recovery adapts gets an address from the range, so any free range does. A guest
that keeps its own address needs its own subnet
([Windows and appliances](#windows-appliances-and-other-guests-it-cannot-adapt)).

`plan`, `check`, `doctor` and every run refuse, before anything is created, a range that:

- holds the PVE API (`PVE_URL`) or the PBS server (`PBS_REPOSITORY`);
- equals, contains or lies inside a network, address or gateway of the node;
- holds your SSH session's address, a DNS server of the node, or a `vxlan` peer;
- overlaps loopback, link-local, multicast or reserved space.

When the node's routes cannot be read, `plan` and `check` warn and a run stops. Each refusal and its
fix: [Issues 39 to 44](troubleshooting.md#issue-39-the-sandbox-range-contains-the-pve-api-or-the-pbs-server).
`validate` cannot see the node, so it only notes a range outside the three documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

#### Use a pre-provisioned sandbox

With `lifecycle: preprovisioned` you create the zone and VNet once, and runs use them without any
SDN change or network reload. On a cluster node, `plan` warns that an ephemeral sandbox reloads the
network on every node at the start and at the end of each run, and names this option. The VNet
must have no gateway, no SNAT and no uplink, and serve CertiStack alone: another guest on it could
answer a probe in place of the VM under test. `plan` and `run` refuse a VNet that another VM or
container has a network device on, now or by a pending change, and name it. A run checks again after
each tier's probes and after its soak, and fails the tier if one has been added. For a `simple` zone
it reads the guests of the run's node (each node's bridge is its own); for `vxlan`, those of every
node. Templates are not counted. PVE lists only the guests the token may see, so the token needs
`VM.Audit` on `/vms` with propagation, and each check also reads the ports of the VNet's bridge on the
run's node: a port other than the run's own VMs' (and a `vxlan` zone's tunnel) is refused, and so is
a node where the bridge does not exist. A VM tagged `certistack` on the VNet is another run's sandbox
VM, or one a crashed run left: two runs must not share a pre-provisioned VNet at once, and the
recovery on its node removes a leftover ([Issue 26](troubleshooting.md#issue-26-lost-contact-with-node)).
`certistack setup rbac --zone` limits the token to that zone ([commands](cli-reference.md#setup-rbac)).

Each run checks the sandbox with read-only requests, adds a firewall table that drops forwarding,
and keeps the zone and VNet at the end. PVE turns IPv4 forwarding on for every SDN bridge at each
network reload, and a run refuses a VNet that forwards. Keep it off on every node that may run a
test, for example with an `/etc/network/if-up.d/` hook that writes `0` to
`/proc/sys/net/ipv4/conf/<vnet>/forwarding`. (An ephemeral sandbox turns it off by itself.)

### `storage` keys

| Key | Type | Required / default | What it does |
| :--- | :--- | :--- | :--- |
| `overlay_storage` | string | required on stock Proxmox VE | The PVE storage for the sandbox's overlays: file-based (`dir`, `nfs`, `cifs`, `cephfs`, `btrfs` or `glusterfs`) with `images` content. `--overlay-storage` and `CERTISTACK_OVERLAY_STORAGE` override it |
| `max_copy_gib` | int | optional, default `0` | `0` (no cap) to `1048576`: the most [copy-before-boot](#copy-before-boot) writes in one run |
| `pbs_namespace` | string | optional | The PBS namespace of every VM's backups |
| `scratch_dir` | string | optional | A private work directory on the node, which also holds the overlays when no `overlay_storage` is set: a clean absolute path other than `/`. `validate` refuses a shared one such as `/tmp` |
| `pbs_repository` | string | optional, discouraged | Lets a VM leave out `source_pbs`. Use the environment file instead: a plan is kept as evidence. A VM without `source_vmid` then tests `vm/<vmid>/latest`, the backups of the sandbox ID itself, so always set `source_vmid` |
| `pbs_fingerprint` | string | optional, discouraged | The PBS certificate fingerprint; also better in the environment file |

The environment overrides the other keys too: `CERTISTACK_SCRATCH_DIR` overrides `scratch_dir`,
`PBS_NAMESPACE` overrides `pbs_namespace` (a VM's `source_pbs.namespace` must then match it), and
`PBS_REPOSITORY` and `PBS_FINGERPRINT` override `pbs_repository` and `pbs_fingerprint`
([which setting wins](configuration.md#precedence)).

A run stops before it changes anything when the overlay storage is inactive, lacks `images` content
or has less than 5 GiB free.

### `tiers` keys

Tiers boot in ascending `level`. A run starts every VM of a tier, waits `startup_grace_period_sec`,
then probes each VM that booted. The next tier starts only when every VM and probe of this tier
passed. Every tier stays up until the end, so put what others need (DNS, a directory, databases)
first.

| Key | Type | Required / default | What it does |
| :--- | :--- | :--- | :--- |
| `level` | int | required | `1` or more, unique in the plan. `tier` is an alias |
| `name` | string | optional, default `Tier <level>` | The tier's name in reports |
| `startup_grace_period_sec` | int | optional, default `0` | The wait between the start and the probes |
| `boot_timeout_sec` | int | optional, default `60` | `0` means 60. The PVE start task, then QEMU's `running` status, each get this long |
| `soak_time_sec` | int | optional, default `0` | Hold the tier this long after its probes pass, and check it again ([tier soak](#tier-soak-what-it-checks)) |
| `vms` | list | required | At least one VM: [`vms` keys](#vms-keys) |

#### Tier soak: what it checks

A soak shows that a service stays up, not only that it answered once. The run watches that QEMU
keeps each VM running and runs each VM's service probes (the wire probes and `qga`) again every 30
seconds and once more when the period is over.

- **The checks.** Every 30 seconds, counted from the end of the previous round of checks, and once
  more when the period is over, each probe runs under its own `timeout_sec` and `retries`. A soak
  of 30 seconds or less has one check, at its end.
- **What counts as down.** A probe keeps trying inside `timeout_sec` (with `retries: 0`, the
  default; `tcp`, `http` and `dns` over UDP do so whatever `retries` is), so an outage that ends
  inside that budget is not a failed check; one that outlasts it is. Size `timeout_sec` for the
  longest outage you accept. A service down only between two checks is not seen.
- **A failed check fails the VM** and the tier, at the first one. Its peers are checked to the end.
- **Is the VM running?** The run asks PVE every 10 seconds. A read that fails is not evidence that
  the VM runs: a refusal (HTTP 401 or 403) fails the VM at once, and other failures after two
  minutes without a good read. A wait in which not one read worked fails its VMs too, however short
  it was.

Only the last tier's soak is outside the RTO: an earlier tier's soak delays the tiers after it. Each
VM's record carries a `soak` summary ([Reports](reports.md)).

### `vms` keys

Each entry under `tiers[].vms[]` is one sandbox VM restored from one backup.

| Key | Type | Required / default | What it does |
| :--- | :--- | :--- | :--- |
| `vmid` | int | required | `100` to `999999999`: the temporary sandbox VM, unique in the plan, not the `source_vmid` of any VM of the plan, absent from the node. `target_vmid` is an alias |
| `source_vmid` | int | required for `snapshot: latest` | The VM whose backup is tested |
| `name` | string | required | The sandbox VM's name: a DNS name of at most 63 characters (letters, digits, `-` and `.`, starting and ending with a letter or digit), as PVE requires |
| `source_pbs` | map | required unless `source_vmid` is set | Which backup and disks: [`source_pbs` keys](#source_pbs-keys) |
| `probes` | list | required | At least one wire probe, or a `qga` probe with `require_qga: true` ([Probes](#probes)) |
| `network_recovery` | map | optional | [`network_recovery` keys](#network_recovery-keys) |
| `copy_before_boot` | string | optional, default `auto` | `auto`, `always` or `never` ([copy-before-boot](#copy-before-boot)) |
| `require_quiesced_backup` | bool | optional, default `false` | Fail unless the backup froze the file systems ([backup checks](#backup-consistency-and-signatures)) |
| `require_signed_backup` | bool | optional, default `false` | Stop the run unless your key verified the backup's signature ([backup checks](#backup-consistency-and-signatures)) |
| `mac` | string | optional | The NIC's MAC ([MAC rules](#nic-mac-addresses)) |
| `nic_model` | string | optional | `virtio`, `e1000`, `e1000e`, `igb`, `ne2k_pci`, `ne2k_isa`, `pcnet`, `rtl8139` or `vmxnet3` |
| `machine`, `ostype`, `bios`, `scsihw` | string | optional | Proxmox VE's values, which override the backup's; `validate` checks them. `ostype`: `other`, `wxp`, `w2k`, `w2k3`, `w2k8`, `wvista`, `win7`, `win8`, `win10`, `win11`, `l24`, `l26` or `solaris`. `bios`: `seabios` or `ovmf`. `scsihw`: `lsi`, `lsi53c810`, `virtio-scsi-pci`, `virtio-scsi-single`, `megasas` or `pvscsi`. `machine`: a type such as `q35`, `pc`, `pc-i440fx-9.2` or `pc-q35-9.2+pve1`, optionally followed by options such as `,viommu=virtio`. `validate` checks the type and the options `viommu`, `aw-bits`, `enable-s3` and `enable-s4`, and leaves any other option (a name of letters, digits and `-`) to Proxmox VE |
| `hardware_overrides` | map | optional | [`hardware_overrides` keys](#hardware_overrides-keys) |

#### Snapshot selection

For scheduled runs set `source_vmid` and `snapshot: "latest"`: before it creates anything, the run
picks the newest backup of that VM and records its exact path in the report. To test an older
backup again, give its full path (`vm/100/2026-09-27T03:00:07Z`). The snapshot must belong to
`source_vmid`.

#### Source disk layout

With `use_backup_config: true` the run restores every disk in the backup. Without it, list the disks
in `source_pbs.drives`, each in its source slot, leaving out Cloud-Init drives. To restore only some
disks, such as the boot disk of a VM with a large data disk, list only those (without
`use_backup_config`): the run warns, and the report lists the disks left out
(`omitted_source_disks`). A disk the backup does not hold is refused. With `use_backup_config`, a
`drives` list must name every disk of the backup, or the run stops before it creates anything.

#### What the sandbox VM gets

Every run reads the backup's VM configuration. With `use_backup_config` the VM takes its disks, CPU
cores and sockets, memory, ballooning, CPU weight, and `net0` MAC and model from it. A value the
plan sets wins. A configuration that is not text, or that does not list a disk the snapshot holds,
is refused before anything is created ([Issue 46](troubleshooting.md#issue-46-a-backup-is-refused-before-the-run-starts)).

- **Always from the backup, unless the plan sets them:** firmware, machine type, SCSI controller
  and guest OS type, since PVE's defaults may not boot the guest.
- **Machine version.** A backup from a newer Proxmox VE can pin a machine version the node's QEMU
  cannot run. The run refuses that VM; restore on a node as new, or set `machine:` to the
  unversioned type (`q35` or `pc`).
- **Also kept:** the boot order, the SMBIOS UUID, and CD-ROM drives (empty).
- **Not carried over:** the CPU model (the sandbox uses `host`), extra NICs (see
  [`attach_all_nics`](#more-than-one-nic)), bridges, VLAN tags, PVE tags, hooks, passthrough
  devices, QEMU arguments and disk serials. The guest agent is always on.

#### UEFI and TPM firmware state

The run restores a UEFI VM's `efidisk0` and `tpmstate0` with every plan, onto
`storage.overlay_storage`, so a UEFI VM needs overlay storage. `bios: seabios` for a UEFI backup is
refused, and so is a firmware disk excluded from the backup. The copies hold firmware secrets, such
as a BitLocker key sealed in the TPM. A backup job that selects all VMs and runs during a test
copies them into a new backup group: exclude the sandbox VM IDs (`--exclude`, or a pool-based
selection) or run outside the backup window.

#### Integrity scan

Before each VM starts, the run reads every byte of its disks. A disk passes only when the mapped
image is exactly the size the backup's manifest records and reads to its end.

#### Copy-before-boot

Booting straight from PBS can make a guest miss service start deadlines. `copy_before_boot` decides
whether the integrity scan also copies the tier's disks to the overlay storage, so the VM boots from
local copies:

- `auto` (default): copies when the disks would not stay cached until boot, if the overlay storage
  is on a disk apart from the cluster database and has room for them plus 5 GiB. Otherwise it warns
  and boots from PBS.
- `always`: copies, or fails the VM before boot.
- `never`: boots from PBS through the overlays.

`storage.max_copy_gib` caps the copies of one run: `auto` skips a VM that would pass it, and warns;
`always` fails that VM.

#### Backup consistency and signatures

The report records how consistent each backup was (`source_consistency`), from the backup's log:

- `quiesced`: the guest agent froze the file systems (VSS on Windows);
- `crash-consistent`: a running VM was backed up without a freeze that held;
- `powered-off`: the VM was not running;
- `unknown`: the log does not say.

`require_quiesced_backup: true` fails the VM unless its backup is `quiesced` or `powered-off`, so
`unknown` fails too. For an encrypted backup the log is read with `CERTISTACK_PBS_KEYFILE`.

`require_signed_backup: true` stops the whole run, before anything is created, unless the VM's
manifest is signed and the key in `CERTISTACK_PBS_KEYFILE` verified it; no other VM of the plan is
tested either. Without it, an unsigned backup restores and the report says so.

#### NIC MAC addresses

All sandbox NICs share one VNet, so each MAC must be one an interface can hold: not all zeros, not
the broadcast address, and not a multicast address (the lowest bit of the first octet is 0, so the
first octet is even). A backup whose MAC is unusable is reported as `is not a usable MAC address`.

No two NICs of the plan may share a MAC: the bridge would send frames for both guests to whichever
spoke last. Backups of cloned VMs often do share one, so the run checks after reading the backups
and names both NICs (`VM 9901 net0 and VM 9900 net0 both use 00:11:22:33:44:55`, or `VM 9900 net1
and VM 9900 net0`). Give one VM its own `mac` (not under `preserve`), or restore them in separate
runs.

Under `network_recovery.mode: preserve` the guest's network settings are not rewritten, so the VM
takes the backup's `net0` MAC and model when the plan sets none, whether or not `use_backup_config`
is set, and a `mac` or `nic_model` that differs from the backup's is refused.

### `hardware_overrides` keys

A missing key or `0` takes the backup's value (with `use_backup_config`), else the default. A backup whose configuration
holds a value outside these ranges is refused with `use_backup_config: true`, even if the plan sets the key; with `false`,
the run never reads it ([Issue 46](troubleshooting.md#issue-46-a-backup-is-refused-before-the-run-starts)).

| Key | Type | Required / default | What it does |
| :--- | :--- | :--- | :--- |
| `cores` | int | optional, default `2` | `1` to `256` |
| `sockets` | int | optional, default `1` | `1` to `16` |
| `memory_mb` | int | optional, default `2048` | `16` to `4194304` |
| `balloon_mb` | int | optional | `1` to `4194304`, at most the VM's memory. `validate` compares it with a `memory_mb` the plan sets. `plan` and `run` compare it with the memory the backup gives (the default `2048` when the plan does not use the backup's configuration, or the backup has none), and refuse before they create anything |
| `cpu_weight` | int | optional, default `50` | `1` to `262144` (PVE's `cpuunits`) |

### `source_pbs` keys

When `storage_id` is left out and the VM sets `source_vmid` (or the plan sets
`storage.pbs_repository`), the run fills in `storage_id: pbs`, `snapshot: vm/<source_vmid>/latest`
and, without `use_backup_config`, `drive-scsi0`. A `source_pbs` that sets `storage_id` gets none of
these: it must give `snapshot`, and without `use_backup_config` it must give `drives`.

| Key | Type | Required / default | What it does |
| :--- | :--- | :--- | :--- |
| `storage_id` | string | optional when `source_vmid` is set | `pbs`, the run's one PBS repository; the only value |
| `snapshot` | string | required when `storage_id` is set, else default `vm/<source_vmid>/latest` | `latest`, `vm/<vmid>/latest` or `vm/<vmid>/<RFC 3339 time>` |
| `drives` | list | required without `use_backup_config` when `storage_id` is set, else default `drive-scsi0` | Each entry: a `slot` (`scsi0`-`scsi30`, `virtio0`-`virtio15`, `sata0`-`sata5`, `ide0`-`ide3`) and the `archive` backed up from it |
| `drive` | string | alias | One archive, in the slot its name gives (`drive-virtio0` is `virtio0`), else `scsi0` |
| `namespace` | string | optional, default `storage.pbs_namespace` | The PBS namespace; one run reads one |

### `network_recovery` keys

How it works: [Guest network recovery](#guest-network-recovery).

| Key | Type | Required / default | What it does |
| :--- | :--- | :--- | :--- |
| `mode` | string | optional, default `auto` | `auto`, `preserve`, `ifcfg`, `networkmanager`, `netplan`, `systemd-networkd` or `ifupdown` |
| `sandbox_ip` | string | optional | `net0`'s address in `network.ip_range`, unique in the plan. Needed with `attach_all_nics` when probes target several addresses. Refused with `preserve` |
| `interface_name` | string | optional | [A legacy interface name](#interface_name): 1 to 15 letters, digits, `_`, `-` and `.`, not `lo` |
| `attach_all_nics` | bool | optional, default `false` | Also attach `net1` and up ([more than one NIC](#more-than-one-nic)) |
| `capture_diagnostics` | bool | optional, default `false` | Record guest network details when a wire probe fails ([diagnostics](#diagnostics)) |

```yaml
network_recovery:
  mode: auto
  sandbox_ip: "192.0.2.10"
  capture_diagnostics: true
```

## Probes

A probe checks a restored guest.

- **Wire probes** (`tcp`, `http`, `dns`, `ldap`, `mssql`, `smb`) run on the node and reach the
  guest over the sandbox network.
- **`qga`** runs a check inside the guest through the QEMU guest agent.
- **`qmp` and `screendump`** only record what QEMU saw.

Each probe must pass within its `timeout_sec`; a later pass does not count. A Windows guest agent
can take minutes to start, so size `timeout_sec` for the slowest start you accept, and set
`require_qga: true` on a `qga` probe that must wait for it.

### Choosing probes

The SSH probe `init` writes shows the guest came up, not that it does its job. Add a probe of what
each VM exists for:

| To prove that... | Use |
| --- | --- |
| A TCP service listens (SSH, PostgreSQL, Redis) | `tcp` |
| A web application or API answers | `http` |
| A DNS server serves its zone | `dns` with `domain` |
| An OpenLDAP or 389-ds directory serves data | `ldap` with `base_dn` |
| An Active Directory domain controller serves its domain | `ldap` with `naming_context`, and `dns` with `record_type: srv` |
| SQL Server answers | `mssql` |
| A file server answers | `smb` |
| A service runs inside the guest | `qga` with `systemctl is-active NAME` or `sc query NAME` |

### Which probes verify a VM

A VM is `verified` only when a wire probe, or a `qga` probe that was not skipped, ran and passed.
`qmp` and `screendump` never count. Validation refuses a VM with no probe that is sure to count:
add a wire probe, or set `require_qga: true` on a `qga` probe. A VM whose probes were all skipped
is `unverified` and fails its tier.

### Probe keys

| Key | Type | Required / default | What it does |
| :--- | :--- | :--- | :--- |
| `type` | string | required | `tcp`, `http`, `dns`, `ldap`, `mssql`, `smb`, `qga`, `qmp` or `screendump`. Aliases: `tcp_handshake`, `http_get`, `qga_ping`, `qmp_status` |
| `timeout_sec` | int | optional, default `10` | `1` to `604800` |
| `retries` | int | optional, default `0` | `0` to `10`. `0` keeps trying until the timeout. A positive value caps the attempts at `retries + 1` for `ldap`, `mssql`, `smb`, `dns` over TCP and `qga`; `tcp`, `http` and `dns` over UDP keep trying for the whole `timeout_sec` whatever it is |
| `description` | string | optional, default `<type> verification probe` | Shown in the report |
| `target_ip` | string | required for wire probes | The guest's address: inside `ip_range`, not `probe_ip`, used by one VM only |
| `port` | int | required for wire probes | `1` to `65535` |
| `url` | string | optional (`http`) | `http(s)://<address>[:port]/path`, instead of `target_ip`, `port`, `path` and `tls` |
| `path` | string | optional (`http`), default `/` | The request path, sent as written (a missing leading `/` is added) |
| `tls` | bool | optional (`http`) | Use HTTPS |
| `expected_status` | int | required for `http` | `200` to `599` |
| `server_name` | string | optional (`http`, `mssql`) | The DNS name the certificate must carry; on `http` also the SNI and `Host` header; on `mssql` it makes the probe use TDS 8.0 strict encryption only |
| `domain` | string | optional (`dns`) | The name to resolve: labels of 1 to 63 characters, at most 253 in all |
| `transport` | string | optional (`dns`), default `udp` | `udp` or `tcp` |
| `record_type` | string | optional (`dns`), default `a` | `a` (A or AAAA) or `srv` |
| `base_dn` | string | optional (`ldap`) | `auto`, or a DN to read |
| `naming_context` | string | optional (`ldap`) | A DN the directory must advertise; not with `base_dn` |
| `command` | string | required for `qga` | One of the [allowed commands](#qga) |
| `expected_output` | string | optional (`qga`) | Text the output must contain |
| `require_qga` | bool | optional (`qga`), default `false` | Fail, instead of skip, when the guest agent does not answer; with it the probe waits up to `timeout_sec` for the agent. Without it an agent that does not answer within about 5 seconds makes the probe `SKIPPED` at once |
| `tls_skip_verify`, `insecure_skip_verify` | bool | rejected | Certificates are always verified |

A key that a type does not read is refused on that type, so a `tcp` probe with `tls: true` cannot
look stronger than it is. A `dns` probe reads `path` as the domain when `domain` is left out.

| Probe type | Fields it reads besides `type`, `timeout_sec`, `retries` and `description` |
| :--- | :--- |
| `tcp` | `target_ip`, `port` |
| `http` | `target_ip`, `port`, `url`, `path`, `tls`, `server_name`, `expected_status` |
| `dns` | `target_ip`, `port`, `path`, `domain`, `transport`, `record_type` |
| `ldap` | `target_ip`, `port`, `base_dn`, `naming_context` |
| `mssql` | `target_ip`, `port`, `server_name` |
| `smb` | `target_ip`, `port` |
| `qga` | `command`, `expected_output`, `require_qga` |
| `qmp` | none |
| `screendump` | none |

Each wire-probe target belongs to one VM, in every `network_recovery.mode`. The controller checks
reports for it too: a report in which passing wire probes of two VM records name one address is
refused by the controller (no report is written) and rejected by `verify-report` as pass evidence
even without `--expect-plan`.

### `tcp`

Completes a TCP handshake: something listens, which is not proof that the service works.

```yaml
- type: "tcp"
  target_ip: "192.0.2.10"
  port: 5432
  timeout_sec: 15
  description: "PostgreSQL accepts connections"
```

### `http`

Sends a GET and checks the status code, again every second until it gets `expected_status` or
`timeout_sec` runs out. Redirects are not followed: an application that answers `/` with `302`
fails `expected_status: 200`, so expect the `302` or probe the page it leads to.

```yaml
- type: "http"
  target_ip: "192.0.2.10"
  port: 443
  path: "/healthz"
  tls: true
  server_name: "service.example.com"
  expected_status: 200
  timeout_sec: 20
  description: "Health endpoint answers 200 over verified HTTPS"
```

- **HTTPS always verifies** the certificate: it must chain to a CA the node trusts (install your own
  CA on the node) and name `server_name`, or the target IP when none is set.
- **TLS 1.2 or later.** A guest with only TLS 1.0 or 1.1 (an old IIS) fails; use `tcp` for it.
- **3 seconds per attempt** for the connection and the response headers, whatever `timeout_sec` is.
- **`url`** is a shorthand: `url: "http://192.0.2.10:8080/health?check=db"`.
- **`path`** may carry a query; a `#fragment` is refused.

### `dns`

Sends one query straight to `target_ip`, over UDP (re-sent every 2 seconds) or TCP; the node's own
resolver is never used.

```yaml
- type: "dns"
  target_ip: "192.0.2.10"
  port: 53
  domain: "healthy.example.com"
  transport: "tcp"
  timeout_sec: 10
  description: "DNS server resolves its zone"
```

- With `domain`, it passes only on an A or AAAA answer, so a DNS server that lost its zone fails.
- Without `domain`, any well-formed reply passes.
- `record_type: srv` checks SRV records. For a domain controller, `domain:
  "_ldap._tcp.dc._msdcs.example.com"` shows the server still serves the records clients use to
  find a DC.

### `ldap`

An anonymous LDAP v3 bind over cleartext TCP (port 389). There is no LDAPS or StartTLS, so a
directory that requires a protected channel fails.

- `base_dn` set to a DN: the search must return that entry.
- `base_dn: auto`: one of the directory's advertised naming contexts must be readable.
- `base_dn` left out: the bind succeeds, or is refused by policy, which still shows a server
  answered.
- `naming_context`: the directory must advertise that context. No search is sent.

```yaml
- type: "ldap"
  target_ip: "192.0.2.10"
  port: 389
  base_dn: "auto"
  timeout_sec: 15
  description: "A restored naming context is readable"
```

Active Directory refuses anonymous searches, so use `naming_context` for a domain controller. A DC
whose database did not open fails, though port 389 answers.

```yaml
- type: "ldap"
  target_ip: "192.0.2.10"
  port: 389
  naming_context: "DC=example,DC=com"
  timeout_sec: 60
  description: "The domain controller serves example.com"
```

DNs follow RFC 4514 (at most 1024 bytes) and are compared ignoring case.

### `mssql`

Sends a TDS `PRELOGIN`, the first message of every SQL Server connection. No login, no
credentials. A named instance needs a static port: the probe does not ask SQL Browser.

```yaml
- type: "mssql"
  target_ip: "192.0.2.10"
  port: 1433
  timeout_sec: 120
  description: "SQL Server answers TDS"
```

An instance set to Force Strict Encryption (TDS 8.0) is detected, and its certificate is **not
verified**. With `server_name` the probe uses only TDS 8.0 strict encryption and verifies the
certificate for that name against the node's trust store, so a server that does not force strict
encryption fails it: leave `server_name` out for such a server. Pair the probe with a `qga` check
such as `sc query MSSQLSERVER`: an answer is not a working login.

### `smb`

Sends an SMB2 `NEGOTIATE` (SMB 2.0.2 to 3.1.1). No share is opened, so pair it with a check that
reads the data.

```yaml
- type: "smb"
  target_ip: "192.0.2.10"
  port: 445
  timeout_sec: 60
  description: "The file server answers SMB"
```

### `qga`

Runs a check inside the guest through the QEMU guest agent. Only these commands are allowed:
`hostname`, `guest-get-host-name`, `ping`, `guest-ping`, `systemctl is-active <service>` and
`sc query <service>` (Windows).

```yaml
- type: "qga"
  command: "systemctl is-active postgresql@16-main"
  expected_output: "active"
  require_qga: true
  timeout_sec: 30
  description: "The PostgreSQL cluster unit is active"
```

- A command passes when it exits with 0 and its output contains `expected_output`, when set.
- `hostname` matches **case-sensitively**: Windows reports `WEB01`.
- `ping` only checks that the agent answers; `expected_output` is refused there.
- `sc query` passes only when the service is `4 RUNNING`. The Windows agent allows this by default
  (`guest-exec`).
- Name the unit that runs the service. On Debian and Ubuntu, `postgresql` is active with no
  database running; the cluster's unit is `postgresql@16-main` (`pg_lsclusters` lists it). On the
  RHEL family it is `postgresql`.
- Without `require_qga: true`, a probe whose agent does not answer within about 5 seconds is
  `SKIPPED` at once, whatever its `timeout_sec`, and a skip is never evidence. Set
  `require_qga: true` for an agent that is slow to start (Windows).

### `qmp` and `screendump`

`qmp` passes when QEMU reports the VM `running`, as a guest stuck at a kernel panic also is.
`screendump` passes when a screenshot could be taken. Neither verifies a VM. When any probe fails,
the run captures a screenshot anyway.

### What a probe result records

Each result records its `timeout_sec`, `retries`, `require_qga` and `server_name`, its attempts, and
where it ran from ([Reports](reports.md)).

## Guest network recovery

A restored Linux guest keeps its production network settings, which often name an interface the
sandbox VM does not have. So before a VM with wire probes boots, CertiStack writes one temporary
network profile into the VM's copy-on-write overlay. It gives the guest the address its probes
target: no gateway, no DNS, no uplink. The source VM and the backup are never changed. Most plans
need no `network_recovery` key.

### What it needs

- **`guestfish`** (package `libguestfs-tools`) on the node; setup installs it. `preserve` does not
  need it.
- **Every disk the guest needs.** Recovery fails before boot when the plan leaves out a disk the
  root file system needs, or when a data disk holds a second operating system.
- **No encrypted disks.** In `auto`, a LUKS or BitLocker volume fails the run before boot. Use
  `mode: preserve` (the guest must unlock without a prompt), only `qga` probes, or leave the
  encrypted data disk out.

### Which backend is used

`auto` detects legacy `ifcfg` (RHEL, Rocky), NetworkManager, Netplan, systemd-networkd or ifupdown
(Debian, and OpenRC guests such as Alpine), and binds the profile to the NIC's MAC. It follows the
service in charge of the network, not the folders the image keeps:

| Guest state | Result |
| --- | --- |
| `NetworkManager.service` masked | It owns nothing. If every service that could read a profile is masked, recovery fails |
| A Netplan definition rendered by networkd matches the NIC | Netplan owns the NIC |
| NetworkManager disabled | An enabled networkd or ifupdown owns it |
| NetworkManager and networkd both enabled, and networkd files match the NIC | Set `mode` yourself |
| `mode` set in the plan | Used, unless the service that would read it is masked |

CertiStack decides from the guest's files without booting it. A tool that rewrites the network at
boot, such as cloud-init on a changed instance, is not modeled.

### What each backend gets

- **ifcfg and NetworkManager.** When a guest keeps an `ifcfg` profile bound to the NIC's MAC
  (`HWADDR`), recovery rewrites that profile in place. When more than one profile is bound to the
  MAC, recovery asks for `interface_name` instead of rewriting whichever the directory lists first.
  Files ending in `.bak`, `~`, `.orig`, `.rej`, `.rpmnew`, `.rpmorig`, `.rpmsave`, `.augnew`,
  `.augsave` or `.augtmp` are ignored, as NetworkManager ignores them.
- **NetworkManager's configuration** is read in its own order: `/usr/lib/NetworkManager/conf.d`,
  `/run/NetworkManager/conf.d`, `/etc/NetworkManager/NetworkManager.conf`,
  `/etc/NetworkManager/conf.d`, `/var/lib/NetworkManager/NetworkManager-intern.conf`. Profiles go
  to `/etc/NetworkManager/system-connections` by default. A configuration it cannot evaluate
  offline is refused before anything is written, naming the file.
- **ifupdown.** Recovery replaces `/etc/network/interfaces` with a static stanza and keeps the
  original as `interfaces.certistack-original`. A stanza built on the recovered NIC (a bridge, bond
  or VLAN over it, `bridge_ports all`), a `mapping`, `rename` or `template` stanza, and an option
  line outside any stanza are refused before anything is written. With `attach_all_nics`, the
  replacement file keeps the guest's own stanzas for the other interfaces.
- **Netplan and systemd-networkd.** Recovery names its files to sort before every guest file that
  can match the NIC, and never changes the guest's files. `.link` files are read from
  `/etc/systemd/network`, `/run/systemd/network`, `/usr/local/lib/systemd/network`,
  `/usr/lib/systemd/network` and `/lib/systemd/network`; a file hides one of the same name in a
  later directory, and a link to `/dev/null` hides it altogether. Rules inside the guest's
  initramfs are not visible offline and are not modeled.

Recovery writes over a regular file in place, which keeps its SELinux label, or creates a missing
one; it refuses a path that is a link, directory or special file, naming it. If the guest runs firewalld, recovery opens the probe
ports to `probe_ip` only, and fails before boot, naming the zone, when a rule would drop the probe.
For a guest it cannot repair, `mode: preserve` is the way out.

### Windows, appliances and other guests it cannot adapt

Recovery rewrites only Linux network settings. A Windows guest, or any guest whose network it does
not recognize, fails in the default mode with `unsupported guest network layout`. For such a guest:

- set `network_recovery.mode: preserve`, so it keeps its own address on the sandbox VNet;
- make `network.ip_range` the subnet the guest already uses, and each `target_ip` its own address;
- leave out `sandbox_ip`.

The node that runs the test must have no address and no route in that subnet. Run on a cluster node
with no leg in it, or re-address the guest
([Issue 40](troubleshooting.md#issue-40-the-sandbox-range-overlaps-a-network-an-address-or-a-gateway-of-the-node)).

Appliances fail the same way: pfSense, OPNsense, MikroTik RouterOS and VyOS (`no operating system
was found on this disk` or `unsupported guest network layout`), and Home Assistant OS, whose root is
read-only. Set `preserve`, and probe the appliance with `qga` or at the address it already holds.

### `interface_name`

Only for a legacy profile tied to an interface name, such as `ifcfg-eth0`: recovery adds a
MAC-bound `.link` file so the guest sees that name. It never renames a source interface.

### More than one NIC

Only `net0` is attached by default. `attach_all_nics: true` also attaches `net1` and up, with their
MACs and models, to the sandbox VNet only. Use it when a service binds to a second interface's
address. Only `net0` gets a recovery address; the others keep the guest's settings, and their
in-range addresses must be unique in the sandbox (check them yourself). To probe a service on
another NIC, set `sandbox_ip` to `net0`'s address and point the probe at the other one.

### Diagnostics

With `capture_diagnostics: true`, a failed wire probe makes the run record the guest's interfaces,
routes, listening sockets, failed services and the enabled services that are not running in the
report, through the guest agent when it answers. Each service that is not running is listed with its
state, its result and its condition result, and a service whose start condition was not met
(`condition=no`) comes first. Otherwise a script in the overlay captures them at boot, on network
changes and once boot has settled, and the newest eight stay in the overlay. The settled capture
waits until the guest has finished starting, for at most 120 seconds, and says so when it gave up.
The report keeps the newest capture. `report show` prints it whole, after the VM's probes.

The overlay is read during teardown, after the sandbox VM is confirmed stopped and before PVE
destroys it. When the VM cannot be confirmed stopped the overlay is not read, and the diagnostic in
the report says it was not read and why. An overlay that is already gone, or that cannot be read,
is said in the diagnostic and is not a cleanup failure. A capture is cut at 32 KiB, at most 16 KiB
is read back, and a cut capture ends with `[truncated]`.

## Examples

Each plan below is a file in
[`examples/`](https://github.com/cliftcloud/certistack/tree/main/examples) that the test suite
validates, using `192.0.2.0/24` ([check it is free](#choose-the-sandbox-range)). To start from one,
copy it on the controller, in a clone of the repository:

```bash
cp examples/three-tier-app.yaml my-app.yaml
```

Change each value marked `CHANGE`, and each `source_vmid`, `target_ip`, `port`, `path`,
`server_name` and unit name, to yours. Then run `certistack validate`, `certistack plan` and
`certistack run` on it.

### One VM, and an HTTP probe for it

`minimal-single-vm.yaml` is a plan like the first one on this page, with a framework label filled in
(change it), ready to copy:

```yaml
--8<-- "examples/minimal-single-vm.yaml"
```

To check a web application instead of SSH, replace its `probes` with these:

```yaml
- type: "http"
  target_ip: "192.0.2.10"
  port: 8080
  path: "/healthz"
  expected_status: 200
  timeout_sec: 120
  description: "Application health endpoint returns 200"
- type: "qga"
  command: "systemctl is-active nginx"
  require_qga: true
  timeout_sec: 60
  description: "nginx is active inside the guest"
```

### Several VMs in tiers

A database, an application server and a web front end. Tier 2 starts after every probe of tier 1
passed, and tier 3 after tier 2. Each guest gets the address its probes target.

```yaml
--8<-- "examples/three-tier-app.yaml"
```

### A Windows guest

A domain controller first, then a SQL Server and a file server together.

```yaml
--8<-- "examples/windows-domain.yaml"
```

It differs from a Linux plan in three ways:

- `network_recovery.mode: preserve` on every VM, and `ip_range` set to the guests' own subnet
  ([why](#windows-appliances-and-other-guests-it-cannot-adapt)).
- Each guest keeps its backup's `net0` MAC, so two backups with one MAC are refused
  ([MAC rules](#nic-mac-addresses)).
- Long timeouts, because a cold Windows boot from a backup is slow. Read
  [Issue 19](troubleshooting.md#issue-19-a-windows-guests-agent-or-services-never-start-in-the-sandbox)
  before you shorten them.

### An encrypted backup

The plan does not change. The environment file needs the key in `CERTISTACK_PBS_KEYFILE` (setup
offers to copy it), and `PBS_ENCRYPTION_PASSWORD` when the key has a passphrase
([settings and files](configuration.md)). To refuse a backup the key does not verify, or one taken
without a file system freeze, add the two checks to the VM:

```yaml
tiers:
  - level: 1
    name: "Recovery check"
    vms:
      - vmid: 9100
        source_vmid: 100
        name: "cs-web-01"
        require_signed_backup: true
        require_quiesced_backup: true
        source_pbs:
          storage_id: "pbs"
          snapshot: "latest"
        probes:
          - type: "tcp"
            target_ip: "192.0.2.10"
            port: 22
            timeout_sec: 300
            description: "SSH answers on the sandbox address"
```
