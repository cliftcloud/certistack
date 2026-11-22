# Plans

A plan is the YAML file that names the backups to restore, the probes that check each guest, and the node's limits.

## A first plan

[`certistack init`](quickstart.md#3-write-your-first-plan) writes a plan like this one. Change `source_vmid`,
`frameworks` and the probe (check the VM's service); change `network` only if the node uses `192.0.2.0/24`.

```yaml
--8<-- "examples/minimal-single-vm.yaml"
```

`certistack validate` checks a plan without credentials; `certistack plan` shows what a run would do.

### Editor completion and checks

Save the schema and name it on the plan's first line, for editors with a YAML language server. Print it again after
an upgrade.

```bash
certistack schema > certistack-plan.schema.json
```

```yaml
# yaml-language-server: $schema=./certistack-plan.schema.json
```

## The keys

- An unknown key is refused, naming the key you probably meant. A **rejected** key fails validation.
- A plan is read literally: `${VAR}` is not expanded.
- Durations are whole seconds, at most `604800` (7 days). IDs and names take quoted text: `name: "2026"`.
- Credentials never go in a plan; they go in the [environment file](configuration.md#variables).

### Top level

| Key | What it does |
| --- | --- |
| `version` | Required. `v1`; `certistack/v1` is an alias |
| `plan_id` | Required. 1 to 128 letters, digits, `_` and `-`; names the report folder |
| `name` | Required. The plan's title in reports |
| `environment` | A free-text label for the report |
| `use_backup_config` | Default `false`. Take disks and hardware from the [backup](#what-the-sandbox-vm-gets) |
| `compliance` | Required |
| `admission_control` | Required. `admission` is an alias |
| `network` | Required |
| `storage` | Optional |
| `tiers` | Required. At least one tier |

### `compliance`

| Key | What it does |
| --- | --- |
| `frameworks` | Required. Report labels, not certifications: `NONE` (alone), `DORA`, `DORA-Article-12`, `SOC2`, `SOC2-Type2-CC7.4`, `HIPAA`, `HIPAA-164.308-A7`, `ISO27001`, `ISO27001-A8.13`, `ISO27001-A.12.3`, `ISO27001-A12.3` or `CIS_V8`. Write `[NONE]`, not `NONE` |
| `retention_days` | Required. `1` to `36500` days. Recorded only; nothing is deleted |
| `rto_target_seconds` | Above `0`: the most seconds from the start of a run to its last passing probe. Set it from a [measured run](compatibility.md#how-long-a-run-takes) |
| `sign_key_path` | The Enterprise Edition's signing key; Community ignores it |

<a id="admission-control"></a>

### `admission_control`

A run over either limit waits `defer_retry_interval_sec` and checks again, up to `max_defer_retries` times (`init`
writes 30 and 10: 5 minutes), then fails before it creates anything. A plan whose VMs need more than
`max_host_ram_percent` of the node's whole memory can never be admitted: `plan` and `run` refuse it at once
([Issue 3](troubleshooting.md#issue-3)).

| Key | What it does |
| --- | --- |
| `max_host_ram_percent` | Required. Above `0`, at most `100`: the most memory in use, counting the run's reservation |
| `max_host_iowait_percent` | Required. Above `0`, at most `100`: the most CPU I/O wait. `max_host_io_wait_percent` is an alias |
| `defer_retry_interval_sec` | Required. `1` to `604800` |
| `max_defer_retries` | Required. `1` to `10000` |
| `max_concurrent_boots` | Default `0` (no limit), up to `64`: VMs booting at once. Use `1` or `2` when the overlay storage shares the cluster database's disk |
| `boot_settle_sec` | Default `180`, up to `3600`: how long a started VM counts as booting. Needs `max_concurrent_boots` |

The run reserves each VM's memory plus 256 MiB.

### `network`

| Key | What it does |
| --- | --- |
| `mode` | Required. `simple` (one node) or `vxlan` (a zone across cluster nodes) |
| `lifecycle` | Default `ephemeral`: each run creates and removes the zone and VNet. `preprovisioned`: [your own sandbox](#use-a-pre-provisioned-sandbox) |
| `zone_id` | Required. A letter, then 1 to 7 letters or digits (`csZone01`) |
| `vnet_id` | Required. Same form; differs from `zone_id` when `ephemeral` |
| `tag` | `vxlan` only, required: the VNI, `1` to `16777215`, unused by other VNets |
| `peers` | `vxlan` only, required: comma-separated peer IP addresses, none inside `ip_range` |
| `ip_range` | Required. The sandbox subnet as an IPv4 network address (`192.0.2.0/24`). `subnet_cidr` is an alias |
| `probe_ip` | Required. The node's address in the sandbox: a free host address in `ip_range` |
| `gateway` | Rejected: must be empty |
| `ipam` | Rejected |
| `mtu` | Rejected |

#### Choose the sandbox range

`ip_range` must be a network where the node has no address and no route: during a run the node routes the whole range
into the sandbox. `ip -4 route` on the node lists its networks. `plan`, `check`, `doctor` and `run` refuse a range that
holds the PVE API, the PBS server, a node network, gateway or DNS server, your SSH client or a `vxlan` peer
([Issues 8 to 13](troubleshooting.md#issue-8)).

#### Use a pre-provisioned sandbox

With `lifecycle: preprovisioned` you create the zone and VNet once; runs then make no SDN change and, on a cluster,
no network reload on every node.

- The VNet has no gateway, no SNAT and no uplink, and serves CertiStack alone: a run refuses it while another guest
  has a network device on it. Two runs never share it at once.
- The token needs `VM.Audit` on `/vms` with propagation; [`setup rbac --zone`](configuration.md#setup-rbac) limits it
  to the zone.
- PVE turns IPv4 forwarding on at each network reload, and a run refuses a VNet that forwards. Keep it off on every
  node that may run a test, for example with an `/etc/network/if-up.d/` hook that writes `0` to
  `/proc/sys/net/ipv4/conf/<vnet>/forwarding`.

### `storage`

| Key | What it does |
| --- | --- |
| `overlay_storage` | Required on stock Proxmox VE. A file-based PVE storage (`dir`, `nfs`, `cifs`, `cephfs`, `btrfs` or `glusterfs`) for the overlays, active, with `images` content and 5 GiB free |
| `max_copy_gib` | Default `0` (no cap): the most `copy_before_boot` writes in one run |
| `pbs_namespace` | The PBS namespace of every VM's backups |
| `scratch_dir` | A private node directory for work files, and for the overlays when no `overlay_storage` is set. Not `/` or `/tmp` |
| `pbs_repository` | Discouraged; use the environment file. Lets a VM leave out `source_pbs` |
| `pbs_fingerprint` | Discouraged; use the environment file. The PBS certificate fingerprint |

Flags and the environment override these keys ([which setting wins](configuration.md#precedence)).

### `tiers`

Tiers boot in ascending `level`, each after every probe of the one before passed, and stay up: put DNS and databases
first.

| Key | What it does |
| --- | --- |
| `level` | Required. `1` or more, unique in the plan. `tier` is an alias |
| `name` | Default `Tier <level>` |
| `startup_grace_period_sec` | Default `0`: the wait between the start and the probes |
| `boot_timeout_sec` | Default `60`: how long the PVE start task, then QEMU's `running` status, may each take |
| `soak_time_sec` | Default `0`. Keep the tier up this long after its probes pass, repeating them every 30 seconds |
| `vms` | Required. At least one VM |

### `vms`

| Key | What it does |
| --- | --- |
| `vmid` | Required. `100` to `999999999`: the temporary sandbox VM, unique, absent from the node. `target_vmid` is an alias |
| `source_vmid` | The VM whose backup is tested. Required for `snapshot: latest` |
| `name` | Required. A DNS name of at most 63 characters |
| `source_pbs` | Which backup and disks. Required unless `source_vmid` is set |
| `probes` | Required. At least one wire probe, or a `qga` probe with `require_qga: true` |
| `network_recovery` | [Guest network recovery](#guest-network-recovery) settings |
| `copy_before_boot` | Default `auto`: copy the disks to the overlay storage before boot when they would not stay cached and there is room. `always`: copy or fail. `never`: boot from PBS |
| `require_quiesced_backup` | Default `false`. Fail unless the backup froze the file systems or the VM was off |
| `require_signed_backup` | Default `false`. Stop the whole run unless the key in `CERTISTACK_PBS_KEYFILE` verified the backup's signature |
| `mac` | The NIC's MAC: unique in the plan (clones often share one), not zero, broadcast or multicast |
| `nic_model` | A PVE NIC model, such as `virtio` or `e1000` |
| `machine`, `ostype`, `bios`, `scsihw` | Proxmox VE's values, overriding the backup's; `validate` checks them |
| `hardware_overrides` | CPU and memory ([below](#hardware_overrides)) |

#### What the sandbox VM gets

- **The backup.** `snapshot: "latest"` picks the newest backup of `source_vmid`; the report records its path. To retest an
  older one, give its path (`vm/100/2026-09-27T03:00:07Z`).
- **Disks.** With `use_backup_config: true`, every disk in the backup; without it, those in `source_pbs.drives` (leave
  out Cloud-Init drives).
- **Hardware.** With `use_backup_config`, CPU, memory and `net0`'s MAC and model come from the backup; firmware,
  machine type, SCSI controller and OS type always do. A value the plan sets wins. Extra NICs, VLAN tags and
  passthrough devices are dropped.
- **Machine version.** If the node's QEMU cannot run the backup's, set `machine:` to `q35` or `pc`.
- **UEFI and TPM.** `efidisk0` and `tpmstate0` go onto the overlay storage, with their secrets. A backup job that
  selects all VMs during a test copies them into a new backup group: exclude the sandbox VM IDs (`--exclude`, or a
  pool-based selection).

### `hardware_overrides`

A missing key or `0` takes the backup's value (with `use_backup_config`), else the default.

| Key | What it does |
| --- | --- |
| `cores` | Default `2`; `1` to `256` |
| `sockets` | Default `1`; `1` to `16` |
| `memory_mb` | Default `2048`; `16` to `4194304` |
| `balloon_mb` | At most the VM's memory |
| `cpu_weight` | Default `50`; `1` to `262144` (PVE's `cpuunits`) |

### `source_pbs`

Left out, it means `vm/<source_vmid>/latest`, and `drive-scsi0` without `use_backup_config`. With `storage_id` set,
give `snapshot`, and `drives` without `use_backup_config`.

| Key | What it does |
| --- | --- |
| `storage_id` | `pbs`, the only value |
| `snapshot` | `latest`, `vm/<vmid>/latest` or `vm/<vmid>/<RFC 3339 time>`, of `source_vmid` |
| `drives` | Each entry: a `slot` (such as `scsi0` or `virtio0`) and the `archive` backed up from it |
| `drive` | Alias: one archive, in the slot its name gives (`drive-virtio0` is `virtio0`) |
| `namespace` | Default `storage.pbs_namespace`. One run reads one namespace |

### `network_recovery`

| Key | What it does |
| --- | --- |
| `mode` | Default `auto`; or `ifcfg`, `networkmanager`, `netplan`, `systemd-networkd`, `ifupdown`, or `preserve` (keep the guest's network, MAC and model) |
| `sandbox_ip` | `net0`'s address in `ip_range`, unique in the plan. Not with `preserve` |
| `interface_name` | For a legacy profile tied to a name, such as `ifcfg-eth0`: the guest sees that name |
| `attach_all_nics` | Default `false`. Also attach `net1` and up, with the guest's own settings. To probe one, set `sandbox_ip` to `net0`'s address |
| `capture_diagnostics` | Default `false`. When a wire probe fails, record the guest's interfaces, routes, sockets and failed services |

## Probes

Wire probes (`tcp`, `http`, `dns`, `ldap`, `mssql`, `smb`) reach the guest from the node over the sandbox network;
`qga` runs inside the guest. A VM is `verified` only when a wire probe or an unskipped `qga` probe passed within its
`timeout_sec`; `qmp` and `screendump` never verify.

| Key | What it does |
| --- | --- |
| `type` | Required. A type below. Aliases: `tcp_handshake`, `http_get`, `qga_ping`, `qmp_status` |
| `timeout_sec` | Default `10` |
| `retries` | Default `0` (keep trying until the timeout), up to `10` |
| `description` | Shown in the report |
| `target_ip` | The guest's address: inside `ip_range`, not `probe_ip`, one VM's only |
| `port` | `1` to `65535` |
| `url` | `http(s)://<address>[:port]/path`, instead of `target_ip`, `port`, `path` and `tls` |
| `path` | Default `/` |
| `tls` | Use HTTPS |
| `expected_status` | `200` to `599`; redirects are not followed |
| `server_name` | The name the certificate must carry; on `http` also the SNI and `Host` header |
| `domain` | The name to resolve |
| `transport` | `udp` (default) or `tcp` |
| `record_type` | `a` (A or AAAA; default) or `srv` |
| `base_dn` | `auto`, or a DN to read |
| `naming_context` | A DN the directory must advertise; not with `base_dn` |
| `command` | One of the [allowed commands](#qga) |
| `expected_output` | Text the output must contain |
| `require_qga` | Default `false`. Fail instead of skip when the agent does not answer; set it for Windows |
| `tls_skip_verify`, `insecure_skip_verify` | Rejected: certificates are always verified |

### Probe types

Wire probes need `target_ip` and `port`. A type refuses a key it does not read.

| Type | Also reads | Passes when |
| --- | --- | --- |
| `tcp` | | A TCP handshake completes |
| `http` | `url`, `path`, `tls`, `server_name`, `expected_status` | A GET returns `expected_status` (required); HTTPS certificates verify against the node's trust store |
| `dns` | `path`, `domain`, `transport`, `record_type` | `target_ip` answers `domain`; without `domain`, any well-formed reply |
| `ldap` | `base_dn`, `naming_context` | An anonymous bind without TLS returns `base_dn` or shows `naming_context` (use it for an Active Directory DC) |
| `mssql` | `server_name` | SQL Server answers a TDS `PRELOGIN`. With `server_name`, TDS 8.0 strict encryption only |
| `smb` | | The server answers an SMB2 `NEGOTIATE` |
| `qga` | `command`, `expected_output`, `require_qga` | The command exits 0 with `expected_output` |
| `qmp` | | QEMU reports `running`, even at a kernel panic |
| `screendump` | | A screenshot was taken |

### `qga`

Allowed commands: `hostname`, `guest-get-host-name`, `ping`, `guest-ping`, `systemctl is-active <service>` and
`sc query <service>` (passes only for `4 RUNNING`). Name the unit that runs the service: on Debian and Ubuntu,
`postgresql@16-main`, not `postgresql`. Without `require_qga: true`, an agent silent for about 5 seconds makes the
probe `SKIPPED`, and a skip is never evidence.

## Guest network recovery

Before a VM with wire probes boots, CertiStack writes a network profile into its overlay that gives the guest its
probe address. It needs `guestfish` on the node (setup installs it) and every disk the root file system
needs. When NetworkManager and networkd both match the NIC, set `mode` yourself. A LUKS or BitLocker volume, or a layout
recovery cannot rewrite safely, fails before boot: use `preserve` (the guest must unlock without a prompt), or leave
the encrypted disk out.

### Windows and appliances

Windows guests and appliances such as pfSense or OPNsense fail with `unsupported guest network layout`. Set
`network_recovery.mode: preserve`, set `ip_range` to the guest's own subnet and each `target_ip` to its address, and
leave out `sandbox_ip`. The node that runs the test must have no address and no route in that subnet.

## Examples

Each is a file in [`examples/`](https://github.com/cliftcloud/certistack/tree/main/examples). Copy one, then change
each value marked `CHANGE` and each address, port and unit name:

```bash
cp examples/three-tier-app.yaml my-app.yaml
```

### Three tiers

```yaml
--8<-- "examples/three-tier-app.yaml"
```

### Windows domain

```yaml
--8<-- "examples/windows-domain.yaml"
```
