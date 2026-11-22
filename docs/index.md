# Overview

CertiStack proves your Proxmox backups restore. It takes a VM's backup from Proxmox Backup Server, boots it in an
isolated sandbox on your Proxmox VE node, checks that its services answer, removes everything, and writes a
report.

PBS verify jobs check that stored data is intact but boot nothing. Keep them: CertiStack checks that the VM starts and
its services come up.

**New here? Start with the [quickstart](quickstart.md).**

## How a run works

You run `certistack` on the *controller*, a small Linux VM (or the
[container](https://github.com/cliftcloud/certistack/blob/main/deploy/controller/README.md) or
[VM template](https://github.com/cliftcloud/certistack/blob/main/deploy/appliance/README.md)) that holds your plans,
credentials and reports. A *plan* names the VMs to restore and what to check.

1. The controller connects to the node over SSH, with a pinned host key, and uploads a short-lived worker into a
   root-only directory. Nothing of CertiStack keeps running on the node.
2. The worker maps each backup disk read-only from PBS, with a throwaway overlay on top that takes every write. It reads
   every disk in full and records its SHA-256.
3. It creates a temporary SDN network with no gateway and no uplink, and boots a new VM from the overlays.
4. It runs the plan's checks: the VM is running, then network probes (tcp, http, dns, ldap, mssql, smb) from the worker,
   then commands through the guest agent.
5. It removes the VM, the overlays, the backup maps and the network, and checks that each is gone. The controller writes
   the report.

A run passes only when every check passed **and** the cleanup was verified. CertiStack has been tested with more than
10,000 VM restore tests ([what was tested](compatibility.md#what-was-tested)).

<a id="what-it-changes"></a>

## What it changes on your node

- Setup adds the controller's SSH key to root's `authorized_keys`, the package `libguestfs-tools` (and `nftables` if
  missing), a directory storage `certistack-scratch` for the overlays, a PVE API token that can manage VMs and SDN, and a read-only
  PBS user.
- A run adds a sandbox VM (IDs from 9100 up), a temporary SDN zone and VNet, and a worker, and removes them again. On a
  cluster, applying SDN reloads the network on every node.
- Between runs, only `/var/lib/certistack` (the run journal) stays on the node.
- The full list, the access you grant and how to take it back: [Your node](manual-setup.md#what-it-changes).

## Safety

- **Your backups are only read.** They are mapped read-only, and the PBS user can only read.
- **Your VMs are never touched.** The sandbox is a new VM, and a run refuses a VM ID that already exists.
- **The sandbox has no way out.** Its network has no gateway, uplink or NAT, and a firewall rule on the node drops new
  traffic from it. CertiStack does not scan for malware, but a VM whose files were encrypted fails its probes.
- **Cleanup is proven.** A resource counts as removed only when CertiStack can show it was the run's own and is gone.
  Recovery touches only what the run recorded, never anything else on the host.
- **An interrupted run is cleaned up.** The node keeps a journal of what each run created. It cleans up on its own when
  the controller goes silent, the next run finishes it first, and `certistack recover` does it on demand
  ([Issue 35](troubleshooting.md#issue-35)).
- **Root only on the node.** Mapping a backup needs root, so the controller logs in to the node as root. The controller
  itself runs as an ordinary user.
- **Nothing leaves your network.** CertiStack talks only to your PVE, PBS, node and sandbox guests.
  [Usage statistics](telemetry.md) are off unless you opt in.

A pass means the plan's probes passed in that run: a `tcp` probe proves a port is open, an `http` probe a status code.
Pick probes for what each VM is for ([Plans](plan-reference.md)).

## Editions

This is the **Community Edition**: a free, open source command-line tool (AGPL-3.0-or-later) with no limit on nodes or
VMs. Built-in schedules, alerts and a dashboard are in the [Enterprise Edition](editions.md).

## Help

Ask in [GitHub Discussions](https://github.com/cliftcloud/certistack/discussions). Report bugs as
[issues](https://github.com/cliftcloud/certistack/issues/new/choose), with the `--debug` output, `certistack version`
and your PVE and PBS versions, credentials removed. Report security problems privately
([security policy](https://github.com/cliftcloud/certistack/blob/main/SECURITY.md)).
