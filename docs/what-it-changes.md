# What it changes on your node

CertiStack only reads your backups and never touches your running VMs. To restore and boot a
backup, though, setup has to grant it some access, and each run makes temporary changes on the
node. This page lists all of it in one place, with what keeps each change contained.
[Remove CertiStack](undo.md) takes every part of it back off.

## Never changed

- **Your backups.** A run maps each backup read-only, and the PBS user that setup creates can
  only read.
- **Your VMs.** The sandbox is a new VM with its own ID. Its disk writes go to a throwaway overlay,
  and the source VM is never touched.

## What setup adds

Setup asks before each change on the node, PVE and PBS. It writes the controller's files into the
directory you give it without asking again.

| Where | What | Why |
| --- | --- | --- |
| Node | The controller's SSH key in `/root/.ssh/authorized_keys` | The controller runs a short-lived worker on the node as root |
| Node | The packages `libguestfs-tools` and `nftables` | Preparing the guest's network offline, and the network probes |
| Node | A directory storage `certistack-scratch` (images, not shared) | The overlays the sandbox VM writes to |
| PVE | The role `CertiStackRole`, the user `certistack-svc@pve` and its token `certistack-svc@pve!automation` | Creating, starting and removing the sandbox VM and its network |
| PBS | The user `certistack-ro@pbs` and its token, with `DatastoreReader` | Reading the backups, and nothing else |
| Controller | In the setup directory (`/secure/certistack`): the SSH key, the node's host key, the PVE CA, `controller.env` (mode `0600`) and earlier copies of it (`controller.env.bak-*`), and, when they apply, an encrypted storage's key (`<ID>.enc`) and `pbs-access.sh`. The PBS's host key goes into your `~/.ssh/known_hosts` | The credentials a run uses |

## What a run does

1. It uploads a worker to a root-only directory on the node over SSH.
2. It maps the backup read-only and puts a copy-on-write overlay on each disk.
3. It creates the sandbox VM, using one of the plan's sandbox VM IDs (from 9100 up). It refuses
   to start if that ID already exists.
4. It creates a temporary SDN zone and VNet with no gateway and no uplink, so the guest can reach
   nothing outside the sandbox. On a cluster this reloads the network on every node
   ([below](#things-to-plan-around)).
5. It boots the VM, runs the checks the plan lists, and then removes the VM, the overlays, the
   network and the worker. It verifies that each one is gone.
6. It keeps a journal in `/var/lib/certistack` on the node, so an interrupted run can be cleaned up
   later with `certistack recover`. Between runs, only that directory stays.

## The access you grant, and what limits it

| Access | What it could do | What limits it |
| --- | --- | --- |
| The SSH key, as root | Anything on the node. On a cluster, root's `authorized_keys` is shared, so the key is root on **every** node. | Use a dedicated controller, not your workstation. The node's host key is pinned, so the key only talks to the node you confirmed. |
| The PVE token | Create, start and destroy any VM, and any SDN zone, through the API | A run only touches its plan's sandbox VM IDs and the zone its plan names. Keep `controller.env` private (setup writes it as mode `0600`). A run with a [pre-provisioned network](plan-reference.md#network) changes no SDN configuration; to limit the token itself to that one zone, create it with `certistack setup rbac --zone ZONE` ([Set up by hand](manual-setup.md)). The token `certistack setup` creates can change any zone. |
| The PBS user | Read every backup in the datastore, or only in the namespace you gave setup | Give setup a namespace to narrow it; it then offers to remove an earlier grant of the whole datastore. Setup asks before it grants the whole datastore. |
| The encryption key, if setup copied it | Decrypt every backup in that PBS storage | Setup asks, and the default is no. Copy it only to a controller you trust as much as the PBS itself. |

## Things to plan around

- **Clusters: the network reload.** Every run applies SDN twice, and Proxmox reloads the network
  on all nodes each time, one after another. On a 14-node PVE 9.2 cluster we measured it: guests on
  other nodes, pinged five times a second through both applies, missed no reply, and their latency
  stayed in its usual range. An address added to an interface by hand, outside the node's network
  configuration, can still be lost in a reload. Start on a standalone node, or use a
  [pre-provisioned network](plan-reference.md#network), which changes no SDN configuration.
- **Disk space and load.** A run needs at least 5 GiB free on the overlay storage. Plan for the
  VM's disk size plus 5 GiB, because when the node can't keep a VM's disks cached it copies them
  there first. On a cluster node, setup refuses the root disk, because heavy I/O there can delay
  corosync and cost the node its cluster membership.
- **Memory.** A run needs the VM's memory plus 256 MiB free. It waits rather than start a VM that
  would push the node above 85 % of its RAM.
- **Backup jobs.** A backup job that selects all VMs can pick up a sandbox VM if it starts during
  a run, and file it as a new backup group. The simplest fix is to run outside your backup window.
  Or have your backup jobs select VMs by pool instead of "all": sandbox VMs are never in your
  pools ([more](architecture.md#backup-jobs-and-vm-ids)).
- **VM IDs.** Keep the plan's sandbox VM IDs (from 9100 up) free. A run refuses an ID that already
  exists, so it never overwrites a VM.
