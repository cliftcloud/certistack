# Your node

<a id="what-it-changes"></a>

## What it changes on your node

Your backups and source VMs are never changed. Setup asks before each change.

| Where | What | Why |
| --- | --- | --- |
| Node | The controller's SSH key in `/root/.ssh/authorized_keys` | The controller runs a short-lived worker as root. On a cluster the file is shared, so the key is root on every node: use a dedicated controller. |
| Node | `libguestfs-tools` and `nftables`, each if missing (stock PVE 9 has `nftables`), with about 110 dependencies (about 225 MB on a stock PVE 9.2); the first run adds libguestfs's cache, `/var/tmp/.guestfs-0` (about 1.3 GB). apt may also upgrade a few installed packages they need, such as `util-linux` and `mount`, and on PVE 8 it replaces `fuse` with `fuse3`: setup lists them and asks first. One dependency, `mdadm`, makes apt rebuild the node's initramfs and boot menu; removing them rebuilds the initramfs again | Preparing the guest's network offline; network probes |
| Node | A directory storage `certistack-scratch` | The sandbox VM's overlays |
| PVE | Role `CertiStackRole`, user `certistack-svc@pve`, token `certistack-svc@pve!automation` | Creating and removing the sandbox VM and network. The token could do this to any VM or zone: keep `controller.env` private. |
| PBS | User `certistack-ro@pbs` and its token, with `DatastoreReader` | Reading the whole datastore, or only the namespace you give setup |
| Controller | In `/secure/certistack`: SSH key, host key, PVE CA, `controller.env` and its `.bak-*` copies, and if used `pbs-access.sh` and an encryption key (`<ID>.enc`); the PBS's host keys in `~/.ssh/known_hosts`; `controller.env`'s path in `~/.config/certistack/env-file` | The credentials a run uses. The encryption key decrypts every backup in its storage; setup copies it only if you say yes. |
| Node, during a run | A worker, read-only backup maps with overlays, the sandbox VM (a VM ID from 9100 up; an existing ID is refused), and an SDN zone and VNet with no uplink | Booting the backup in isolation. The run removes each and checks it is gone. |
| Node, between runs | `/var/lib/certistack` | The journal that `recover` uses after an interrupted run |

### Plan around

- **Cluster network reload.** Every run applies SDN twice, reloading the network on every node. Guests on other nodes
  lost no ping on a 14-node PVE 9.2 cluster, but an address added by hand outside the network configuration can be
  lost. A [pre-provisioned sandbox](plan-reference.md#use-a-pre-provisioned-sandbox) avoids the reload.
- **Disk.** The overlay storage needs the VM's disk size plus 5 GiB free. Never put it on a cluster node's root disk:
  heavy I/O can delay corosync and cost the node its cluster membership.
- **Memory.** A run needs the VM's memory plus 256 MiB free, and waits rather than push the node above 85% of its RAM.
- **Backup jobs.** A job that selects all VMs can back up a running sandbox VM: run outside your backup window, or
  select VMs by pool (sandbox VMs are in none).

## Set up by hand

`certistack setup` runs these steps for you, asking before each. Replace `pve-node-01.example.com` with the node's
address, spelled the same everywhere (`known_hosts` matches by spelling); `pve-node-01` with its name in PVE (on the
node: `basename "$(readlink /etc/pve/local)"`); and `pbs.example.com`, `datastore1` and `certistack-scratch` with your
PBS, datastore and overlay storage. Without `sudo`, see [Install without sudo](quickstart.md#install-without-sudo).

### 1. Prepare the node

As root on the node. A run needs `qemu-img` and `proxmox-backup-client`, which every node has, and the two packages
below. Without a subscription, a `401 Unauthorized` for `enterprise.proxmox.com` is expected.

Apt's list should remove nothing, except on PVE 8, where it replaces `fuse` with `fuse3`: `fuse3` provides `fuse`, so
`pve-cluster` keeps working. Setup shows this as `It would REMOVE: fuse.` and asks, with No as the default: answer `y`
when `fuse` is the only package listed. For any other removal, answer No and find out why
([Setup messages](troubleshooting.md#setup-messages)).

```bash
apt update; apt install --no-upgrade libguestfs-tools nftables
```

Add the overlay storage where `df -h` shows enough free space ([Plan around](#plan-around)). On a cluster node, give a
path on another disk, and add `--nodes pve-node-01`.

```bash
findmnt -T /var/lib/vz
df -h /var/lib/vz
```

```bash
pvesm add dir certistack-scratch --path /var/lib/vz/certistack-scratch --content images --shared 0
```

### 2. Connect the controller to the node

On the controller:

```bash
sudo install -d -m 0700 -o "$USER" /secure/certistack
ssh-keygen -t ed25519 -N '' -C certistack-controller -f /secure/certistack/id_ed25519
```

```bash
certistack setup trust-node --host pve-node-01.example.com
```

Before you type `yes`, check that its `SHA256:...` matches what this prints at the node's console:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Authorize the key for root. `ssh-copy-id` asks for root's password; if the node refuses passwords, append
`id_ed25519.pub` to its `/root/.ssh/authorized_keys` yourself.

```bash
mkdir -p -m 700 ~/.ssh
ssh-copy-id -o UserKnownHostsFile=/secure/certistack/known_hosts -o StrictHostKeyChecking=yes \
  -i /secure/certistack/id_ed25519.pub root@pve-node-01.example.com
```

Test it; it prints `x86_64`:

```bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/secure/certistack/known_hosts -o IdentitiesOnly=yes \
  -i /secure/certistack/id_ed25519 root@pve-node-01.example.com uname -m
```

### 3. Create the PVE token and the read-only PBS user

`certistack setup rbac` prints the scripts and runs nothing. For backups in a PBS namespace, add
`--pbs-namespace NAME` to the `--part pbs` command, or the user can read the whole datastore. For a pre-provisioned
sandbox, add `--zone ZONE` to the `--part pve` command: the token can then change only that zone.

```bash
certistack setup rbac --node pve-node-01 --overlay-storage certistack-scratch \
  --pbs-datastore datastore1 --part pve > pve-access.sh
certistack setup rbac --node pve-node-01 --overlay-storage certistack-scratch \
  --pbs-datastore datastore1 --part pbs > pbs-access.sh
```

Read both, then run `pve-access.sh` as root on the node:

```bash
ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/secure/certistack/known_hosts \
  -i /secure/certistack/id_ed25519 root@pve-node-01.example.com sh -s < pve-access.sh
```

Run `pbs-access.sh` as root on the PBS (`ssh root@pbs.example.com sh -s < pbs-access.sh`), or in its web shell type
`sh`, paste it, then `exit`. Do not authorize the controller's key on the PBS.

Each script prints its secret once: for PVE, the long string in the `value` row, between the `│` characters
(`PVE_TOKEN_SECRET`); for PBS, `PBS_PASSWORD`. Both scripts are safe to run again. To replace a lost secret, remove the
token and rerun: `pveum user token remove certistack-svc@pve automation` on the node,
`proxmox-backup-manager user delete-token certistack-ro@pbs ro` on the PBS.

### 4. Write the controller environment file

Create it with mode `0600` (`(umask 077; touch /secure/certistack/controller.env)`), and change the hosts, the
datastore and the two secrets. Comments go on their own line. Every variable is in
[Variables](configuration.md#variables).

```dotenv
PVE_URL=https://pve-node-01.example.com:8006
PVE_TOKEN_ID=certistack-svc@pve!automation
PVE_TOKEN_SECRET=your-pve-token-secret
PBS_REPOSITORY=certistack-ro@pbs!ro@pbs.example.com:8007:datastore1
PBS_PASSWORD=your-pbs-token-secret
# The PBS dashboard's Show Fingerprint, or on the PBS: proxmox-backup-manager cert info
PBS_FINGERPRINT=ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89
# Only when the backups are in a PBS namespace
#PBS_NAMESPACE=your-namespace
# The node's name in PVE, not its DNS name
CERTISTACK_NODE=pve-node-01
CERTISTACK_SSH_HOST=pve-node-01.example.com
CERTISTACK_SSH_USER=root
CERTISTACK_SSH_IDENTITY=/secure/certistack/id_ed25519
CERTISTACK_SSH_KNOWN_HOSTS=/secure/certistack/known_hosts
# The overlay storage from step 1, which step 3 granted
CERTISTACK_OVERLAY_STORAGE=certistack-scratch
# Without sudo: an absolute path you own (no ~)
#CERTISTACK_OUTPUT_DIR=/home/you/certistack/reports
```

Pass this file to each command with `--env-file`: only `certistack setup` records a default.

The node's API certificate is signed by the cluster's CA. This prints a `CERTISTACK_PVE_CA_SOURCE=...` line to add:

```bash
certistack setup pve-ca --env-file /secure/certistack/controller.env
```

### 5. Check the controller

```bash
certistack check --env-file /secure/certistack/controller.env
```

Add a plan file to check the plan and its sandbox range too.

## A second PBS for the same node

Run `certistack setup` once per node. Never run it again for the same node to reach another PBS: it can only replace
the node's PVE token, and the first environment file then stops working. For another PBS, print the PBS part of
[step 3](#3-create-the-pve-token-and-the-read-only-pbs-user) and run it as root on that PBS
(`ssh root@pbs2.example.com sh -s < pbs2-access.sh`); it prints the token secret once:

```bash
certistack setup rbac --node pve-node-01 --overlay-storage certistack-scratch \
  --pbs-datastore datastore2 --part pbs > pbs2-access.sh
```

Copy the environment file, owner-only, and in the copy change only `PBS_REPOSITORY`, `PBS_PASSWORD` (the secret the
script printed) and `PBS_FINGERPRINT` (`proxmox-backup-manager cert info` on that PBS):

```bash
install -m 0600 /secure/certistack/controller.env /secure/certistack/controller-pbs2.env
```

Pass the copy to each command for that PBS; without `--env-file`, commands use the first file:

```bash
certistack check --env-file /secure/certistack/controller-pbs2.env
```

## The sudoers rule for a non-root account

The worker runs as root. To connect as another account, give it passwordless `sudo` (at `/usr/bin/sudo`), and set
`CERTISTACK_SSH_USER` and `CERTISTACK_SSH_SUDO=true`. On the node, as root:

```bash
useradd -m -s /bin/bash certistack
```

Give it a password (`passwd certistack`) for `ssh-copy-id`, and authorize the key as in step 2 with `certistack@`.

Then install `sudo`, create the rule with `visudo`, and check it:

```bash
apt install sudo
visudo -f /etc/sudoers.d/certistack
visudo -cf /etc/sudoers.d/certistack
```

The file holds one line; the check prints `parsed OK`:

```text
certistack ALL=(root) NOPASSWD: /usr/bin/install, /usr/bin/systemd-run, /bin/sh, /usr/bin/rm, /usr/bin/cat, /usr/bin/touch, /usr/bin/test, /var/lib/certistack/workers/*/certistack-node
```

Change `certistack` to your `CERTISTACK_SSH_USER`, and `/var/lib/certistack` to your `CERTISTACK_STATE_DIR` if set.
From the controller, this prints nothing and exits `0` when the rule works; `certistack check` tests the rest:

```bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/secure/certistack/known_hosts -o IdentitiesOnly=yes \
  -i /secure/certistack/id_ed25519 certistack@pve-node-01.example.com \
  sudo -n /usr/bin/test ! -e /nonexistent
```

The rule is not a security boundary: `/bin/sh`, `install` and `systemd-run` can do anything as root. Do not narrow it
with argument patterns; the arguments change with every run.

## The PVE role and its permissions

The token `certistack-svc@pve!automation` is privilege-separated: it gets only what both it and `certistack-svc@pve`
hold. So the role `CertiStackRole` is granted to both on each path, never on `/`:

| ACL path | Propagate | Covers |
| --- | --- | --- |
| `/vms` | yes | The sandbox VMs (PVE deletes a VM's own ACL with the VM). With a pre-provisioned sandbox, `VM.Audit` here also shows a run every guest on its VNet. |
| `/sdn` | no | PVE's SDN lock (PVE 9) and applying the sandbox network |
| `/sdn/zones` | yes | Creating and removing the sandbox zone and VNet |
| `/sdn/zones/<zone>` | yes | Instead of the two above, each pre-provisioned zone |
| `/storage/<overlay storage>` | yes | The overlays |
| `/nodes/<node>` | no | Node status and QEMU machine versions |

The same with plain commands, as root on a PVE node (run again, they stop with "already exists"):

```bash
pveum role add CertiStackRole --privs "VM.Allocate VM.Audit VM.PowerMgmt VM.Console VM.Config.Disk VM.Config.CPU VM.Config.Memory VM.Config.Network VM.Config.Options VM.Config.HWType VM.Config.CDROM SDN.Allocate SDN.Audit SDN.Use Sys.Audit Datastore.AllocateSpace Datastore.Audit"
pveum user add certistack-svc@pve --comment "CertiStack DR validation"
pveum user token add certistack-svc@pve automation --privsep 1
for path in /vms /sdn/zones /storage/certistack-scratch; do
  pveum acl modify "$path" --roles CertiStackRole \
    --users certistack-svc@pve --tokens 'certistack-svc@pve!automation' --propagate 1
done
for path in /sdn /nodes/pve-node-01; do
  pveum acl modify "$path" --roles CertiStackRole \
    --users certistack-svc@pve --tokens 'certistack-svc@pve!automation' --propagate 0
done
```

Check a path with `pveum user token permissions certistack-svc@pve automation --path /vms`. On the PBS, the user needs
only `DatastoreReader`; `generate-token` prints `PBS_PASSWORD` once:

```bash
proxmox-backup-manager user create certistack-ro@pbs
proxmox-backup-manager user generate-token certistack-ro@pbs ro
proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id certistack-ro@pbs
proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id 'certistack-ro@pbs!ro'
```

## Create the PVE access with Terraform

The module in `terraform/` (Terraform 1.8 or later, or OpenTofu 1.10 or later) creates the same role, user, token and grants;
`terraform/terraform.tfvars.example` lists its inputs. Run it with `SSL_CERT_FILE=/secure/certistack/pve-root-ca.pem`
and a bootstrap token you remove afterwards (`pveum user token add root@pam terraform --privsep 0`).
`terraform output -raw pve_token_secret` prints the secret. The state holds it: use an encrypted backend.

## Build from source

You need `make` and Go 1.27.4 or later.

```bash
git clone --depth 1 --branch v0.1.3 https://github.com/cliftcloud/certistack.git certistack-src
cd certistack-src
make build-linux          # bin/certistack-linux-amd64
make build-linux-arm64    # bin/certistack-linux-arm64 (offline commands only)
```

A `go install` build has no commit, so it is not release evidence.

## Install, upgrade and roll back a release

To keep versions side by side, run this in the download directory of
[Install by hand](quickstart.md#install-by-hand):

```bash
version=v0.1.3
sudo install -d -m 0755 "/opt/certistack/releases/$version"
sudo install -m 0755 certistack-linux-amd64 "/opt/certistack/releases/$version/certistack"
sudo ln -sfn "/opt/certistack/releases/$version/certistack" /usr/local/bin/certistack
certistack version
```

Upgrade with no run going or left to recover, then run a plan that should pass. To roll back, first recover any run
the newer version left, as root on the node with its kept worker ([Issue 35](troubleshooting.md#issue-35)); never
delete a journal, report or workspace instead. Then set `version` to the previous release and run the `ln -sfn` and
`certistack version` lines again. An appliance runs the image named in `/etc/certistack/controller-image` instead:
see `deploy/appliance/README.md`.

## Remove CertiStack

This removes what setup or [Set up by hand](#set-up-by-hand) created.

<a id="remove-1-let-runs-finish"></a>

### 1. Controller: let runs finish

Let a run finish, or press Ctrl-C once in its terminal and wait. This prints nothing when none is going:

```bash
pgrep -af 'certistack [r]un'
```

<a id="remove-2-check-the-node"></a>

### 2. Node: check that no run left anything

As root on the node, look for a sandbox VM (from 9100 up) and a zone named `csZone…`, then recover any workspace:

```bash
ls /var/lib/certistack/workers/
qm list
pvesh get /cluster/sdn/zones --output-format json
```

On a node without SDN (PVE 8.0 without `libpve-network-perl`), `pvesh` prints `No 'get' handler defined for
'/cluster/sdn/zones'`: there is no zone to look for.

```bash
# On the node, as root: recover every workspace that is listed.
for w in /var/lib/certistack/workers/*/; do
  [ -x "$w/certistack-node" ] && "$w/certistack-node" recover \
    --state-dir /var/lib/certistack --env-file "$w/runtime.env"
done
```

An interrupted `init`, `check` or `run` can also leave a staging directory with a copy of the credentials (root only,
mode 0600); the command that was stopped prints how to delete it. Look for one and delete it:

```bash
# On the node, as root.
ls -d /tmp/certistack-controller-* 2>/dev/null && rm -rf /tmp/certistack-controller-*
```

A workspace with `credentials-removed.txt` cannot recover: run one more `certistack run` (it recovers first), or
remove the VM (`qm stop <vmid>; qm destroy <vmid>`) and its subnets, VNet and zone in Datacenter > SDN, then Apply (which
also applies others' pending changes: ask first). Go on only when nothing is left and `/var/lib/certistack/active.json`,
if present, shows the phase `cleaned`.

<a id="remove-3-proxmox-ve"></a>

### 3. Proxmox VE: take back the access

As root on the node (with the Terraform module, `terraform destroy` instead). The last command prints nothing when none
is left.

```bash
pveum user token remove certistack-svc@pve automation
pveum user delete certistack-svc@pve
pveum role delete CertiStackRole
pveum acl list | grep -i certistack
```

`pveum user delete` may print `ignore invalid acl token 'certistack-svc@pve!automation'` once per grant of the removed
token; the last command shows that none is left.

Then the overlay storage and state directory, **on the node only**: on the controller, `/var/lib/certistack` holds your
reports. If the storage was yours before setup (setup said `Using the existing storage` the first time it ran),
keep the storage, and after the first block delete only CertiStack's files with
`find "$P" -type f -name 'certistack-delta-*' -delete`. A storage that setup added and a later rerun reused is
CertiStack's: remove it.

```bash
# On the node, as root. P is the storage's directory, read before pvesm forgets it.
P=$(awk '/^dir: certistack-scratch$/ {f=1; next} /^[a-z]+: / {f=0} f && $1 == "path" {print $2; exit}' /etc/pve/storage.cfg)
echo "storage directory: ${P:?certistack-scratch is not in /etc/pve/storage.cfg}"
find "$P" -type f ! -name 'certistack-delta-*'
```

The `find` should print nothing; if it lists a file, the next block keeps the storage. In the same shell:

```bash
# On the node, as root. Removes the storage and its images only when every file in it is CertiStack's,
# the directory only if it is then empty, and the node's state directory.
if [ -z "${P:-}" ]; then
  echo "run the block above first, in this shell"
elif [ -n "$(find "$P" -type f ! -name 'certistack-delta-*' -print -quit)" ]; then
  echo "kept certistack-scratch: $P holds files that are not CertiStack's"
else
  pvesm remove certistack-scratch && rm -rf "$P/images" && { rmdir "$P" 2>/dev/null || echo "kept $P: it holds other files, or it is a mount point"; }
fi
rm -rf /var/lib/certistack
```

Remove the controller's keys from root's `authorized_keys`. A cluster shares the file: keep a second root session open,
and write it back in place (`sed -i` can break the link). The second count must be `0`:

```bash
grep -c ' certistack-controller$' /root/.ssh/authorized_keys
grep -v ' certistack-controller$' /root/.ssh/authorized_keys > /root/authorized_keys.new
cat /root/authorized_keys.new > /root/.ssh/authorized_keys && rm /root/authorized_keys.new
grep -c ' certistack-controller$' /root/.ssh/authorized_keys
```

On the controller, this must now say `Permission denied (publickey...)`:

```bash
ssh -i /secure/certistack/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/secure/certistack/known_hosts \
  root@pve-node-01.example.com true
```

<a id="remove-4-proxmox-backup-server"></a>

### 4. Proxmox Backup Server: take back the read-only user

As root on each PBS you gave access. Keep one `acl update` line per path the first command shows; the last prints
nothing when none is left.

```bash
proxmox-backup-manager acl list | grep -i certistack
proxmox-backup-manager user delete-token certistack-ro@pbs ro
proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id certistack-ro@pbs --delete true
proxmox-backup-manager acl update /datastore/datastore1/NAMESPACE DatastoreReader --auth-id certistack-ro@pbs --delete true
proxmox-backup-manager user remove certistack-ro@pbs
proxmox-backup-manager acl list | grep -i certistack
```

<a id="remove-5-controller-files"></a>

### 5. Controller: remove the files

Use your setup directory, and delete the encryption key `CERTISTACK_PBS_KEYFILE` named, if any (`<storage>.enc`), and
any other environment file you made, such as `controller-pbs2.env`.

```bash
certistack telemetry reset
rm -f /secure/certistack/controller.env /secure/certistack/controller.env.bak-* \
  /secure/certistack/controller.env.partial \
  /secure/certistack/id_ed25519 /secure/certistack/id_ed25519.pub \
  /secure/certistack/known_hosts /secure/certistack/pve-root-ca.pem \
  /secure/certistack/pbs-access.sh
rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/certistack/env-file"
sudo rm -f /usr/local/bin/certistack /usr/local/bin/certistack.prev
```

### What stays

- Your reports and plans.
- On the node: `libguestfs-tools` and its dependencies, if setup installed them (`The node lacks libguestfs-tools`),
  and libguestfs's cache, `/var/tmp/.guestfs-0`. If nothing else uses them: `rm -rf /var/tmp/.guestfs-0`, then
  `apt purge libguestfs-tools && apt autoremove --purge` (purging also removes their configuration files, such as
  `/etc/mdadm/mdadm.conf`). apt keeps the dependencies that another installed package recommends or suggests: on a
  stock PVE 9.2 about 40 of the 110 stay, and they are harmless. The packages setup upgraded stay at their new
  versions, and `apt clean` empties apt's download cache. To see exactly what setup added, compare `dpkg-query -W`
  with a list you took before setup.
- On the node: `nftables`, if it was there before setup (PVE 9 ships it): PVE's firewall uses it. If setup installed it
  (`The node lacks ... nftables`, as on PVE 8.0 and 8.1), `apt remove nftables` once nothing else uses it.
- On the node: PVE's SDN files in `/etc/pve/sdn` (empty once the zones are gone), its IPAM state, which keeps an empty
  entry for each zone name a run used (`csZone1`, `csZone2` …), and `/etc/network/interfaces.d/sdn`, which PVE writes
  at each SDN apply. They are PVE's own bookkeeping and harmless.
- On the node: `/etc/pve/storage.cfg` as PVE rewrote it when setup added the overlay storage and step 3 removed it.
  Other storages' `content` lists may be in another order; the content is the same.
- On the controller: the setup directory, empty, and `~/.config/certistack`. Remove them if you like:
  `sudo rmdir /secure/certistack /secure` (the second fails, harmlessly, if something else is in `/secure`) and
  `rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/certistack"`.
- Delete when you like: `release-signing-key.gpg`, `release-signing-key.gpg~` and `~/certistack-download`; scripts
  `setup rbac` printed; `telemetry.json.lock`; the PBS's host keys in `~/.ssh/known_hosts` (ssh adds every key the PBS
  offers, under a hashed name): `ssh-keygen -R <PBS address>` removes them, and keeps the file before as
  `known_hosts.old`, which you can delete; secrets in your shell history. `~/.ssh` and `~/.config` stay, empty if
  nothing else uses them.
- After a setup by hand: the node's `certistack` account (`userdel -r certistack`) and `/etc/sudoers.d/certistack`, and
  the controller's `/opt/certistack/releases/<version>`.
