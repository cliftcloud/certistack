# Remove CertiStack

Remove everything `certistack setup` or the [manual setup](manual-setup.md) created, in an order that keeps the tools
working. Your backups and source VMs are never touched. Names are the quickstart's; use yours if
you changed them.

## 1. Controller: stop scheduled runs {#1-on-the-controller-stop-scheduled-runs}

If you [scheduled runs](automation.md), remove them first (for the container, its `crontab -e` line). This stops and
disables every plan's timer, and removes the units, the drop-ins `systemctl edit` made (a site's environment file, a
plan's own time, the usage statistics' opt-in), the cron file and the wrapper:

```bash
sudo systemctl stop 'certistack-validate@*.timer'
sudo systemctl stop 'certistack-validate@*.service'   # a run going now: waits for its cleanup
sudo rm -f /etc/systemd/system/timers.target.wants/certistack-validate@*.timer
sudo rm -f /etc/systemd/system/certistack-validate@.service /etc/systemd/system/certistack-validate@.timer \
  /etc/systemd/system/certistack-alert@.service
sudo rm -rf /etc/systemd/system/certistack-validate@*.service.d /etc/systemd/system/certistack-validate@*.timer.d \
  /etc/systemd/system/certistack-alert@*.service.d
sudo systemctl daemon-reload
sudo rm -f /etc/cron.d/certistack /usr/local/bin/certistack-validate
```

Check that no run is going (no output). Let one you started by hand finish, or press Ctrl-C once in its terminal and
wait:

```bash
pgrep -af 'certistack [r]un'
```

## 2. Node: check nothing is left {#2-on-the-node-check-that-no-run-left-anything}

An interrupted run can leave a sandbox behind. As root:

```bash
ls /var/lib/certistack/workers/
qm list
pvesh get /cluster/sdn/zones --output-format json
```

Expect no sandbox VM (IDs from 9100 up) and no zone `csZone1`. A workspace directory may stay after a recovery (it
keeps its logs); step 3 deletes it. Recover any workspace first
([Issue 26](troubleshooting.md#issue-26-lost-contact-with-node)):

```bash
# On the node, as root: recover every workspace that is listed.
for w in /var/lib/certistack/workers/*/; do
  [ -x "$w/certistack-node" ] && "$w/certistack-node" recover \
    --state-dir /var/lib/certistack --env-file "$w/runtime.env"
done
```

A workspace with `credentials-removed.txt` cannot. Run one more `certistack run` (it recovers first), or remove the VM
(`qm stop <vmid>; qm destroy <vmid>`) and, in Datacenter > SDN, the subnets, VNet and zone, then Apply (Apply also
applies others' pending changes: ask first). Go on only when no sandbox VM or zone is left, and
`/var/lib/certistack/active.json`, if there is one, shows the phase `cleaned`.

## 3. Proxmox VE node: take back the access {#3-on-the-proxmox-ve-node-as-root-take-back-the-access}

As root, remove the token, user and role, then look for leftover permissions (no output means none):

```bash
pveum user token remove certistack-svc@pve automation
pveum user delete certistack-svc@pve
pveum role delete CertiStackRole
pveum acl list | grep -i certistack
```

A `user config - ignore invalid acl token` notice is harmless. With the Terraform module, run `terraform destroy`
instead.

### Overlay storage and worker files

Read the storage's directory first: `pvesm remove` forgets it. **Run this on the node only:** on the controller,
`/var/lib/certistack` holds your reports. If setup said `Using the existing storage`, it did not create the storage:
do not remove it, and delete only CertiStack's files in it, with `find "$P" -type f -name 'certistack-delta-*' -delete`
after the first block.

```bash
# On the node, as root. P is the storage's directory, read before pvesm forgets it.
P=$(awk '/^dir: certistack-scratch$/ {f=1; next} /^[a-z]+: / {f=0} f && $1 == "path" {print $2; exit}' /etc/pve/storage.cfg)
echo "storage directory: ${P:?certistack-scratch is not in /etc/pve/storage.cfg}"
find "$P" -type f ! -name 'certistack-delta-*'
```

The `find` should print nothing: a file it lists is not CertiStack's, and the next block then keeps the storage. Then,
in that shell:

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

### The controller's SSH key

Remove the key commented `certistack-controller` from root's `authorized_keys`. A cluster shares this file: keep a
second root session open, and write it back in place (a `sed -i` can break the link).

```bash
grep -c ' certistack-controller$' /root/.ssh/authorized_keys
grep -v ' certistack-controller$' /root/.ssh/authorized_keys > /root/authorized_keys.new
cat /root/authorized_keys.new > /root/.ssh/authorized_keys && rm /root/authorized_keys.new
grep -c ' certistack-controller$' /root/.ssh/authorized_keys
```

The first count is the number of controller keys: one per setup directory that was set up against this node or its
cluster (setup run again in the same directory reuses its key). The block removes them all, and the second count is
`0`. On the controller, check the key fails:

```bash
ssh -i /secure/certistack/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/secure/certistack/known_hosts \
  root@pve-node-01.example.com true
```

It must say `Permission denied (publickey...)`; `Host key verification failed` means it did not test. After
scheduled runs the files are the `certistack` user's: put `sudo -u certistack` in front of `ssh`.

## 4. Proxmox Backup Server: take back the read-only user {#4-on-the-proxmox-backup-server-as-root-take-back-the-read-only-user}

As root. The first command shows each path the user holds a grant on: the datastore, a namespace of it, or both (a
later setup with a namespace may have left the earlier grant). Keep one `acl update` line for each path it shows, with
that path:

```bash
proxmox-backup-manager acl list | grep -i certistack
proxmox-backup-manager user delete-token certistack-ro@pbs ro
proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id certistack-ro@pbs --delete true
proxmox-backup-manager acl update /datastore/datastore1/NAMESPACE DatastoreReader --auth-id certistack-ro@pbs --delete true
proxmox-backup-manager user remove certistack-ro@pbs
proxmox-backup-manager acl list | grep -i certistack
```

The last command prints nothing when no grant is left. Deleting the token removes its own grants.

## 5. Controller: remove the files {#5-on-the-controller-remove-the-files}

`telemetry reset` needs the program, so it goes first.

```bash
certistack telemetry reset
rm -f /secure/certistack/controller.env /secure/certistack/controller.env.bak-* \
  /secure/certistack/controller.env.partial \
  /secure/certistack/id_ed25519 /secure/certistack/id_ed25519.pub \
  /secure/certistack/known_hosts /secure/certistack/pve-root-ca.pem \
  /secure/certistack/pbs-access.sh
sudo rm -f /usr/local/bin/certistack /usr/local/bin/certistack.prev
```

Use your setup directory: `/secure/certistack`, or `~/certistack/secure` if that was not writable. The `.bak-*` and
`.partial` files hold secrets. Also delete the encryption key that `CERTISTACK_PBS_KEYFILE` named, if any (setup copies
it as `<storage>.enc`).

After scheduled runs, the files are the `certistack` user's and your shell cannot list them, so run these instead of the
first two commands above (`sh -c` lets root expand the `*`). The first two reset your own answer to the usage
statistics question and the `certistack` user's:

```bash
certistack telemetry reset
sudo -u certistack env XDG_CONFIG_HOME=/var/lib/certistack certistack telemetry reset
sudo sh -c 'rm -f /secure/certistack/controller.env /secure/certistack/controller.env.bak-* \
  /secure/certistack/controller.env.partial /secure/certistack/id_ed25519 /secure/certistack/id_ed25519.pub \
  /secure/certistack/known_hosts /secure/certistack/pve-root-ca.pem /secure/certistack/pbs-access.sh'
```

## What stays

- Your reports and plans (or a `reports` directory beside the setup directory, if setup made one).
- Delete when you like: if you installed by hand, `release-signing-key.gpg` (and the `release-signing-key.gpg~` backup gpg makes), `~/certistack-download`, the downloaded `certistack-validate`, scripts printed by `setup rbac`,
  empty directories, `telemetry.json.lock`, the PBS host key in `~/.ssh/known_hosts`, and secrets in your shell history.
- The node's `libguestfs-tools` and `nftables`, if anything else uses them.
- After scheduled runs: the `certistack` user, `/var/lib/certistack/plans`, and `/var/lib/certistack/certistack`
  (the unit's configuration directory; after the reset it holds only `telemetry.json.lock`).
- After a manual setup: the node's `certistack` account (`userdel -r certistack`), `/etc/sudoers.d/certistack`, and
  `/opt/certistack/releases/<version>`.
