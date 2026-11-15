# Quickstart

This page takes you from nothing to your first restore-test report, on one standalone Proxmox VE
node. A first test run on a small VM takes about 6 to 20 minutes, mostly reading the backup from
PBS.

## Before you start

You need:

- **A Proxmox VE node** (9.x or 8.4, see [supported versions](compatibility.md#supported-versions))
  you can SSH to as root. A standalone node is best for a first run
  ([why](what-it-changes.md#things-to-plan-around)).
- **A Proxmox Backup Server** (3.x or 4.x) that the node can reach, with a recent backup of a
  **small Linux VM** (under about 20 GiB, with `sshd` on port 22).
- **A Linux machine to run CertiStack from**, called the *controller*: a small Debian or Ubuntu
  VM. A VM on the same node is fine, but not the Proxmox VE host itself, and not your everyday
  workstation ([why](what-it-changes.md#the-access-you-grant-and-what-limits-it)).
- **Free space on the node** for the VM's disk size plus 5 GiB, and **free VM IDs from 9100 up**.

Setup gives the controller root on the node and creates an API token that can manage VMs. Read
[What it changes on your node](what-it-changes.md) (two minutes) so you know what you are agreeing
to.

The examples use `pve-node-01.example.com` for the node and `pbs.example.com` with datastore
`datastore1` for the PBS. Use your own names.

## 1. Install the CLI {#1-install-the-cli-on-the-controller}

On the controller (not the Proxmox VE host), run:

```bash
curl -fsSL https://certistack.dev/install.sh | bash
```

The installer downloads the v0.1.0 release and checks it before it installs anything:

- the GPG signature, against the release key's fingerprint
  `C72A BBC9 F354 4A71 FD5D  27A9 5774 80B5 3010 1FD2`, which is written into the script;
- the checksums of the downloaded files.

If both pass, it installs `certistack` into `/usr/local/bin` (`sudo` asks for your password) and
creates `/secure/certistack` and `/var/lib/certistack/reports` for the next step. It prints the
version it installed:

```text
certistack v0.1.0
  commit:    <the release's commit>
  built:     <build time>
  go:        go1.26.11
  os/arch:   linux/amd64
```

On a minimal Debian or Ubuntu, run `sudo apt install curl gnupg` first: without `curl` the line
stops with a `curl` not-found error, and the installer names anything else it needs. You can
[read the script](https://github.com/cliftcloud/certistack/blob/v0.1.0/scripts/install.sh) before
you run it, or [install by hand](going-further.md#install-by-hand), checking each step yourself.

## 2. Run the setup {#2-run-the-setup}

```bash
certistack setup
```

Setup asks before every change it makes on the node and the PBS (on the controller it writes its
files into the directory you give it):

1. It connects to the node and shows the node's SSH host key.
2. It installs the packages a run needs on the node (`libguestfs-tools` and `nftables`), after it shows what `apt` would install, upgrade and remove.
3. It adds an overlay storage for the sandbox's disks (`/var/lib/vz/certistack-scratch` on a
   standalone node).
4. It creates a PVE API token and a read-only PBS user.
5. It writes `/secure/certistack/controller.env`.
6. It runs `certistack check` to prove it all works.

It never shows a secret. Press Enter to accept a default (shown in `[brackets]`); a `[Y/n]`
question defaults to yes. These need an answer from you, in this order:

1. **The node's name or IP address**, as the controller reaches it over SSH.
2. **The host key.** Before you type `yes`, open the node's shell in the PVE web UI and run
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. The two `SHA256:...` strings must match.
3. **Root's password on the node, once**, so `ssh-copy-id` can authorize the controller's key. The
   question says what that grants: the key signs in as root on this node, and on a cluster, where
   root's `authorized_keys` is shared, as root on every node
   ([The access you grant](what-it-changes.md#the-access-you-grant-and-what-limits-it)).
4. **Where the PBS is**: its host name as the node reaches it, the datastore and the namespace.
   If the node already backs up to that PBS, setup lists it and you pick a number (the default is
   marked), and it takes the namespace from there. When you name the PBS yourself and your backups
   are in a PBS namespace, give it. An empty answer asks `Continue?` (the default is no), because
   the PBS user can then read every namespace of the datastore.
5. **The PBS's host key**, which `ssh` asks you to confirm (`Are you sure you want to continue
   connecting`). Check it the same way, in the PBS web UI's shell (Administration, Shell), before you
   type `yes`.
6. **Root's password on the PBS**, when setup runs its one script there over SSH. Or answer `n` to
   running it over SSH, and setup gives you a file to paste into the PBS web shell instead (type `sh`
   first, and `exit` after). Then paste back the token secret the script printed (only the string
   after `"value":`; the prompt does not echo it) and, if setup asks, the PBS certificate's
   fingerprint (PBS dashboard, Show Fingerprint).

Setup is done when the check passes:

```text
  ✓ 1. Environment file  /secure/certistack/controller.env, mode 0600, the 5 required variables are set
  ✓ 2. SSH files         identity /secure/certistack/id_ed25519; /secure/certistack/known_hosts has an entry for pve-node-01.example.com
  ✓ 3. SSH connection    ssh to root@pve-node-01.example.com works without a prompt, with strict host-key checking; the node reports x86_64
  ✓ 4. Node tools        found on the node: qemu-img, proxmox-backup-client, guestfish, ip, nft
  ✓ 5. PVE API           the node reaches the PVE API and PVE accepts the token (Proxmox VE 9.2.2)
  ✓ 6. PBS               the PBS credential lists the repository: 2 VMs have a complete backup

✓ Every layer passed.
```

If a layer fails, it prints the fix. Apply it, then run
`certistack check --env-file /secure/certistack/controller.env` again. Every question and flag of
setup is in the [command reference](cli-reference.md#setup).

## 3. Write your first plan {#3-write-your-first-plan}

A *plan* is a small YAML file that says which VM to restore and what to check once it boots.
List the VMs that have a backup:

```bash
certistack init --env-file /secure/certistack/controller.env
```

```text
VMID  NOTES   NEWEST BACKUP         BACKUPS  DISKS
100   web-01  2026-09-27 03:00 UTC  14       32 GiB
102   dns-01  2026-09-27 03:06 UTC  14       12 GiB
```

Write a plan for a small one:

```bash
certistack init --env-file /secure/certistack/controller.env --vm 102 -o my-first-plan.yaml
```

`init` first says what a run of the plan will read and reserve:

```text
The plan restores 1 VM(s). A run of it:
  reads 12 GiB of backup disks, each in full
  takes about 4 min (reading at 100 MB/s, a rate measured on older servers, plus 2 minutes to prepare each VM; a faster node takes less)
  reserves 2.2 GiB of the node's RAM while it runs (each VM's memory plus 256 MiB)
```

The plan is valid as it is, and needs no edit. `frameworks: [NONE]` means the report names no
standard; replace it only to name one such as SOC2. The probe marked `CHANGE` checks that SSH
answers on port 22; leave it as it is for this first test. `init` also asks once about anonymous
usage statistics; pressing Enter keeps them off.

## 4. Run it {#4-run-it}

First, see what the run will do. This changes nothing:

```bash
certistack plan my-first-plan.yaml --env-file /secure/certistack/controller.env
```

A line with `✗` means the run would be refused; fix it first. Lines with `!` are advice. Then run it:

```bash
certistack run my-first-plan.yaml --env-file /secure/certistack/controller.env
```

The run maps the backup read-only, boots a copy of the VM in an isolated network, checks it,
removes everything again and writes a report. Run it inside `tmux` or `screen` so a dropped
connection does not stop it. If you must stop it, press Ctrl-C **once** and let it clean up; a
second Ctrl-C leaves the cleanup to `certistack recover`
([Issue 26](troubleshooting.md#issue-26-lost-contact-with-node)).

## 5. Read the report {#5-read-the-report}

The run's last line is the command that shows its report. With the default report directory, this
shows the newest one:

```bash
certistack report show "$(ls -t /var/lib/certistack/reports/*/*.json | head -n 1)"
```

```text
Outcome:       PASS (as the file states)
Validation:    full_integrity: every mapped disk image was read back and checksummed
...
  VM 9100 "dns-01"  PASS
    Integrity:         scsi0 verified, sha256 c8c983df...
    Probes (1):
      PASS tcp 192.0.2.10:22  (from the worker host over the sandbox network, 1m 19s, 1 attempt)
...
Teardown:
  cleanup verified (at 2026-09-27T04:17:03Z)
```

A good run shows `Outcome: PASS`, every disk `verified`, every probe `PASS`, and
`cleanup verified`. That means the backup restored, the VM booted, SSH answered, and nothing was
left behind on the node.

If the outcome is `FAIL`, the report names the probe and the reason. On a first run it is almost
always the guest itself: its firewall does not allow SSH from the sandbox network, or `sshd` does
not start at boot. [A probe fails on a first run](troubleshooting.md#issue-45-a-probe-fails-on-a-first-run)
has the fix.

## Next

- Check your real services (HTTP, DNS, SQL Server and more) and test more VMs:
  [Going further](going-further.md) and [The plan file](plan-reference.md).
- Run it every night with an alert when it fails: [Run it on a schedule](automation.md).
- Keep reports as evidence: [Reports](reports.md).
- Something went wrong: [When something fails](troubleshooting.md).
- Take it all back off the node: [Remove CertiStack](undo.md).
