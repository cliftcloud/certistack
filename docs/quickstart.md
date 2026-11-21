# Quickstart

From nothing to your first restore-test report on one standalone Proxmox VE node. A first run on a small VM takes about
6 to 20 minutes, mostly reading the backup from PBS.

## Before you start

- **A Proxmox VE node** ([9.x or 8.4](compatibility.md#supported-versions)), standalone for a first run, that you can
  SSH to as root.
- **A PBS** (3.x or 4.x) the node can reach, with a recent backup of a **small Linux VM** (under about 20 GiB, `sshd`
  on port 22).
- **A controller**: a small Debian or Ubuntu VM. It may run on the same node, but not on the Proxmox VE host itself or
  your workstation: it keeps an SSH key that is root on the node, and the API token.
- **Free space on the node** for the VM's disk size plus 5 GiB, and **free VM IDs from 9100 up**.

Setup gives the controller root on the node and an API token that can manage VMs: read
[What it changes](manual-setup.md#what-it-changes) first.

<a id="1-install-the-cli-on-the-controller"></a>

## 1. Install the CLI

On the controller:

```bash
curl -fsSL https://certistack.dev/install.sh | bash
```

The installer checks the release's GPG signature and checksums, installs `certistack` into `/usr/local/bin`, and
creates `/secure/certistack` and `/var/lib/certistack/reports`. A minimal Debian or Ubuntu needs
`sudo apt install curl gnupg` first. To check each step yourself, [install by hand](#install-by-hand).

## 2. Run the setup

```bash
certistack setup
```

Setup asks before each change, adds an overlay storage for the sandbox's disks (`/var/lib/vz/certistack-scratch` on a
standalone node), writes `/secure/certistack/controller.env`, and ends by running `certistack check`. Enter accepts the
default in `[brackets]`.

You answer, in this order:

1. **The node's name or IP address**, as the controller reaches it.
2. **The node's host key.** Before you type `yes`, run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` in the
   node's shell (PVE web UI). The `SHA256:...` strings must match.
3. **Root's password on the node, once**, so `ssh-copy-id` can authorize the controller's key. On a cluster, root's
   `authorized_keys` is shared, so the key is root on every node.
4. **Where the PBS is**: host name (as the node reaches it), datastore and namespace, or pick the node's PBS storage
   from the list. With no namespace the PBS user can read the whole datastore, so setup asks `Continue?` (default
   no): answer `y` if your backups are in the root namespace.
5. **The PBS's host key**, which `ssh` asks you to confirm. Check it the same way, in the PBS web UI's shell.
6. **Root's password on the PBS**, to run one script there. Or answer `n`: setup writes the script for you to paste
   into the PBS web shell, then asks for the token secret it printed (the string after `"value":`).

Setup also asks before each change it makes: installing packages (it lists what apt will install and upgrade), adding
the overlay storage, creating the PVE role, user and token, and running the PBS script. Enter accepts each. When you pick the
node's PBS storage, setup takes the PBS's TLS fingerprint from it, so it trusts the PBS the node already trusts.

For an encrypted PBS storage, setup offers to copy its key (default no); a passphrase goes in `controller.env` as
`PBS_ENCRYPTION_PASSWORD`.

Setup is done when its check ends with `✓ Every layer passed.` Otherwise apply the fix it prints and run
`certistack check` again. The commands below use the `controller.env` setup wrote; `--env-file` chooses another.

## 3. Write your first plan

A *plan* is a YAML file that says which VM to restore and what to check. List the VMs that have a backup:

```bash
certistack init
```

Write a plan for a small one, here VM 102:

```bash
certistack init --vm 102 -o my-first-plan.yaml
```

`init` estimates the run's time and RAM (the VM's memory plus 256 MiB). The plan needs no edit: its probe checks that SSH answers on port 22. `init` also asks once about
[usage statistics](telemetry.md); Enter keeps them off.

## 4. Run it

See what the run will do. This changes nothing:

```bash
certistack plan my-first-plan.yaml
```

Fix any `✗` line first; `!` lines are advice. Then run it inside `tmux` or `screen`, so a dropped connection does not
stop it:

```bash
certistack run my-first-plan.yaml
```

To stop it, press Ctrl-C **once** and let it clean up. A second Ctrl-C leaves the cleanup to `certistack recover`
([Issue 35](troubleshooting.md#issue-35)).

## 5. Read the report

The run's last line is the command that shows its report. With no file named, it shows the newest:

```bash
certistack report show
```

```text
Outcome:       PASS (as the file states)
...
  VM 9100 "dns-01"  PASS
    Integrity:         scsi0 verified, sha256 c8c983df...
    Probes (1):
      PASS tcp 192.0.2.10:22  (from the worker host over the sandbox network, 1m 19s, 1 attempt)
...
Teardown:
  cleanup verified (at 2026-09-27T04:17:03Z)
```

`PASS`, every disk `verified` and `cleanup verified` mean the backup restored, the VM booted, SSH answered, and nothing
was left on the node. A first-run `FAIL` is almost always the guest: its firewall blocks SSH from the sandbox network,
or `sshd` does not start at boot ([Issue 22](troubleshooting.md#issue-22)).

## Install by hand

On the controller (a minimal Debian or Ubuntu needs `sudo apt install gnupg git curl` first):

```bash
mkdir -p ~/certistack-download && cd ~/certistack-download
for f in certistack-linux-amd64 CONTAINER-IMAGE.txt SHA256SUMS-bin.txt SHA256SUMS-bin.txt.asc; do
  curl -fLO "https://github.com/cliftcloud/certistack/releases/download/v0.1.1/$f"
done
sudo install -d -m 0700 -o "$USER" /secure/certistack /var/lib/certistack/reports
git clone --depth 1 --branch v0.1.1 https://github.com/cliftcloud/certistack.git
gpg --no-default-keyring --keyring /secure/certistack/release-signing-key.gpg \
  --import certistack/release/release-public-key.asc
gpg --no-default-keyring --keyring /secure/certistack/release-signing-key.gpg --fingerprint
gpgv --keyring /secure/certistack/release-signing-key.gpg SHA256SUMS-bin.txt.asc SHA256SUMS-bin.txt
sha256sum --strict --check SHA256SUMS-bin.txt
```

Go on only if the fingerprint reads `C72A BBC9 F354 4A71 FD5D  27A9 5774 80B5 3010 1FD2`, `gpgv` prints
`Good signature` from the subkey ending `F701B3B2C1836DDF`, and `sha256sum` reports both files `OK`. Then:

```bash
cd ~/certistack-download && sha256sum --strict --check SHA256SUMS-bin.txt && \
  sudo install -m 0755 certistack-linux-amd64 /usr/local/bin/certistack
certistack version
```

To download again, delete `~/certistack-download` first.

## Install without sudo

Give the installer a directory of yours on your `PATH`:

```bash
curl -fsSL https://certistack.dev/install.sh | CERTISTACK_BIN_DIR="$HOME/bin" bash
```

If `certistack` is not found, run `export PATH="$HOME/bin:$PATH"`. When setup asks for its directory, accept
`~/certistack/secure`; reports then go to a `reports` directory next to it. By hand, in the first block above, replace
the `sudo install -d` line by `install -d -m 0700 YOUR_DIR` and `/secure/certistack` in the three `--keyring` paths by
`YOUR_DIR`, then `install -D -m 0755 certistack-linux-amd64 ~/bin/certistack`.

Either way, use your directory for `/secure/certistack` in every command.

## Upgrade

Finish or recover every run first. Run the installer again; it keeps the current binary as
`/usr/local/bin/certistack.prev` (to pick a release, put `CERTISTACK_VERSION=v0.1.1` before `bash`). Then run
`certistack check` and one plan. To roll back:
`sudo install -m 0755 /usr/local/bin/certistack.prev /usr/local/bin/certistack`.

## Next

- Real services, several VMs, tiers, an older backup: [Plans](plan-reference.md). `init --inspect` writes a
  probe for each service it finds in a Linux VM's backup.
- A cluster node: read [What it changes](manual-setup.md#what-it-changes) first, or use a
  [pre-provisioned sandbox](plan-reference.md#use-a-pre-provisioned-sandbox).
- Several sites: one setup directory per site. The last setup is the default; pass `--env-file` for the others.
- [Troubleshooting](troubleshooting.md), [Remove CertiStack](manual-setup.md#remove-certistack).
