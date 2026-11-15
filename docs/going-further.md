# Going further

You have run the [quickstart](quickstart.md) on one node. This page covers the next things people
want: checking real services, more VMs, clusters, encrypted backups and a few setups that need one
extra step. Each section is short and links to the reference for the detail.

## Check your real services

The first plan only checks that SSH answers. A probe can check what the VM is for instead:

| Probe | Checks |
| --- | --- |
| `tcp` | a port accepts connections |
| `http` | a URL answers with the status you expect (HTTP or HTTPS) |
| `dns` | a name resolves to the address you expect |
| `ldap` | a directory answers (for example an Active Directory domain controller) |
| `mssql` | SQL Server answers at the protocol level |
| `smb` | a file share answers |
| `qga` | a service inside the guest (`systemctl is-active`, `sc query`), its host name, or that the guest agent answers, through the QEMU guest agent |

The network probes (`tcp` to `smb`; the reference calls them *wire probes*) run from the node
over the sandbox network. Let CertiStack suggest probes: `--inspect` looks inside each Linux VM's
newest backup, read-only,
and writes a probe for each service it finds:

```bash
certistack init --env-file /secure/certistack/controller.env --vm 100 --inspect -o web.yaml
```

Every probe and its options are in [The plan file](plan-reference.md).

## Test more VMs at once

Give `--vm` more than once, or use `--all`:

```bash
certistack init --env-file /secure/certistack/controller.env --vm 100 --vm 101 -o app.yaml
```

VMs that depend on each other, such as a database and the web server that uses it, go into
*tiers*: tier 2 starts only after every VM and probe in tier 1 has passed. The node needs free
memory for each VM, so start with two or three ([The plan file](plan-reference.md)).

## Test an older backup

A plan written by `init` uses `snapshot: "latest"`: the newest backup when the run starts. The
report records exactly which one it used. To test an older restore point, set the VM's
`source_pbs.snapshot` to that backup's full path, such as `vm/100/2026-09-27T03:00:07Z`
([The plan file](plan-reference.md)).

## Use a cluster node

CertiStack works on a cluster node. Read the cluster points on What it changes on your node first:
the network reload and the overlay disk
([Things to plan around](what-it-changes.md#things-to-plan-around)), and the shared SSH key
([The access you grant](what-it-changes.md#the-access-you-grant-and-what-limits-it)). To avoid the network reload, create the sandbox network
once yourself and set `network.lifecycle: preprovisioned` in the plan
([how](plan-reference.md#network)); runs then change no SDN configuration.

## Encrypted backups

If the node backs up to an encrypted PBS storage, setup offers to copy its key to the controller
and sets `CERTISTACK_PBS_KEYFILE` in `controller.env`
([what the key allows](what-it-changes.md#the-access-you-grant-and-what-limits-it)). If the key
has a passphrase, add
`PBS_ENCRYPTION_PASSWORD` to `controller.env` yourself ([Settings and files](configuration.md)).

## Limit what the PBS user can read

Setup takes the namespace from the node's PBS storage, or asks for it when you name the PBS
yourself. With a namespace, the read-only user can
only read that namespace. With none, it can read the whole datastore.

Granting a namespace does not take back an earlier grant of the whole datastore. When you run setup
again with a namespace and the user still has setup's earlier grant on the datastore, setup says
`The PBS user can still read every namespace of datastore ...` and asks to remove it (yes is the
default, and `--yes` removes it). To check or remove it by hand, see
[Manual setup](manual-setup.md#3-create-the-pve-token-and-the-read-only-pbs-user).

## Windows guests, and guests that manage their own network

Before a Linux guest boots, CertiStack sets its network to an address inside the sandbox, on the
throwaway overlay. Windows guests keep their own network settings (`init` writes
`network_recovery.mode: preserve` for them); probe them over the network or with the guest agent. Windows Server, Active Directory and SQL Server were tested, and a cold
Windows boot adds a few minutes. A guest with a LUKS-encrypted root disk, or a network
configuration that can't be read offline, is refused before boot with the reason.
[Tested and supported](compatibility.md) lists what each kind of guest gets, and
[The plan file](plan-reference.md) has the settings.

## Install by hand {#install-by-hand}

The one-line installer in the quickstart does exactly this. To check each step yourself, run these
on the controller (a minimal Debian or Ubuntu needs `sudo apt install gnupg git curl` first). The
release public key comes from a clone of the repository at the release tag, not from the release
page:

```bash
mkdir -p ~/certistack-download && cd ~/certistack-download
for f in certistack-linux-amd64 CONTAINER-IMAGE.txt SHA256SUMS-bin.txt SHA256SUMS-bin.txt.asc; do
  curl -fLO "https://github.com/cliftcloud/certistack/releases/download/v0.1.0/$f"
done
sudo install -d -m 0700 -o "$USER" /secure/certistack /var/lib/certistack/reports
git clone --depth 1 --branch v0.1.0 https://github.com/cliftcloud/certistack.git
gpg --no-default-keyring --keyring /secure/certistack/release-signing-key.gpg \
  --import certistack/release/release-public-key.asc
gpg --no-default-keyring --keyring /secure/certistack/release-signing-key.gpg --fingerprint
gpgv --keyring /secure/certistack/release-signing-key.gpg SHA256SUMS-bin.txt.asc SHA256SUMS-bin.txt
sha256sum --strict --check SHA256SUMS-bin.txt
```

Go on only if all three are true:

- the fingerprint reads `C72A BBC9 F354 4A71 FD5D  27A9 5774 80B5 3010 1FD2`;
- `gpgv` prints `Good signature` from the signing subkey ending `F701B3B2C1836DDF`;
- `sha256sum` reports both files `OK`.

Then install it:

```bash
cd ~/certistack-download && sha256sum --strict --check SHA256SUMS-bin.txt && \
  sudo install -m 0755 certistack-linux-amd64 /usr/local/bin/certistack
certistack version
```

To run the download again, delete `~/certistack-download` first.

## Install without sudo

With the installer, choose a directory of yours on your `PATH`; it then needs no `sudo`:

```bash
curl -fsSL https://certistack.dev/install.sh | CERTISTACK_BIN_DIR="$HOME/bin" bash
```

If `certistack` is then not found, run `export PATH="$HOME/bin:$PATH"` or log in again. When setup
asks for its directory, accept `~/certistack/secure`.

By hand, use directories you own:

1. In the first block of [Install by hand](#install-by-hand), replace the `sudo install -d` line by
   `install -d -m 0700 YOUR_DIR`, and `/secure/certistack` in its three `gpg`/`gpgv --keyring`
   paths by `YOUR_DIR`.
2. Install the program into a directory of yours on your `PATH`:
   `install -D -m 0755 certistack-linux-amd64 ~/bin/certistack`. This also creates `~/bin`.

Either way, replace `/secure/certistack` by your directory in every command in these pages, and
pass `--known-hosts YOUR_DIR/known_hosts` to `certistack setup trust-node` if you
[set up by hand](manual-setup.md).

When `/var/lib/certistack/reports` is not writable, setup creates a `reports` directory next to
yours and points `CERTISTACK_OUTPUT_DIR` at it. Read your reports there, with the path the run
prints on its last line.

## Upgrade

1. Let any running job finish. If a run was interrupted, finish its cleanup first
   ([Issue 26](troubleshooting.md#issue-26-lost-contact-with-node)).
2. Run the installer again. It installs the release it names, checks it the same way, and keeps the
   current binary as `/usr/local/bin/certistack.prev`. When the setup directory already holds a
   `controller.env`, it ends with `Next: certistack check --env-file` and that file, not with
   `certistack setup`. To pick a release, add `CERTISTACK_VERSION=v0.1.0` (for example) before `bash`.
3. Run `certistack check --env-file /secure/certistack/controller.env`, then one plan.

To roll back, `sudo install -m 0755 /usr/local/bin/certistack.prev /usr/local/bin/certistack`.
[Set up by hand](manual-setup.md#install-upgrade-and-roll-back-a-release) has a layout that keeps
every release side by side.

## More than one site

Run setup once per site, giving each its own directory, for example
`/secure/certistack/site-a`. Pass that site's `--env-file` to every command, and set
`CERTISTACK_OUTPUT_DIR` in each site's `controller.env` to keep the reports apart. Each node
runs one CertiStack operation at a time; runs on different nodes can overlap. The scheduling script serves every site:
give each site's job its `CERTISTACK_ENV_FILE` ([More than one site](automation.md#more-than-one-site)).

## Run the controller somewhere else

The controller can be a container or a VM template instead of a host you install by hand.
[How it works](architecture.md) describes both. To set up a node without the wizard, one
command at a time (for example with a non-root SSH account), see
[Set up by hand](manual-setup.md).
