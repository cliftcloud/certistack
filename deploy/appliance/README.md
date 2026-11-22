# Controller appliance

A dedicated management VM, built as a PVE template with Packer. It runs the digest-pinned controller image of
[`deploy/controller`](../controller/README.md) under Podman and reaches the nodes over SSH. It is not installed on a
hypervisor.

## Size of the VM

A starting point, not measured capacity.

| | Minimum | Recommended |
| :--- | :--- | :--- |
| vCPU | 2 | 2 |
| Memory | 2048 MiB | 4096 MiB |
| Disk | the source template's disk, plus space for reports | as the minimum, on backed-up storage |

## Build a PVE VM template

Build from a Linux machine that reaches the node's API (port 8006) and the build VM's SSH (port 22). Prerequisites:

1. **Packer** in the [pinned range](#what-is-pinned) ([install](https://developer.hashicorp.com/packer/install)), and
   a private directory for the build's files:

   ```bash
   sudo install -d -m 0700 -o "$USER" /secure/certistack
   ```

2. **A patched Debian or Ubuntu cloud-init source template** in PVE, with `cloud-init` and `qemu-guest-agent`
   installed, enabled at boot and answering, and a cloud-init drive (`qm set <vmid> --ide2 <storage>:cloudinit`). The
   recipe sets `qemu_agent = true`: Packer finds the build VM's address through the guest agent before any provisioner
   runs, so the recipe cannot install the agent for you. On a clone of the template, `qm agent <vmid> ping` run on the
   node prints nothing and exits 0 when the agent answers. If you cannot install the agent, copy the recipe, set
   `qemu_agent = false` and give it an `ssh_host`.
3. **An address for the build VM**: DHCP on the bridge (`bridge`), or a static `build_ip` and `build_gateway`. Packer
   reads the address from the guest agent; without one, the build ends with `Timeout waiting for SSH`.
4. **The node's CA**, which signs the PVE API certificate. Copy `/etc/pve/pve-root-ca.pem` from the node to
   `/secure/certistack/pve-root-ca.pem`, and check that this prints the fingerprint that
   `openssl x509 -noout -fingerprint -sha256 -in /etc/pve/pve-root-ca.pem` prints at the node's console:

   ```bash
   openssl x509 -noout -fingerprint -sha256 -in /secure/certistack/pve-root-ca.pem
   ```

5. **A key pair for this build alone**, without a passphrase, which Packer cannot use. The plugin authorizes it for
   the login user (`root` unless you set `ssh_username`) through the build VM's cloud-init settings, so the source
   template needs no change:

   ```bash
   ssh-keygen -t ed25519 -N '' -C packer-build -f /secure/certistack/packer-build
   ```

6. **A Packer API token** for this build only ([permissions](#packer-token-permissions)).
7. **The controller image digest** from the release asset `CONTAINER-IMAGE.txt`, verified through the signed release
   manifest ([Use the published image](../controller/README.md#use-the-published-image)). The build pulls the image by
   this digest and checks it. To confirm that the registry's tag names the same digest, with skopeo
   (`sudo apt install skopeo` on Debian or Ubuntu):

   ```bash
   skopeo inspect --format '{{.Digest}}' docker://ghcr.io/cliftcloud/certistack-controller:<version>
   ```

Write the inputs to `/secure/certistack/packer.pkrvars.hcl`. Never pass the token secret with `-var`, where other local
users can see it:

```hcl
proxmox_url               = "https://pve-01.example.internal:8006/api2/json"
proxmox_token_id          = "packer@pve!template"
proxmox_token_secret      = "the secret that pveum user token add printed"
proxmox_node              = "pve-01"
source_template           = "debian12-cloudinit"
ssh_private_key_file      = "/secure/certistack/packer-build"
ssh_build_public_key_file = "/secure/certistack/packer-build.pub"
controller_image          = "ghcr.io/cliftcloud/certistack-controller@sha256:<64 hex digits from CONTAINER-IMAGE.txt>"
```

Build from a checkout of the release (`git clone --depth 1 --branch <tag> https://github.com/cliftcloud/certistack.git`),
whose wrapper and files the template installs. `SSL_CERT_FILE` makes the build trust the node's CA, for this command
only:

```bash
cd deploy/appliance/packer
packer init .
SSL_CERT_FILE=/secure/certistack/pve-root-ca.pem packer build -var-file=/secure/certistack/packer.pkrvars.hcl .
```

It ends with `A template was created: 9800`. Then delete the variable file and the key pair, and remove the token
and its grants ([Packer token permissions](#packer-token-permissions)):

```bash
rm -f /secure/certistack/packer.pkrvars.hcl /secure/certistack/packer-build /secure/certistack/packer-build.pub
```

A failed build deletes its VM, and PVE deletes the VM's grant with it: run the `/vms/<template_vmid>` line of
[Packer token permissions](#packer-token-permissions) again before you retry (a grant on `/pool/<pool>` stays).
`PACKER_LOG=1` shows why a wait timed out.

### Inputs

| Input | Required | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `proxmox_url` | Yes | | PVE API endpoint with its path: `https://<host>:8006/api2/json` |
| `proxmox_token_id` | Yes | | Packer-only API token ID |
| `proxmox_token_secret` | Yes | | Token secret (sensitive) |
| `proxmox_node` | Yes | | Node that owns the source template |
| `source_template` | Yes | | The source template's name, not its VM ID |
| `ssh_private_key_file` | Yes | | Build-only private key |
| `ssh_build_public_key_file` | Yes | | Its public half |
| `controller_image` | Yes | | `registry-host/repository@sha256:<64 lowercase hex digits>` |
| `template_name` | No | `certistack-controller` | |
| `template_vmid` | No | `9800` | Must be unused |
| `bridge` | No | `vmbr0` | The build VM's and the template's network bridge |
| `build_ip` | No | none | The build VM's static address with prefix length, such as `192.0.2.50/24`; none means DHCP |
| `build_gateway` | No | none | Gateway for `build_ip` |
| `scsi_controller` | No | `virtio-scsi-single` | The plugin's own `lsi` has no driver in Debian's cloud kernel |
| `cloud_init_storage_pool` | No | `local-lvm` | Storage for the template's cloud-init drive |
| `pool` | No | none | PVE resource pool |
| `task_timeout` | No | `10m` | Wait for one PVE task, such as the full clone; a timed-out client does not stop the task, so check the node's task list before you retry |
| `memory` | No | `2048` | MiB, at least 2048 |
| `cores` | No | `2` | Per socket, at least 2 |
| `sockets` | No | `1` | |
| `cpu_type` | No | `x86-64-v2-AES` | `host` only on one node or identical hardware |
| `os` | No | `l26` | PVE guest OS type |
| `ssh_username` | No | `root` | The provisioners assume root |
| `insecure_skip_tls_verify` | No | `false` | Only for an isolated build environment |

### What the build checks

The first provisioner waits for the source template's first-boot cloud-init to finish before it installs `podman`,
`tini` and the CA certificates and pulls the image. The last, `files/finalize-template.sh`, runs in the build VM, and any
failure fails the build. It:

- resets cloud-init state and the machine ID, and removes the SSH host keys and the journals, so each clone makes its
  own. `/etc/machine-id` stays, empty: without it a clone boots with no network. journald writes to `/run` from then
  on, so the build VM's shutdown leaves no journal in the template;
- removes the build key from every `authorized_keys` file under `/root/.ssh`, the home directories and `/etc/ssh`, and
  fails if a second search finds it. The search follows no symbolic links, so a link in those paths fails the build;
  remove it from the source template. Other keys in the source template stay;
- checks the pulled image against the `controller_image` digest before `/etc/certistack/controller-image` records it;
- writes `/etc/certistack/build-manifest`: the controller image, Packer version, OS release and every installed package
  with its version.

The template keeps an empty cloud-init drive, and its description names the controller image.

### What is pinned

The recipe pins the controller image by digest, Packer with `required_version = ">= 1.14.2, < 2.0.0"` and the Proxmox
plugin to exactly `= 1.2.4`. The source template and the distribution packages are not pinned.

## Packer token permissions

This token is not read-only: it clones, configures, starts and stops the VM and converts it to a template. Keep a user
and a role for template builds only, give each build its own privilege-separated token that expires, and remove the
token after the build. PVE checks such a token against both the token and its user, so grant the role to each.

Grant the role on four paths: the source template (`/vms/<its VM ID>`), the build VM (`/vms/<template_vmid>`, or
`/pool/<pool>` when `pool` is set), the storage of the clone and of the cloud-init drive (`/storage/<storage>`) and the
network (`/sdn/zones/localnetwork/<bridge>`, or `/sdn/zones/<zone>/<vnet>`). For example, with `9000` the source
template and `9800` the new one:

```bash
pveum role add PackerTemplateBuilder --privs "VM.Audit VM.Clone VM.Allocate VM.Config.CPU VM.Config.Memory VM.Config.HWType VM.Config.Options VM.Config.Disk VM.Config.Network VM.Config.Cloudinit VM.Config.CDROM VM.PowerMgmt VM.GuestAgent.Audit Datastore.AllocateSpace Datastore.Audit SDN.Use"
pveum user add packer@pve --comment "CertiStack template build"
pveum user token add packer@pve template --privsep 1 --expire "$(date -d '+1 day' +%s)"
pveum acl modify /vms/9000 --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
pveum acl modify /vms/9800 --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
pveum acl modify /storage/local-lvm --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
pveum acl modify /sdn/zones/localnetwork/vmbr0 --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
```

`token add` prints the secret once; write it into the variable file. Check each path with
`pveum user token permissions packer@pve template --path <path>`. After the build, remove the token's grants on the
same four paths, then the token. A token removed first leaves its grants behind, and every `pveum` and `qm` command
then warns `ignore invalid acl token`:

```bash
for path in /vms/9000 /vms/9800 /storage/local-lvm /sdn/zones/localnetwork/vmbr0; do
  pveum acl delete "$path" --roles PackerTemplateBuilder --tokens 'packer@pve!template'
done
pveum user token remove packer@pve template
```

For a later build, add a new token and run the four `acl modify` lines again, with an unused `template_vmid` while the
old template exists; the role and the user stay. Remove them when you build no more templates
([Remove the appliance](#remove-the-appliance)).

The role covers the calls plugin 1.2.4 makes on PVE 9.x. If PVE denies a call (`403 Permission check failed`), add the
privilege it names on that path, and never use an administrator or root-scoped token.

## First boot

As root on the node, clone the template and give the clone its login and address before its first start: your SSH
public key (copied to the node) for the image's default user (`debian` on Debian, `ubuntu` on Ubuntu), and a static
address or `ip=dhcp`. For the recommended memory, also run `qm set 120 --memory 4096`:

```bash
qm clone 9800 120 --name certistack-appliance --full
qm set 120 --sshkeys /root/operator.pub --ipconfig0 ip=192.0.2.20/24,gw=192.0.2.1
qm start 120
```

Then prepare the node and its access, as root on the node and on the PBS: [step 1 of Set up by
hand](https://certistack.dev/docs/manual-setup/#1-prepare-the-node) (the packages and the overlay storage) and [the plain
commands of The PVE role and its permissions](https://certistack.dev/docs/manual-setup/#the-pve-role-and-its-permissions)
(the PVE token and the read-only PBS user). Keep the two secrets they print. `certistack setup` cannot do this from the
appliance: the wrapper gives the container no terminal and mounts its secrets read-only.

On the appliance, as the default user, make the controller's key pair and read the node's host key in a private
directory. Use the node's address as `controller.env` will spell it:

```bash
install -d -m 0700 ~/certistack-setup && cd ~/certistack-setup
ssh-keygen -t ed25519 -N '' -C certistack-controller -f id_ed25519
ssh-keyscan -t ed25519 pve-01.example.internal > known_hosts
ssh-keygen -lf known_hosts
```

Go on only if its `SHA256:...` is what `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` prints at the node's console.
Authorize the key for root: `ssh-copy-id` asks for root's password; if the node refuses passwords, append
`id_ed25519.pub` to its `/root/.ssh/authorized_keys` yourself. Then test the login, which prints `x86_64`, copy the
node's CA, and start the environment file from the template's example:

```bash
ssh-copy-id -o StrictHostKeyChecking=yes -o UserKnownHostsFile=known_hosts \
  -i id_ed25519.pub root@pve-01.example.internal
ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=known_hosts -o IdentitiesOnly=yes \
  -i id_ed25519 root@pve-01.example.internal uname -m
scp -o StrictHostKeyChecking=yes -o UserKnownHostsFile=known_hosts -o IdentitiesOnly=yes \
  -i id_ed25519 root@pve-01.example.internal:/etc/pve/pve-root-ca.pem pve-ca.pem
sudo cat /etc/certistack/secrets/controller.env.example > controller.env
```

Edit `controller.env`: the node's name and address, the PBS repository, the two secrets and the overlay storage. A
stock setup also needs both of its commented-out lines:

- `PBS_FINGERPRINT`: a default PBS certificate is self-signed. Fill in the fingerprint from the PBS dashboard (Show
  Fingerprint) or `proxmox-backup-manager cert info`.
- `CERTISTACK_PVE_CA_SOURCE`: a stock Proxmox VE node signs its API certificate with the cluster's own CA, which the
  container does not trust, so it reads `pve-ca.pem`. While this line is active, a missing `pve-ca.pem` stops every
  run before the transfer. A node whose certificate a public CA signed needs neither.

Install the files with `install`, which sets the owner a plain copy would not: UID/GID `65532` (the container's user),
mode 0600:

```bash
sudo install -m 0600 -o 65532 -g 65532 controller.env id_ed25519 known_hosts pve-ca.pem /etc/certistack/secrets/
```

Then delete the working copies: `cd && rm -rf ~/certistack-setup`.

The example environment file connects as root; for another account, see
[the sudoers rule for a non-root account](https://certistack.dev/docs/manual-setup/#the-sudoers-rule-for-a-non-root-account).

### First run

Check the controller, write a first plan into `/var/lib/certistack/plans`, run it and read its report. `init` with no
`--vm` lists the VMs that have backups. Before the run, make the changes `init` asks for with
`sudoedit /var/lib/certistack/plans/my-first-plan.yaml`:

```bash
sudo certistack-controller check
sudo certistack-controller init
sudo certistack-controller init --vm 100 -o /var/lib/certistack/plans/my-first-plan.yaml
sudo certistack-controller run /var/lib/certistack/plans/my-first-plan.yaml
sudo certistack-controller report show
```

Run every command as root; the wrapper refuses any other user. The container starts with an empty environment, so the
wrapper passes `--env-file /run/certistack-secrets/controller.env` to `run`, `plan`, `doctor`, `init`, `check` and
`validate`. Because `validate` loads the file too, `sudo certistack-controller validate plan.yaml` needs
`/etc/certistack/secrets/controller.env` to exist; without it, it fails with "open controller environment file: open
/run/certistack-secrets/controller.env: no such file or directory". The file supplies the credentials and the node and
SSH settings; a flag such as `--node` overrides it.

The commands the controller prints as next steps are written for the `certistack` program. On the appliance, type them
as `sudo certistack-controller ...`; the `--env-file /run/certistack-secrets/controller.env` they may name is the file
the wrapper passes anyway.

Reports stay in `/var/lib/certistack/reports`. Usage statistics are off by default; see
[usage statistics](https://certistack.dev/docs/telemetry/).

## Upgrade and roll back

The appliance runs the image named in `/etc/certistack/controller-image`, and the wrapper never pulls one, so an upgrade
pulls the verified digest before it switches the reference.

The reference selects the controller image and nothing else. The `certistack-controller` wrapper and the example
environment file are installed from the template, not from the image, so a new image does not carry a change to either.
A release that changes them says so in its release notes. The change reaches an appliance only from a rebuilt template
([Patch the appliance's operating system](#patch-the-appliances-operating-system)): an image-only upgrade of an
appliance built from an older template keeps its older wrapper.

Let running jobs finish (`pgrep -af '[c]ertistack-controller-job'` prints nothing when none is running) and recover any
run that reported an incomplete teardown ([Issue 35](https://certistack.dev/docs/troubleshooting/#issue-35)). On a
workstation, verify the release's assets through the signed manifest
([Use the published image](../controller/README.md#use-the-published-image)), and copy the verified
`CONTAINER-IMAGE.txt`, which holds the reference, to the appliance. Pull it into root's Podman store; the last command
succeeds only if the stored digest is the one in the reference:

```bash
new=$(cat CONTAINER-IMAGE.txt)
sudo podman pull "$new"
test "$(sudo podman image inspect --format '{{.Digest}}' "$new")" = "${new#*@}"
```

Then switch the reference. Each command runs only if the one before it succeeded; the old reference is kept as
`controller-image.previous`, and the new one replaces it atomically. The last command starts the new image:

```bash
new=$(cat CONTAINER-IMAGE.txt)
printf '%s' "$new" | grep -Eq '^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+@sha256:[a-f0-9]{64}$' &&
  sudo podman image exists "$new" &&
  sudo cp -p /etc/certistack/controller-image /etc/certistack/controller-image.previous &&
  printf '%s\n' "$new" | sudo tee /etc/certistack/controller-image.next >/dev/null &&
  sudo chmod 0644 /etc/certistack/controller-image.next &&
  sudo mv /etc/certistack/controller-image.next /etc/certistack/controller-image &&
  sudo certistack-controller version
```

Judge a passing plan's report (`sudo certistack-controller verify-report --unsigned --expect-outcome pass <report>`)
before you rely on the new image. To roll back, restore the previous reference:

```bash
sudo cp -p /etc/certistack/controller-image.previous /etc/certistack/controller-image.rollback &&
  sudo mv /etc/certistack/controller-image.rollback /etc/certistack/controller-image &&
  sudo certistack-controller version
```

Keep the previous image: do not run `podman rmi` or `podman image prune` on it. Never delete a report, a recovery
journal or a worker workspace to force a rollback.

## Patch the appliance's operating system

The supported model is replacement, not in-place patching. The kernel, Podman, OpenSSH client and trust store come from
the template, so rebuild it from a patched source template and deploy a new VM from it.

1. Patch the source template when your distribution publishes a security update for the kernel, Podman, OpenSSH or
   `ca-certificates`, and rebuild the appliance template under an unused `template_vmid`, such as `9801`, with a new
   token and its grants ([Packer token permissions](#packer-token-permissions)). Its `/etc/certistack/build-manifest`
   lists what it contains.
2. Clone a new VM as in [First boot](#first-boot), and copy `/etc/certistack/secrets` and `/var/lib/certistack` from
   the old VM, with their owners, through your workstation. The archive holds `controller.env` and the controller's
   key, which is root on the node: create it readable by you alone, and shred it afterwards. If both VMs use one
   address, power the old VM off after the first command, and only then start the new one:

   ```bash
   (umask 077; ssh debian@old-appliance 'sudo tar -C / -cpf - --exclude=controller.env.example etc/certistack/secrets var/lib/certistack' > appliance-state.tar)
   ssh debian@new-appliance 'sudo tar -C / -xpf -' < appliance-state.tar
   shred -u appliance-state.tar
   ```

3. Verify it: `sudo certistack-controller version`, then a plan that should pass, with its report judged.
4. Keep the old VM, powered off, while you may want to roll back to it (powering it on is the rollback), then destroy
   it and the old template.

Do not run `apt upgrade`, or reboot, while a job is running, and first recover any run that reported an incomplete
teardown. If the source template enables unattended upgrades, turn off their automatic reboot
(`Unattended-Upgrade::Automatic-Reboot "false"`).

## Remove the appliance

1. Let running jobs finish (`pgrep -af '[c]ertistack-controller-job'` prints nothing), and copy off the reports in
   `/var/lib/certistack/reports` that you keep.
2. Take back CertiStack's access with steps 2 to 4 of
   [Remove CertiStack](https://certistack.dev/docs/manual-setup/#remove-certistack), as root on the node and the PBS.
   Then, on the appliance, this must say `Permission denied (publickey...)`:

   ```bash
   sudo ssh -i /etc/certistack/secrets/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes \
     -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/certistack/secrets/known_hosts \
     root@pve-01.example.internal true
   ```

3. As root on the node, destroy the appliance and each template you built, and the Packer user and role:

   ```bash
   qm stop 120 && qm destroy 120 --purge
   qm destroy 9800 --purge
   pveum user delete packer@pve
   pveum role delete PackerTemplateBuilder
   ```

4. On the build machine, delete the node's CA copy (`rm -f /secure/certistack/pve-root-ca.pem`) and the release
   checkout. If nothing else uses them, also remove Packer's plugin (`rm -rf ~/.config/packer`), uninstall Packer and
   skopeo (`sudo apt remove packer skopeo` when apt installed them), and remove the private directory
   (`sudo rmdir /secure/certistack`, which fails while it holds other files).
