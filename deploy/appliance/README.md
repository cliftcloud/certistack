# Controller appliance

A dedicated management VM, built as a PVE template with Packer. It runs the digest-pinned controller image of
[`deploy/controller`](../controller/README.md) under Podman and reaches the nodes over SSH. It is not installed on a
hypervisor. The recipe has not yet been built against a live PVE.

## Size of the VM

A starting point, not measured capacity.

| | Minimum | Recommended |
| :--- | :--- | :--- |
| vCPU | 2 | 2 |
| Memory | 2048 MiB | 4096 MiB |
| Disk | the source template's disk, plus space for reports | as the minimum, on backed-up storage |

## Build a PVE VM template

Prerequisites:

1. **A patched Debian or Ubuntu cloud-init source template** in PVE, with `cloud-init` and `qemu-guest-agent`
   installed, enabled at boot and answering. The recipe sets `qemu_agent = true`: Packer finds the build VM's address
   through the guest agent before any provisioner runs, so the recipe cannot install the agent for you. On a clone of
   the template, `qm agent <vmid> ping` run on the node prints nothing and exits 0 when the agent answers. If you cannot
   install the agent, copy the recipe, set `qemu_agent = false` and give it an `ssh_host`.
2. **A key pair for this build alone** (`ssh-keygen -t ed25519`), authorized in the source template for the login user
   (`root` unless you set `ssh_username`). Afterwards, delete the pair and remove its public key from the source template.
3. **A Packer API token** for this build only ([permissions](#packer-token-permissions)).
4. **The controller image digest** from the release asset `CONTAINER-IMAGE.txt`, verified through the signed release
   manifest ([Use the published image](../controller/README.md#use-the-published-image)) and confirmed against the
   registry:

   ```bash
   docker buildx imagetools inspect ghcr.io/cliftcloud/certistack-controller:<version>
   ```

Put the inputs in a variable file outside this checkout, readable by you alone; never pass the token secret with `-var`,
where other local users can see it. Build the template, then delete the file, the build private key and the token:

```bash
cd deploy/appliance/packer
packer init .
packer build -var-file=/secure/certistack/packer.pkrvars.hcl .
```

### Inputs

| Input | Required | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `proxmox_url` | Yes | | PVE API endpoint |
| `proxmox_token_id` | Yes | | Packer-only API token ID |
| `proxmox_token_secret` | Yes | | Token secret (sensitive) |
| `proxmox_node` | Yes | | Node that owns the source template |
| `source_template` | Yes | | Name or ID |
| `ssh_private_key_file` | Yes | | Build-only private key |
| `ssh_build_public_key_file` | Yes | | Its public half |
| `controller_image` | Yes | | `registry-host/repository@sha256:<64 lowercase hex digits>` |
| `template_name` | No | `certistack-controller` | |
| `template_vmid` | No | `9800` | Must be unused |
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

The last provisioner, `files/finalize-template.sh`, runs in the build VM, and any failure fails the build. It:

- resets cloud-init state and the machine ID, so each clone makes its own;
- removes the build key from every `authorized_keys` file under `/root/.ssh`, the home directories and `/etc/ssh`, and
  fails if a second search finds it. The search follows no symbolic links, so a link in those paths fails the build;
  remove it from the source template. Other keys in the source template stay;
- checks the pulled image against the `controller_image` digest before `/etc/certistack/controller-image` records it;
- writes `/etc/certistack/build-manifest`: the controller image, Packer version, OS release and every installed package
  with its version.

### What is pinned

The recipe pins the controller image by digest, Packer with `required_version = ">= 1.14.2, < 2.0.0"` and the Proxmox
plugin to exactly `= 1.2.4`. The source template and the distribution packages are not pinned.

## Packer token permissions

This token is not read-only: it clones, configures, starts and stops the VM and converts it to a template. Use a
separate user and a privilege-separated token for each build, let it expire, and remove it afterwards. PVE checks such
a token against both the token and its user, so grant the role to each.

Grant the role on four paths: the source template (`/vms/<source VM ID>`), the build VM (`/vms/<template_vmid>`, or
`/pool/<pool>` when `pool` is set), the clone's storage (`/storage/<storage>`) and its network
(`/sdn/zones/localnetwork/<bridge>`, or `/sdn/zones/<zone>/<vnet>`). For example, with `9000` the source template and
`9800` the new one:

```bash
pveum role add PackerTemplateBuilder --privs "VM.Audit VM.Clone VM.Allocate VM.Config.CPU VM.Config.Memory VM.Config.HWType VM.Config.Options VM.Config.Disk VM.Config.Network VM.PowerMgmt VM.GuestAgent.Audit Datastore.AllocateSpace Datastore.Audit SDN.Use"
pveum user add packer@pve --comment "CertiStack template build"
pveum user token add packer@pve template --privsep 1 --expire "$(date -d '+1 day' +%s)"
pveum acl modify /vms/9000 --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
pveum acl modify /vms/9800 --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
pveum acl modify /storage/local-lvm --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
pveum acl modify /sdn/zones/localnetwork/vmbr0 --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
```

`token add` prints the secret once; write it into the variable file. Check each path with
`pveum user token permissions packer@pve template --path <path>`. Afterwards, remove the token with
`pveum user token remove packer@pve template` and, unless the next build reuses them, the user and the role:

```bash
pveum user delete packer@pve
pveum role delete PackerTemplateBuilder
```

The role follows PVE's documented permissions for the calls plugin 1.2.4 makes on PVE 9.x; it is an upper bound, not a
proven minimum. If PVE denies a call, add that one privilege on that path, and never use an administrator or root-scoped
token.

## First boot

Install these files on the new VM with `install`, which sets the owner a plain copy would not: UID/GID `65532` (the
container's user), mode 0600:

```bash
sudo install -m 0600 -o 65532 -g 65532 controller.env id_ed25519 known_hosts /etc/certistack/secrets/
```

Start from [`files/controller.env.example`](files/controller.env.example). A stock setup needs both of its
commented-out lines:

- `PBS_FINGERPRINT`: a default PBS certificate is self-signed. Fill in the fingerprint from the PBS dashboard (Show
  Fingerprint) or `proxmox-backup-manager cert info`.
- `CERTISTACK_PVE_CA_SOURCE`: a stock Proxmox VE node signs its API certificate with the cluster's own CA, which the
  container does not trust. Copy `/etc/pve/pve-root-ca.pem` from the node as `pve-ca.pem` and install it the same way.
  While this line is active, a missing `pve-ca.pem` stops every run before the transfer.

```bash
sudo install -m 0600 -o 65532 -g 65532 pve-ca.pem /etc/certistack/secrets/
```

The example environment file connects as root; for another account, see
[the sudoers rule for a non-root account](https://certistack.dev/docs/manual-setup/#the-sudoers-rule-for-a-non-root-account).

Run plans from `/var/lib/certistack/plans`, as root; the wrapper refuses any other user:

```bash
sudo certistack-controller run /var/lib/certistack/plans/my-first-plan.yaml \
  --node pve-01 --ssh-host pve-01.example.internal \
  --ssh-identity /run/certistack-secrets/id_ed25519 \
  --ssh-known-hosts /run/certistack-secrets/known_hosts
```

The container starts with an empty environment, so the wrapper passes
`--env-file /run/certistack-secrets/controller.env` to `run`, `plan`, `doctor`, `init`, `check` and `validate`. Because
`validate` loads the file too, `sudo certistack-controller validate plan.yaml` needs
`/etc/certistack/secrets/controller.env` to exist; without it, it fails with "open controller environment file: open
/run/certistack-secrets/controller.env: no such file or directory". The file supplies the credentials and the
`CERTISTACK_*` defaults, so the node and SSH flags above are optional; a flag overrides the file.

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

Let running jobs finish and recover any run that reported an incomplete teardown
([Issue 35](https://certistack.dev/docs/troubleshooting/#issue-35)). Verify the release's assets through the signed
manifest ([Use the published image](../controller/README.md#use-the-published-image)); `CONTAINER-IMAGE.txt` then
holds the reference. Pull it into root's Podman store; the last command succeeds only if the stored digest is the one in
the reference:

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

Judge a passing plan's report (`certistack verify-report --unsigned --expect-outcome pass`) before you rely on the new
image. To roll back, restore the previous reference:

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
   `ca-certificates`, and rebuild the appliance template. Its `/etc/certistack/build-manifest` lists what it contains.
2. Clone a new VM. Install `/etc/certistack/secrets` as in [First boot](#first-boot) and copy `/var/lib/certistack/plans`
   and `/var/lib/certistack/reports`.
3. Verify it: `sudo certistack-controller version`, then a plan that should pass, with its report judged.
4. Keep the old VM, powered off, while you may want to roll back to it (powering it on is the rollback), then destroy
   it.

Do not run `apt upgrade`, or reboot, while a job is running, and first recover any run that reported an incomplete
teardown. If the source template enables unattended upgrades, turn off their automatic reboot
(`Unattended-Upgrade::Automatic-Reboot "false"`).
