# CertiStack Controller appliance

The appliance is a dedicated management VM, not software installed directly
on a PVE hypervisor. It preloads the same digest-pinned OCI controller image
used by `deploy/controller/Dockerfile`, plus Podman and the SSH client needed
to reach PVE nodes.

## Size of the VM

The controller does not restore or run workloads itself; the temporary node
worker on the PVE node does. The appliance carries the guest OS, Podman, one
controller container, the SSH transfers to the node and the
retained reports.

| | Minimum | Recommended |
| :--- | :--- | :--- |
| vCPU | 2 | 2 |
| Memory | 2048 MiB | 4096 MiB |
| Disk | the source template's disk, plus room for reports under `/var/lib/certistack` | as the minimum, on backed-up storage |

These are a floor and a starting point, not measured capacity. The build
refuses less than the minimum. Packer's Proxmox plugin would otherwise replace
the source template's own sizing with its defaults (512 MiB, one core, the
`kvm64` CPU model and OS type `other`), so the recipe sets memory, cores,
sockets, CPU model and OS type itself, from the inputs below. The default CPU
model, `x86-64-v2-AES`, is a baseline model that live-migrates across a cluster
of mixed CPU generations; use `host` only on a single node or on identical
hardware.

## Build a PVE VM template

Everything the build needs is prepared first, so that a missing piece fails
before the long full clone and not after it.

1. **An approved, patched Debian or Ubuntu cloud-init source template** in PVE,
   with `cloud-init` and `qemu-guest-agent` installed, enabled at boot and
   answering. The recipe sets `qemu_agent = true`: Packer finds the build VM's
   address through the guest agent and connects before any CertiStack
   provisioner has run, so the recipe cannot install the agent for you. Check
   it once on a clone of the template: start the clone and run
   `qm agent <vmid> ping` on the node, which prints nothing and exits 0 when the
   agent answers. [Preparing a template](../../docs/manual-setup.md#create-the-pve-access-with-terraform)
   describes one. If you cannot install the agent, copy the recipe, set
   `qemu_agent = false` and give it an `ssh_host`.
2. **A key pair made for this build alone**, with the public half authorized in
   the source template for the login user (`root` unless you set
   `ssh_username`):

   ```bash
   ssh-keygen -t ed25519 -N '' -C certistack-template-build -f /secure/certistack/packer-build-key
   ```

   The build removes that exact public key from every `authorized_keys` file in
   the guest, fails if any copy remains, and leaves the operator's other keys
   alone. Destroy the private key when the build is verified, and remove the
   public key from the source template.
3. **A Packer API token** for this build only, with the permissions in
   [Packer token permissions](#packer-token-permissions).
4. **The controller image digest.** Each Community release publishes the
   matching controller image as
   `ghcr.io/cliftcloud/certistack-controller:<version>` and records its digest
   in the release asset `CONTAINER-IMAGE.txt`. First verify that file through
   the signed release manifest using the
   [controller installation instructions](../controller/README.md#use-the-published-image).
   Use the authenticated digest for `controller_image`, and confirm it against
   the registry before building:

   ```bash
   docker buildx imagetools inspect ghcr.io/cliftcloud/certistack-controller:<version>
   ```

Put the inputs in a variable file outside this checkout, readable by you
alone. The token secret belongs in this file and never on the command line: a
`-var` value is part of the process's argument list, which other local users,
process accounting and build-agent telemetry can read, and shell history keeps
it. Do not run the build with shell tracing (`set -x`) on.

```bash
install -m 0600 /dev/null /secure/certistack/packer.pkrvars.hcl
${EDITOR:-vi} /secure/certistack/packer.pkrvars.hcl
```

```hcl
proxmox_url               = "https://pve.example.internal:8006/api2/json"
proxmox_token_id          = "packer@pve!template"
proxmox_token_secret      = "REPLACE_WITH_THE_TOKEN_SECRET"
proxmox_node              = "pve-01"
source_template           = "debian-12-cloudinit"
ssh_private_key_file      = "/secure/certistack/packer-build-key"
ssh_build_public_key_file = "/secure/certistack/packer-build-key.pub"
controller_image          = "ghcr.io/cliftcloud/certistack-controller@sha256:REPLACE_WITH_64_HEX_DIGEST"
```

Then build a full-clone controller template with Packer:

```bash
cd deploy/appliance/packer
packer init .
packer build -var-file=/secure/certistack/packer.pkrvars.hcl .
```

An automation system can supply the secret as `PKR_VAR_proxmox_token_secret`
instead; a process environment is also readable by the same collectors, so
protect and redact it the same way. When the build is done, delete the variable
file, the build private key and the token (see
[Packer token permissions](#packer-token-permissions)). Keep the Packer state
and artifacts in a protected location.

### Inputs

Every input of `proxmox-clone.pkr.hcl`. A test keeps this table and the recipe
in step.

| Input | Required | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `proxmox_url` | Yes | | PVE API endpoint, such as `https://pve.example:8006/api2/json` |
| `proxmox_token_id` | Yes | | Packer-only API token ID, such as `packer@pve!template` |
| `proxmox_token_secret` | Yes | | The token's secret. Sensitive; supply it from the variable file |
| `proxmox_node` | Yes | | The PVE node that owns the source template |
| `source_template` | Yes | | The source template's name or ID |
| `ssh_private_key_file` | Yes | | The build-only private key |
| `ssh_build_public_key_file` | Yes | | The public half; removed from the guest at the end of the build |
| `controller_image` | Yes | | `registry-host/repository@sha256:<64 lowercase hex digits>`; the form is checked before the build starts |
| `template_name` | No | `certistack-controller` | Name of the template |
| `template_vmid` | No | `9800` | VM ID of the template; it must be unused |
| `pool` | No | none | PVE resource pool for the template |
| `task_timeout` | No | `10m` | How long Packer waits for one PVE task such as the clone |
| `memory` | No | `2048` | MiB; at least 2048 |
| `cores` | No | `2` | Cores per socket; at least 2 |
| `sockets` | No | `1` | CPU sockets |
| `cpu_type` | No | `x86-64-v2-AES` | PVE CPU model |
| `os` | No | `l26` | PVE guest OS type |
| `ssh_username` | No | `root` | The build login; the recipe's provisioners assume root |
| `insecure_skip_tls_verify` | No | `false` | Only for an isolated build lab with an explicit exception |

### What the build checks and leaves out

The last provisioner (`files/finalize-template.sh`) runs inside the build VM,
and any failure in it fails the build, so no template comes out of a
half-cleaned guest:

* **A new machine ID for every clone.** It runs
  `cloud-init clean --logs --seed --machine-id`, which sets `/etc/machine-id`
  to `uninitialized` so that systemd makes a new ID on each clone's first boot.
  A cloud-init too old to know `--machine-id` is followed by emptying
  `/etc/machine-id` instead. The script then checks that the file, and
  D-Bus's copy, are empty, `uninitialized` or absent. Without this, every clone
  shares the build VM's ID, and whatever keys off it (systemd and D-Bus
  consumers, journals, some DHCP clients) cannot tell them apart.
* **cloud-init state.** It checks that the instance state, the seed and the
  cloud-init logs are gone, so a clone runs its first-boot configuration again.
* **No build key.** It removes the public key named by
  `ssh_build_public_key_file`, by key material, from `/root/.ssh`, every home
  directory and `/etc/ssh`, and then searches them again independently and fails
  if the key is still authorized anywhere. The search does not follow symbolic
  links, so the build refuses, before it removes anything, a template that has
  a link as or under any of those directories (a linked `.ssh`, home directory
  or `authorized_keys` file); remove the link from the source template. Packer's own
  `ssh_clear_authorized_keys` is also on, but Packer removes only a key it
  generated itself, so it does nothing for a static key. Anything that
  logs in with another key you put in the source template (for example a
  break-glass key) stays; remove those from the source template if the
  appliance should not carry them.
* **The controller image.** The image the build pulled is checked against the
  digest in `controller_image` before `/etc/certistack/controller-image`
  records it. The `controller_image` input also refuses, before the build
  starts, anything that is not `registry-host/repository@sha256:<digest>`:
  a tag, an uppercase name, a scheme such as `https://`, a doubled slash, a
  transport prefix such as `dir:` or a name with no registry host.
* **A build manifest.** `/etc/certistack/build-manifest` lists the controller
  image, the Packer version, the OS release and every installed package with
  its version. It holds no secret.

After the first build, start two clones and confirm that `cat /etc/machine-id`
differs between them and that the build key cannot log in to either.

### If the clone times out

`task_timeout` bounds each PVE task Packer waits for, the full clone above all.
The plugin's own default is one minute, which a full clone of a large template
on slow storage exceeds; the recipe defaults to ten minutes. Size it from a
measured clone of your source template on your storage (run
`qm clone <source> <scratch-vmid> --full` once and read the task's duration),
plus margin, and raise `task_timeout` if a build fails on a timeout. Before you
retry or delete anything after a timeout, open the PVE task list for the
node, find the clone task and the VM `template_vmid`, and let a running task
finish or stop it there: a timed-out client does not mean the task stopped,
and a retry while it runs fails on the VM ID. Delete only the exact VM that the
failed build left.

### What is pinned

| Input | How it is fixed |
| :--- | :--- |
| Controller image | by sha256 digest (`controller_image`), checked twice |
| Packer | `required_version = ">= 1.14.2, < 2.0.0"` |
| Proxmox plugin | exactly `= 1.2.4`; `packer init` installs that version and no other |

The recipe was checked with Packer 1.14.2 and plugin 1.2.4 by `packer validate`;
no build against a live PVE is recorded for those versions. Not pinned, and so
different from one build to the next: the contents of the source template,
which is yours to maintain, and the Debian or Ubuntu packages, which `apt-get`
resolves on the day of the build. Keep, for every appliance you publish, the
template's `/etc/certistack/build-manifest`, the output of `packer version` and
`packer plugins installed`, and the source template's name and VM ID. Move a
pin by editing the recipe in a reviewed change, rebuilding and reading the new
manifest against the old one; nothing updates them silently.

## Packer token permissions

The build token is not read-only: it clones the source template, changes the
clone's configuration, starts it, reads its address from the guest agent,
stops it and turns it into a template. It is also not the controller's token,
and it needs none of the controller's privileges. Make a separate user and a
privilege-separated token for each build, give them only the role and paths
below, let the token expire, and remove it afterwards.

PVE checks a privilege-separated token against both the token and its user, so
the role is granted twice on every path, once to each (the same arrangement as
the [Terraform module's ACLs](../../docs/manual-setup.md#the-pve-role-and-its-permissions)).

| Operation | Privilege | Path |
| :--- | :--- | :--- |
| Find the source template; read the build VM's configuration and status | `VM.Audit` | source template and build VM |
| Full-clone the source template | `VM.Clone` | `/vms/<source template VM ID>` |
| Create the clone; convert it to a template; remove it if the build fails | `VM.Allocate` | `/vms/<template_vmid>`, or `/pool/<pool>` when `pool` is set |
| Apply the recipe's sizing and options | `VM.Config.CPU`, `VM.Config.Memory`, `VM.Config.HWType`, `VM.Config.Options`, `VM.Config.Disk`, `VM.Config.Network` | the build VM |
| Start and stop the build VM | `VM.PowerMgmt` | the build VM |
| Read the build VM's address from the guest agent | `VM.GuestAgent.Audit` | the build VM |
| Allocate the clone's disks | `Datastore.AllocateSpace`, `Datastore.Audit` | `/storage/<storage>` the clone's disks land on |
| Attach the clone's network device | `SDN.Use` | `/sdn/zones/localnetwork/<bridge>` for a local bridge, or `/sdn/zones/<zone>/<vnet>` |

On a PVE node (the role name and IDs are examples):

```bash
pveum role add PackerTemplateBuilder --privs "VM.Audit VM.Clone VM.Allocate VM.Config.CPU VM.Config.Memory VM.Config.HWType VM.Config.Options VM.Config.Disk VM.Config.Network VM.PowerMgmt VM.GuestAgent.Audit Datastore.AllocateSpace Datastore.Audit SDN.Use"
pveum user add packer@pve --comment "CertiStack template build"
pveum user token add packer@pve template --privsep 1 --expire "$(date -d '+1 day' +%s)"
pveum acl modify /vms/9000 --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
pveum acl modify /vms/9800 --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
pveum acl modify /storage/local-lvm --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
pveum acl modify /sdn/zones/localnetwork/vmbr0 --roles PackerTemplateBuilder --users packer@pve --tokens 'packer@pve!template' --propagate 0
```

Here `9000` is the source template's VM ID and `9800` the template's. The
`token add` command prints the secret once; write it straight into the
variable file. If the source template is on another storage or node, grant
that storage as well.

Before the build, read what the token can actually do on each path. Every
privilege in the role should be listed for the token on the paths above, and
none on any other path:

```bash
pveum user token permissions packer@pve template --path /vms/9000
pveum user token permissions packer@pve template --path /vms/9800
pveum user token permissions packer@pve template --path /storage/local-lvm
pveum user token permissions packer@pve template --path /sdn/zones/localnetwork/vmbr0
```

When the build is done, remove the token and, unless the next build reuses it,
the user and the role:

```bash
pveum user token remove packer@pve template
pveum user delete packer@pve
pveum role delete PackerTemplateBuilder
```

This list follows PVE's documented permission notes for the clone,
configuration, power and guest-agent calls the plugin makes, for plugin 1.2.4
on PVE 9.x, the supported hypervisor. It has not yet been narrowed by removing
each privilege in turn from a working build, so it is an upper bound rather
than a proven minimum. PVE names the path and the privilege when it denies a
call: add that one privilege on that one path rather than widening the role,
and do not substitute an administrator or root-scoped token.

## First boot

After cloning the template, place these controller-only files on the new VM:

```text
/etc/certistack/secrets/controller.env             mode 0600
/etc/certistack/secrets/id_ed25519                 mode 0600
/etc/certistack/secrets/known_hosts                mode 0600
/etc/certistack/secrets/pve-ca.pem                 mode 0600, needed by a stock PVE node (see below)
```

They must be owned by UID/GID `65532`, the unprivileged container identity;
the Packer template pre-creates both `/etc/certistack/secrets` and
`/var/lib/certistack` with that ownership. A file copied into a directory does
not take the directory's owner, so write each one with `install`, which sets
owner and mode as it goes:

```bash
sudo install -m 0600 -o 65532 -g 65532 controller.env id_ed25519 known_hosts /etc/certistack/secrets/
```

Use [`files/controller.env.example`](files/controller.env.example) as the
schema. It leaves two lines commented out, and a stock setup needs both. A
default PBS certificate is self-signed, so uncomment `PBS_FINGERPRINT` and fill in
the fingerprint from the PBS dashboard (Show Fingerprint) or
`proxmox-backup-manager cert info`. A stock Proxmox VE node signs its API
certificate with the cluster's own CA, which the container does not trust, so copy
`/etc/pve/pve-root-ca.pem` from the node as `pve-ca.pem`, install it the same way
and uncomment `CERTISTACK_PVE_CA_SOURCE`; while the line is active, a missing
`pve-ca.pem` stops every run before the transfer
(`stage PVE CA file ... no such file or directory`). A PVE certificate that a CA in
the container's trust store signed needs no CA file.

```bash
sudo install -m 0600 -o 65532 -g 65532 pve-ca.pem /etc/certistack/secrets/
```

The VM template deliberately contains no customer API token, PBS credential,
SSH identity, known host key, report, or plan.

The controller container sends no usage statistics: the opt-in report is off by
default, and the container starts with an empty environment and no terminal to
ask on. The wrapper sets `XDG_CONFIG_HOME` to `/var/lib/certistack/.config`, so
an opt-in with `CERTISTACK_TELEMETRY=1` keeps its install id there. See
[usage statistics](../../docs/telemetry.md).

Store plans under `/var/lib/certistack/plans` and execute a job from the VM,
as root. The controller image lives in root's Podman store and the wrapper never
pulls one (`--pull=never`), so a run as any other user fails with an image that
Podman does not know; the secrets belong to UID/GID 65532 with mode 0600, so
only root and the container can read them. The wrapper refuses to run as
anyone else and says so:

```bash
sudo certistack-controller run /var/lib/certistack/plans/nightly.yaml \
  --node pve-01 --ssh-host pve-01.example.internal \
  --ssh-user certistack \
  --ssh-identity /run/certistack-secrets/id_ed25519 \
  --ssh-known-hosts /run/certistack-secrets/known_hosts
```

The container starts with an empty environment, and the controller reads its
credentials and defaults only from an environment file it is told to load. The
wrapper therefore passes `--env-file /run/certistack-secrets/controller.env`
(the mounted `controller.env`) to `run`, `plan`, `doctor`, `init`, `check` and
`validate` (which only reads and checks the file). Because
`validate` loads the file too, `sudo certistack-controller validate plan.yaml`
needs `/etc/certistack/secrets/controller.env` to exist, to be mode `0600`
and to hold only names the controller allows: before the secrets are installed
it fails with "open controller environment file: open
/run/certistack-secrets/controller.env: no such file or directory" where it
used to validate a plan alone. Create the file first, or validate on a workstation. The file
supplies the PVE and PBS credentials and the `CERTISTACK_*` defaults, so the
node and SSH flags above are optional; a flag you pass overrides the file, and
an `--env-file` of your own after the command name replaces it. The file is
parsed literally and against an allowlist, never shell-sourced.

Reports remain under `/var/lib/certistack/reports` on the controller. The
temporary node worker is removed from
`/var/lib/certistack/workers/<uuid>` after each run.

## Upgrade and roll back

Appliance jobs run the image named in `/etc/certistack/controller-image`, and
the wrapper never pulls one (`--pull=never`). Installing a newer host binary as
in [Verify, install, upgrade, and roll back a release](../../docs/manual-setup.md#install-upgrade-and-roll-back-a-release)
therefore changes nothing on an appliance: its jobs keep running the old image.
Changing only the reference file is no better, because the wrapper cannot fetch
an image the store does not hold. An upgrade pulls the verified digest first
and switches the reference second, and a rollback switches it back.

The reference selects the controller image and nothing else. The `certistack-controller`
wrapper (what it runs as, which commands get the mounted environment file) and
the example environment file are installed from the template, not from the
image, so a new image does not carry a change to either. A release that changes
the wrapper or `controller.env.example` says so in its release notes, and an
appliance gets the change only from a rebuilt template
([Patch the appliance's operating system](#patch-the-appliances-operating-system)):
an image-only upgrade of an appliance built from an older template keeps its
older wrapper.

Before you start, let any running job finish (`sudo podman ps` lists none), and
if a run reported an incomplete teardown, recover it first
([Recover from an interrupted run](../../docs/troubleshooting.md#issue-26-lost-contact-with-node-)).
Verify the release's assets through its signed manifest as described in the
[controller installation instructions](../controller/README.md#use-the-published-image);
`CONTAINER-IMAGE.txt` then holds the one reference to install,
`registry/repository@sha256:<64 hex digits>`.

Pull that digest into root's Podman store and check that the store holds exactly
it. The last command prints nothing and succeeds only if the stored digest is
the one in the reference:

```bash
new=$(cat CONTAINER-IMAGE.txt)
sudo podman pull "$new"
test "$(sudo podman image inspect --format '{{.Digest}}' "$new")" = "${new#*@}"
```

Then switch the reference. The commands run one after another and stop at the
first that fails: the new reference must be a digest, the image must be in the
store, the current reference is kept as `controller-image.previous`, and the
new one replaces it by an atomic rename, so a job starting at any moment sees
the old reference or the new one, never a partial file. The last command starts
the new image:

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

Run a known-safe positive plan and judge its report
(`certistack verify-report --unsigned --expect-outcome pass`) before you rely on the new image. A pull that fails,
or a registry that is unreachable, leaves the old reference and the old image in
place.

To roll back, restore the previous reference the same way. The previous image is
still in the store, so nothing is fetched:

```bash
sudo cp -p /etc/certistack/controller-image.previous /etc/certistack/controller-image.rollback &&
  sudo mv /etc/certistack/controller-image.rollback /etc/certistack/controller-image &&
  sudo certistack-controller version
```

Keep the previous image until you no longer need to roll back: do not run
`podman rmi` or `podman image prune` on it. Never delete a report, a recovery
journal or a temporary worker workspace to force a rollback. The controller
image is one part of the appliance; the operating system under it is patched
as described next.

## Patch the appliance's operating system

The supported model is replacement, not in-place patching. The appliance's
kernel, Podman, OpenSSH client and trust store are the template's, and they
change only when you rebuild the template from a freshly patched source
template and deploy a new VM from it.

1. Patch the source template on your own schedule, and rebuild the appliance
   template from it (above) at least monthly and whenever your distribution
   publishes a security update for the kernel, Podman, OpenSSH or
   `ca-certificates`. The new template's `/etc/certistack/build-manifest` names
   what it contains.
2. Clone the new template to a new VM, and move the controller's state to it:
   install `/etc/certistack/secrets` with the same `install` command as in
   [First boot](#first-boot), and copy `/var/lib/certistack/plans` and
   `/var/lib/certistack/reports`.
3. Verify the new VM: `sudo certistack-controller version`, then a known-safe
   positive plan with its report judged the same way.
4. Keep the old VM, powered off, for as long as you would want to roll back to
   it, then destroy it. Rolling back is powering it on again.

Do not run `apt upgrade`, or reboot, an appliance while a job is running, and
recover any run that reported an incomplete teardown first. If the source
template enables unattended upgrades, that is your patch policy: turn off its
automatic reboot (`Unattended-Upgrade::Automatic-Reboot "false"`) and reboot
when no job is running. The controller image is updated separately, by the
procedure above, on its own cadence.
