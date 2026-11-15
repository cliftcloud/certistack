# Manual setup

`certistack setup` does all of this for you, asking before each change. Use this page instead to read each command before it runs, to connect as an account other than root, to use a pre-provisioned sandbox zone, to create the PVE access with Terraform, or to build CertiStack yourself. What these steps change, and how to undo them: [What it changes on your node](what-it-changes.md).

## Build from source

You need Go and `make` (on Debian or Ubuntu: `sudo apt install golang-go make git`). The build uses Go 1.26.11; an older Go (1.21 or later) downloads that version itself, over the internet. On the controller, clone the tagged release:

```bash
git clone --depth 1 --branch v0.1.0 https://github.com/cliftcloud/certistack.git certistack-src
cd certistack-src
make build-linux          # bin/certistack-linux-amd64
make build-linux-arm64    # bin/certistack-linux-arm64 (offline commands only)
```

`make container` builds the controller image; `deploy/appliance` holds a Packer VM-template recipe. A `go install` build has no commit, so it is not release evidence.

## Install, upgrade and roll back a release

Download and verify a release as in [Install by hand](going-further.md#install-by-hand), and run the block below in `~/certistack-download`. An appliance does not run the host binary installed below: its jobs run the image named in `/etc/certistack/controller-image`. Upgrade and roll back an appliance with "Upgrade and roll back" in `deploy/appliance/README.md`.

On the controller, keep each verified version in its own directory and point the command at the active one (for your own build, use `bin/certistack-linux-amd64`):

```bash
version=v0.1.0
sudo install -d -m 0755 "/opt/certistack/releases/$version"
sudo install -m 0755 certistack-linux-amd64 "/opt/certistack/releases/$version/certistack"
sudo ln -sfn "/opt/certistack/releases/$version/certistack" /usr/local/bin/certistack
certistack version
```

To upgrade, finish or recover every run first, and keep the previous binary, `controller.env`, the reports and the node's journal. Install the new version as above, then run a plan that should pass and read its report. If it fails, point the link back at the previous version and clean up the node with the kept worker's `recover` ([Issue 26](troubleshooting.md#issue-26-lost-contact-with-node)). Never delete a journal, report or workspace to force a rollback.

## Set up by hand

These steps follow `certistack setup`'s order. Replace these example values:

| Example | What it is |
| --- | --- |
| `pve-node-01.example.com` | The node's DNS name or IP address, as the controller reaches it. Write it the same way everywhere: `known_hosts` matches by spelling. |
| `pve-node-01` | The node's name in PVE (on the node: `basename "$(readlink /etc/pve/local)"`). |
| `pbs.example.com`, `datastore1` | The PBS and the datastore that holds the backups. |
| `certistack-scratch` | The name you give the overlay storage. |

### 1. Prepare the node

As root on the node (over SSH, or the node's Shell in the web interface). The node must run a [supported version](compatibility.md#supported-versions) of Proxmox VE. A run needs `qemu-img`, `proxmox-backup-client` and `ip`, which every node has, `nft` (package `nftables`) for network probes, and `guestfish` (package `libguestfs-tools`) for guest network recovery. A stock node lacks `libguestfs-tools` (`guestfish`), and on some versions `nftables` (`nft`); this installs what is missing and leaves the rest:

```bash
apt update; apt install --no-upgrade libguestfs-tools nftables
```

`apt` lists what it installs, upgrades and removes, and asks. Read the list: it should remove nothing. Use `;`, not `&&`: without a subscription, `apt update` ends with `401 Unauthorized` for `enterprise.proxmox.com`, which is expected. To stop that error, turn the enterprise repositories off on the node's Updates, Repositories page.

Then add the overlay storage. `findmnt` shows which disk `/var/lib/vz` is on, and `df -h` must show at least the VM's disk size plus 5 GiB free (25 GiB for a VM with a 20 GiB disk):

```bash
findmnt -T /var/lib/vz
df -h /var/lib/vz
```

```bash
pvesm add dir certistack-scratch --path /var/lib/vz/certistack-scratch --content images --shared 0
```

On a cluster node, use a directory on another disk as the path, and add `--nodes pve-node-01`, or the cluster defines the storage on every node. Never use a cluster node's root disk: heavy I/O can delay corosync and cost the node its cluster membership. 5 GiB is the least a run checks; allow for guest writes and disk copies ([The plan file](plan-reference.md), `copy_before_boot`).

### 2. Connect the controller to the node

On the controller, create the directory for the key and files. Without `sudo`, use a directory you own (`install -d -m 0700 ~/certistack/secure`): replace `/secure/certistack` by it in every command below, and pass `--known-hosts YOUR_DIR/known_hosts` to `certistack setup trust-node`.

```bash
sudo install -d -m 0700 -o "$USER" /secure/certistack
ssh-keygen -t ed25519 -N '' -C certistack-controller -f /secure/certistack/id_ed25519
```

Record the node's host key; `trust-node` writes it after you type `yes`:

```bash
certistack setup trust-node --host pve-node-01.example.com
```

Before you type `yes`, run this at the node's console and check that both `SHA256:...` strings match:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Without `trust-node`, scan the key into a temporary file on the controller. Never redirect `ssh-keyscan` into `known_hosts` with `>`: that replaces every node you approved before.

```bash
scan=$(mktemp)
ssh-keyscan -t ed25519 pve-node-01.example.com > "$scan"
ssh-keygen -lf "$scan"
```

No fingerprint means no key: stop. If it matches the node's, append it:

```bash
cat "$scan" >> /secure/certistack/known_hosts
chmod 600 /secure/certistack/known_hosts
rm -f "$scan"
```

From the controller, authorize the key for root on the node (for another account, see [Use an account other than root](#use-an-account-other-than-root)). `ssh-copy-id` asks for root's password; if the node refuses passwords, append `id_ed25519.pub` to `/root/.ssh/authorized_keys` on the node yourself. The `mkdir` stops `ssh-copy-id` failing with `failed to create required temporary directory under ~/.ssh`.

```bash
mkdir -p -m 700 ~/.ssh
ssh-copy-id -o UserKnownHostsFile=/secure/certistack/known_hosts -o StrictHostKeyChecking=yes \
  -i /secure/certistack/id_ed25519.pub root@pve-node-01.example.com
```

Test it the way CertiStack connects; it prints `x86_64`:

```bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/secure/certistack/known_hosts -o IdentitiesOnly=yes \
  -i /secure/certistack/id_ed25519 root@pve-node-01.example.com uname -m
```

### 3. Create the PVE token and the read-only PBS user

On the controller, `certistack setup rbac` prints the scripts; it runs nothing. If your backups are in a PBS namespace, add `--pbs-namespace NAME` to the `--part pbs` command; without it the PBS user can read the whole datastore. For a pre-provisioned sandbox zone, add `--zone ZONE` to the `--part pve` command.

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

Run `pbs-access.sh` as root on the PBS (`ssh root@pbs.example.com sh -s < pbs-access.sh`), or, in its web shell (Administration, Shell), type `sh`, paste the script, then type `exit`: the script stops at its first error, which would otherwise close the web shell. Do not authorize the step 2 key on the PBS; if `ssh` asks about the PBS host key, compare it as in step 2.

Each script prints one secret, once:

- PVE prints a table. The secret is the long string in the `value` row, between the `│` characters: copy only that string into `PVE_TOKEN_SECRET`. A good run ends with the role's permissions on `/vms`.
- The PBS script prints the secret for `PBS_PASSWORD`.

Both are safe to run again; they only add grants. If you lose a secret, remove the token, then run the script again: `pveum user token remove certistack-svc@pve automation` on the node, `proxmox-backup-manager user delete-token certistack-ro@pbs ro` on the PBS. With `--pbs-namespace`, `proxmox-backup-manager acl list` must show `DatastoreReader` only on `/datastore/datastore1/NAME`. The script says when an earlier grant on the whole datastore stays, and prints the commands that remove it:

```bash
proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id certistack-ro@pbs --delete true
proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id 'certistack-ro@pbs!ro' --delete true
```

### 4. Write the controller environment file

Create `/secure/certistack/controller.env` with mode `0600` (`(umask 077; touch /secure/certistack/controller.env)`) and edit it. Change the hosts, the datastore and the two secrets; keep the user and token names step 3 created. Every variable is in [Settings and files](configuration.md#variables).

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

A comment must be on a line of its own. A stock node's API certificate is signed by the cluster's own CA. Fetch it, then add the `CERTISTACK_PVE_CA_SOURCE=...` line it prints; the command never edits the file:

```bash
certistack setup pve-ca --env-file /secure/certistack/controller.env
```

### 5. Check the controller

On the controller:

```bash
certistack check --env-file /secure/certistack/controller.env
```

It stops at the first layer that fails and prints the fix. Once you have a plan, add it to the command to check the plan and the sandbox range too ([`check`](cli-reference.md#check)).

## Use an account other than root

The worker maps PBS images and creates loop devices, so it runs as root. Either connect as `root`, or use a dedicated account with passwordless `sudo` (at `/usr/bin/sudo`) and set `CERTISTACK_SSH_SUDO=true`. The account is still root-equivalent: it uploads the program it then runs as root. On the node, as root:

```bash
useradd -m -s /bin/bash certistack
```

Give it a password (`passwd certistack`) for `ssh-copy-id`, authorize the key as in step 2 with `certistack@` instead of `root@`, and set `CERTISTACK_SSH_USER=certistack`.

### The sudoers rule for a non-root account

With `CERTISTACK_SSH_SUDO=true`, each step that needs root runs as `/usr/bin/sudo -n COMMAND`. `-n` never asks for a password: a command the rule does not allow fails at once with `sudo: a password is required`. These are the only commands the controller runs under `sudo`:

| Command | What for |
| --- | --- |
| `/bin/sh -c SCRIPT` | Creating the state and workspace directories, stopping or checking a worker, removing staged keys. |
| `/usr/bin/install` | Copying the worker, plan and environment file into the workspace `<state-dir>/workers/<uuid>/`. |
| `/usr/bin/systemd-run` | Starting the worker, and the watch that removes its workspace if the controller disappears. |
| `/usr/bin/cat` | Reading the run's journal, and the cluster CA for `setup pve-ca`. |
| `/usr/bin/touch` | Renewing the workspace's lease. |
| `/usr/bin/rm`, `/usr/bin/test` | Removing staged secrets and the workspace, and confirming they are gone. |
| `<state-dir>/workers/<uuid>/certistack-node` | The uploaded worker, started by `plan`, `check`, `init` and `recover`. |

On the node, as root, install `sudo`, create the rule with `visudo` (which refuses a syntax error), and check it:

```bash
apt install sudo
visudo -f /etc/sudoers.d/certistack
visudo -cf /etc/sudoers.d/certistack
```

The file holds one line; the check prints `parsed OK`:

```text
certistack ALL=(root) NOPASSWD: /usr/bin/install, /usr/bin/systemd-run, /bin/sh, /usr/bin/rm, /usr/bin/cat, /usr/bin/touch, /usr/bin/test, /var/lib/certistack/workers/*/certistack-node
```

Change `certistack` to your `CERTISTACK_SSH_USER`, and `/var/lib/certistack` to your `CERTISTACK_STATE_DIR` if you set one. In sudoers, `*` does not match `/`, so the last entry covers one run's directory. Without that last entry, the failure comes only when the worker starts. From the controller, this prints nothing and exits `0` when the rule works; `certistack check` then tests the other entries at layer 4. `/usr/bin/cat` is used only by `setup pve-ca` and `run`, so `certistack setup pve-ca` is its test:

```bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/secure/certistack/known_hosts -o IdentitiesOnly=yes \
  -i /secure/certistack/id_ed25519 certistack@pve-node-01.example.com \
  sudo -n /usr/bin/test ! -e /nonexistent
```

!!! warning "This rule does not limit the account to less than root"
    `/bin/sh`, `install` and `systemd-run` can do anything as root, and the last entry is a program this account uploaded. The list keeps the sudo log readable; it is not a security boundary. Do not narrow it with argument patterns: the arguments change with every run, and a rule that does not match fails at the first step.

## The PVE role and its permissions

The token works under a role, `CertiStackRole`, limited to what a run does:

| Privileges | What a run uses them for |
| --- | --- |
| `VM.Allocate`, `VM.Audit`, `VM.PowerMgmt`, `VM.Console` | Create, boot, stop and destroy the sandbox VM; query QMP. |
| `VM.Config.Disk`, `VM.Config.CPU`, `VM.Config.Memory`, `VM.Config.Network`, `VM.Config.Options`, `VM.Config.HWType`, `VM.Config.CDROM` | Attach the overlays; set cores, memory, the VNet, the guest agent, machine type and SMBIOS identity; attach CD-ROM drives empty. |
| `SDN.Allocate`, `SDN.Audit`, `SDN.Use` | Create and remove the sandbox zone and VNet. |
| `Datastore.AllocateSpace`, `Datastore.Audit` | Write the overlays. |
| `Sys.Audit` | Read the node's memory, CPU and task status. |

The user is `certistack-svc@pve`, and its token `certistack-svc@pve!automation` is privilege-separated: PVE gives it only what both it and the user hold. So the role is granted to both on each path, and never on `/`:

| ACL path | Propagate | Covers |
| --- | --- | --- |
| `/vms` | yes | the sandbox VMs; PVE deletes a VM's own ACL with the VM, so it cannot be narrower. With a pre-provisioned sandbox, `VM.Audit` here also lets a run see every guest on its VNet |
| `/sdn` | no | PVE's SDN lock (PVE 9) and applying the sandbox network |
| `/sdn/zones` | yes | creating and removing the sandbox zone and VNet |
| `/sdn/zones/<zone>` | yes | instead of the two above, for each pre-provisioned zone |
| `/storage/<overlay storage>` | yes | the overlays |
| `/nodes/<node>` | no | node status and QEMU machine versions |

Before it creates anything, a run (and `plan` and `doctor`) checks the token on every path and lists what is missing. It refuses to start without a privilege it needs, and warns and works around a missing `VM.Config.CDROM`, `VM.Console`, `Sys.Audit` or `/nodes/<node>` grant. A pre-provisioned zone needs `SDN.Audit` on `/sdn/zones/<zone>`, not `SDN.Allocate`; with only zone grants, a plan with an ephemeral sandbox fails this check.

`setup rbac` creates all this. To do it with plain commands as root on a PVE node (they stop with "already exists" when run again):

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

Check a path with `pveum user token permissions certistack-svc@pve automation --path /vms`.

On the PBS, the user needs only `DatastoreReader` (`Datastore.Audit` and `Datastore.Read`) on the datastore, with no write permission:

```bash
proxmox-backup-manager user create certistack-ro@pbs
proxmox-backup-manager user generate-token certistack-ro@pbs ro
proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id certistack-ro@pbs
proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id 'certistack-ro@pbs!ro'
```

`generate-token` prints `PBS_PASSWORD` once; `certistack-ro@pbs!ro` is the user in `PBS_REPOSITORY`.

## Create the PVE access with Terraform

The module in `terraform/` creates the same role, user, token and grants, and optionally a reference VM. It does not install CertiStack, configure PBS or write credentials. It needs Terraform or OpenTofu 1.7 or later; `terraform -chdir=terraform test` checks it offline once `terraform -chdir=terraform init` has fetched the provider. From a machine that reaches the node's port 8006:

1. **Bootstrap token.** On the node, `pveum user token add root@pam terraform --privsep 0` prints its secret once. Set `pve_api_token = "root@pam!terraform=<secret>"` in `terraform.tfvars` (mode `0600`, never committed). Remove the token afterwards with `pveum user token remove root@pam terraform`.
2. **The node's CA.** Run `plan`, `apply` and `destroy` (not `init`) with the CA from `certistack setup pve-ca`: `SSL_CERT_FILE=/secure/certistack/pve-root-ca.pem terraform apply`. Without it, `apply` stops with `x509: certificate signed by unknown authority`.
3. **Apply.** `terraform init`, `terraform plan` (one role, one user, one token and their ACLs), `terraform apply`. Applying again changes nothing.
4. **Hand over the token.** `terraform output -raw pve_token_id` and `terraform output -raw pve_token_secret` print the ID and the secret alone. Write them into `controller.env`, then run `certistack check`.

Terraform keeps the token secret in its state: use an encrypted backend, and never commit `terraform.tfvars`. Start from [`terraform/terraform.tfvars.example`](https://github.com/cliftcloud/certistack/blob/main/terraform/terraform.tfvars.example).

### Terraform inputs

| Input | Required | Meaning |
| --- | --- | --- |
| `pve_api_endpoint` | Yes | The PVE API URL. |
| `pve_api_token` | Yes | The bootstrap token (`USER@REALM!TOKENID=SECRET`). |
| `pve_node_name` | Yes | The node for the worker and sandbox; granted on `/nodes/<node>`. |
| `overlay_storage` | Yes | The overlay storage's ID. |
| `sandbox_sdn_zones` | No | Pre-provisioned zones; empty grants an ephemeral sandbox. |
| `pve_tls_insecure` | No | Accept a self-signed PVE certificate (default `false`); a throwaway lab only. |
| `pbs_host` | Yes | The PBS address. |
| `pbs_port` | No | The PBS API port (default `8007`). |
| `pbs_datastore` | Yes | The PBS datastore. |
| `pbs_fingerprint` | Yes | The PBS certificate's fingerprint. |
| `pbs_user` | Yes | The read-only PBS identity (`user@realm!token`), never `root@pam`. |
| `reference_template_vmid` | No | A template to clone as a reference VM to test; unset creates none. |
| `reference_vmid` | No | Its VM ID (default `9000`). |
| `reference_datastore` | No | Its storage (default `local-lvm`). |
| `pve_bridge` | No | Its isolated bridge, never `vmbr0`. Required with `reference_template_vmid`. |
| `guest_password` | No | Its cloud-init password. Required with `reference_template_vmid`. |

A reference template is a Debian or Ubuntu cloud image with `cloud-init`, `qemu-guest-agent` enabled at boot and a service to probe. The module waits up to 15 minutes for its guest agent; back the clone up to the PBS yourself.

## Run doctor on the node

A node CertiStack never ran on has no credentials for `doctor`. Start with `certistack check` from the controller, which runs the same checks through a temporary worker:

```bash
certistack check --env-file /secure/certistack/controller.env my-first-plan.yaml
```

To see `doctor`'s own list, run it as root on the node:

1. Copy the program and the plan. `"$(command -v certistack)"` is the one you installed; for your own build, name `bin/certistack-linux-amd64` in the clone instead (and use that name in steps 3 and 4).

    ```bash
    scp -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/secure/certistack/known_hosts \
      -i /secure/certistack/id_ed25519 "$(command -v certistack)" my-first-plan.yaml root@pve-node-01.example.com:/root/
    ```

    With encrypted backups, copy the key `CERTISTACK_PBS_KEYFILE` names as well: add its path to the `scp` line.

2. From the controller, build a root-only `/root/doctor.env` with only the lines `doctor` needs and the node's CA path:

    ```bash
    ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/secure/certistack/known_hosts \
      -i /secure/certistack/id_ed25519 root@pve-node-01.example.com 'install -m 0600 /dev/null /root/doctor.env'
    { grep -E '^(PVE_URL|PVE_TOKEN_ID|PVE_TOKEN_SECRET|PBS_REPOSITORY|PBS_PASSWORD|PBS_FINGERPRINT|PBS_NAMESPACE|PBS_ENCRYPTION_PASSWORD)=' /secure/certistack/controller.env
      echo 'CERTISTACK_PVE_CA_SOURCE=/etc/pve/pve-root-ca.pem'; } \
      | ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/secure/certistack/known_hosts \
        -i /secure/certistack/id_ed25519 root@pve-node-01.example.com 'cat >> /root/doctor.env'
    ```

    With encrypted backups, also add the line `CERTISTACK_PBS_KEYFILE=/root/` followed by the key's file name to
    `/root/doctor.env` on the node.

3. Run it. A ready node ends with `System is ready for DR validation.` An `overlay_disk` warning on a one-disk node is advice.

    ```bash
    /root/certistack doctor /root/my-first-plan.yaml --env-file /root/doctor.env
    ```

4. Delete the credentials and the copies (and the key, if you copied it):

    ```bash
    rm -f /root/doctor.env /root/certistack /root/my-first-plan.yaml
    ```
