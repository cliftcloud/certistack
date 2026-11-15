# Commands

Every `certistack` command: what it does, the usual call, its flags and its exit status. Variables and files are in [Settings and files](configuration.md), plan keys in [The plan file](plan-reference.md). The controller uploads its own executable to the node as a temporary worker, so one Linux amd64 binary does both jobs.

## Where each command runs

| Command | Runs on, and changes |
| --- | --- |
| [`validate`](#validate), [`verify-report`](#verify-report), [`report show`](#report-show), [`schema`](#schema), [`version`](#version), [`completion`](#completion), [`setup rbac`](#setup-rbac) | anywhere; nothing |
| [`telemetry`](#telemetry) | anywhere; your `telemetry.json` |
| [`setup`](#setup) | controller; only what you say yes to |
| [`setup trust-node`](#setup-trust-node), [`setup pve-ca`](#setup-pve-ca), [`init`](#init) | controller; the file you name |
| [`check`](#check), [`plan`](#plan) | controller; nothing |
| [`run`](#run) | controller; temporary resources on the node |
| [`doctor`](#doctor), [`inspect`](#inspect), [`recover`](#recover) | node; `recover` removes what the run journal records |

The hidden `node-*` commands run inside the worker; do not script against them. All commands take `--debug` and `--help`.

## Exit status

| Code | Meaning |
| --- | --- |
| `0` | Success. For `run`: the validation passed and the teardown was verified. |
| `1` | The answer is no: an invalid plan (`validate`), a refusal (`plan`), a failed validation with verified teardown (`run`), a report not accepted (`verify-report --expect-*`). |
| `2` | Anything else: a usage error, an SSH, PVE or PBS failure, a failed check, an untrusted report, or a `run` whose cleanup was not verified or whose report was not saved. |
| `130` | Interrupted (`SIGINT`, `SIGTERM` or `SIGHUP`). |

After a `run` exits `2`, the error says whether a workspace was kept on the node and how to recover it ([Issue 26](troubleshooting.md#issue-26-lost-contact-with-node)).

**Ctrl-C.** A command that only reads stops at once with "Interrupt received; stopping". `run`, `init --inspect`, and `plan`, `check` and `init` once they have staged a worker on the node, say "waiting for CertiStack cleanup"; a second Ctrl-C abandons it. After `run` or `init --inspect` the node then keeps the worker workspace for [`recover`](#recover); the others keep no journal, and the node removes their workspace about 90 seconds later.

**Output.** A report `run` could not save is printed between `-----BEGIN CERTISTACK REPORT-----` and `-----END CERTISTACK REPORT-----` lines.

## validate

```text
certistack validate [plan.yaml | plan-directory] [flags]
```

Checks a plan against the `v1` schema, or every `.yaml` and `.yml` file directly in a directory. It exits `0` when every plan is valid, `1` when any is not (it lists them all; a plan file it cannot open counts as invalid), and `2` when the path does not exist or is a directory with no `.yaml` or `.yml` file it reads. A path you name that is a symbolic link is read as `run` reads it. In a directory, a `.yaml` or `.yml` entry that is not a regular file (a link, a FIFO, a directory) is not read, and each is listed with `! not read:` and the reason.

| Flag | Meaning |
| --- | --- |
| `-p`, `--plan` | The plan file or directory, instead of the argument. |
| `--env-file` | An environment file to read and check; its values do not change the result. |

It refuses the `CHANGE` placeholder an earlier `init` wrote. A valid plan can also get notes, each on a line that starts with `!` under its summary. A note is advice: it never changes the exit code. `validate` cannot see the node, so it notes:

- a `network.ip_range` outside the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), which `plan` checks against the node;
- a `network.zone_id` or `network.vnet_id` that a host bridge also has, such as `vmbr0`;
- a `storage.overlay_storage` of `local` or `local-lvm`;
- a `max_host_ram_percent` above `95`;
- that Community never reads `compliance.sign_key_path`.

## verify-report

```text
certistack verify-report <report.json> [flags]
```

Checks a report's signature against a key **you** name, then judges whether its contents are acceptable evidence: every planned VM, every probe, disk integrity and verified cleanup. Give exactly one of `--keyring`, `--public-key` and `--trusted-key`, or `--unsigned` alone; a report never establishes trust in its own key. Community reports are unsigned:

```bash
certistack verify-report --unsigned --expect-outcome pass /var/lib/certistack/reports/<plan-id>/<report-id>.json
```

| Flag | Meaning |
| --- | --- |
| `--keyring` | A trusted-signer keyring: JSON, or a list of hex public keys. |
| `--public-key` | A file with one hex public key. |
| `--trusted-key` | One 64-character hex public key. |
| `--unsigned` | Expect no signature; nothing is verified, and the output says so. |
| `--format` | `text` (default), or `json`. |
| `--allow-test-mode` | Accept a report of the test-only `--skip-integrity` mode (which needs `CERTISTACK_ALLOW_TEST_MODE=1`). |
| `--expect-outcome` | `pass` (default); `fault` (exactly one failed probe, the first of the plan's first VM; needs `--expect-plan`); or `denied` (refused before any VM was restored). |
| `--expect-plan` | Only a report of exactly this plan: VMs, probes, their policy, and the file's SHA-256. |
| `--expect-node` | Only a report from this PVE node. |
| `--expect-version`, `--expect-commit`, `--expect-build-date` | Only a report from this build. |
| `--expect-worker-sha256` | Only a report whose `worker_sha256` is this. |
| `--expect-validation-mode` | `full_integrity`, or `test_skip_integrity` (needs `--allow-test-mode`). |
| `--expect-version-support` | `tested` or `untested`; a report that records none, or `unknown`, is rejected. |

It exits `0` when the signature is trusted (with `--unsigned`: the report was read) and, with an `--expect-*` flag, the report is accepted; `1` when an `--expect-*` flag was given and the report is not accepted; `2` when the report cannot be trusted or read. **Without an `--expect-*` flag, exit `0` does not mean the report is accepted**: read the `ACCEPTED` or `REJECTED` line. The rules: [Reports](reports.md).

## report show

```text
certistack report show <report.json> [--keyring FILE] [--json]
```

Prints what one report says, in reading order: outcome, plan, node, build, each VM (snapshot, network, disk integrity, probes, and the guest's network diagnostic when the report has one) and the teardown. It judges nothing: it exits `0` when it showed the report, and `2` when it cannot read it or the signature check fails.

| Flag | Meaning |
| --- | --- |
| `--keyring` | Verify the signature against this keyring and add `verify-report`'s verdict. A report that fails, or is unsigned, is then an error. |
| `--json` | The same facts as JSON: `view_version` (`1`), `signature`, `acceptance` and `report`. |

Without `--keyring` the signature is not checked, and the first lines say so. The text lists at most 200 VMs and 100 probes per VM; `--json` has them all. The network diagnostic is printed whole, up to 400 lines and 16 KiB, each line cut at 300 characters; a cut says so, and the report file holds the full text in `network_recovery_diagnostic`.

## schema

```text
certistack schema
```

Prints a JSON Schema of the plan file. Save it (`certistack schema > certistack-plan.schema.json`) and name it on a plan's first line (`# yaml-language-server: $schema=./certistack-plan.schema.json`): an editor with a YAML language server then completes keys and marks mistakes. `validate` checks more.

## version

```text
certistack version
```

Prints the version, commit, build time, Go version and platform.

## completion

```text
certistack completion bash | zsh | fish | powershell
```

Prints a completion script: `certistack completion bash | sudo tee /etc/bash_completion.d/certistack`.

## setup

```text
certistack setup [--node-host HOST] [--fingerprint SHA256:...] [--yes] [...]
```

The first-run wizard: it connects this controller to one Proxmox VE node and its Proxmox Backup Server, writes `controller.env`, and ends with [`check`](#check). It changes nothing on the node or the PBS before your yes to that change, and never shows a token secret. The [quickstart](quickstart.md) walks through it. It connects as `root`; for a non-root account, a pre-provisioned sandbox zone, or one command per step, see [Manual setup](manual-setup.md).

| Step | What it does |
| --- | --- |
| 1/9 | Creates the setup directory (mode `0700`). An existing one that other users can open is made private only when it holds nothing but the files listed under [What setup writes and creates](#what-setup-writes-and-creates); else setup changes nothing and asks for another directory (with `--yes`, it stops). |
| 2/9 | Records the node's host key after you type `yes`. Creates the key `id_ed25519` and has root accept it: `ssh-copy-id` (root's password, once), or a line you add to `/root/.ssh/authorized_keys`. The question says that the key signs in as root on the node, and on every node of a cluster, which shares root's `authorized_keys`. |
| 3/9 | Reads the node. Stops if `qemu-img`, `proxmox-backup-client` or `ip` is missing. |
| 4/9 | When `libguestfs-tools` or `nftables` is missing: asks to refresh the node's package lists (`apt-get update`, which changes only apt's lists), shows what `apt-get` would install, upgrade and remove, asks, then installs them (`apt-get -y --no-upgrade install`, without refreshing again). An install that would remove packages says `It would REMOVE:` and the question defaults to no. |
| 5/9 | Reuses the overlay storage if it has `images` content and is enabled and defined for this node, or adds a directory storage. |
| 6/9 | Runs the PVE part of the [`setup rbac`](#setup-rbac) script on the node. |
| 7/9 | Takes a PBS storage of the node (the list marks the default), or asks for host, datastore and namespace. An empty namespace asks `Continue?` first, because the PBS user can then read every namespace of the datastore (default no). Runs the PBS part over your own `ssh`, or writes `pbs-access.sh` for the PBS web shell. With a namespace, if the PBS user still holds an earlier setup's grant on the whole datastore, asks `Remove that grant? [Y/n]` (over `ssh`; the pasted script prints the commands instead). |
| 8/9 | Fetches the cluster CA into `pve-root-ca.pem` and writes `controller.env`. |
| 9/9 | Runs `check`; setup succeeds only if every layer passes. |

| Flag | Default | Meaning |
| --- | --- | --- |
| `--dir` | `/secure/certistack` if writable, else `~/certistack/secure` | The setup directory. |
| `--node-host` | the earlier `controller.env`'s | The node's DNS name or IP address, as the controller reaches it. |
| `--port` | `22` | The node's SSH port. |
| `--fingerprint` | | The node's ED25519 fingerprint (`SHA256:...`) you verified. A value in another form is refused before anything connects. |
| `--yes` | off | Take the default of every question the flags leave. Needs `--fingerprint`, and `--pbs-namespace` unless the PBS storage or the earlier `controller.env` names a namespace. |
| `--overlay-storage` | `certistack-scratch` | The overlay storage's ID. |
| `--overlay-path` | `/var/lib/vz/<ID>`; none on a cluster | The directory for a new overlay storage. |
| `--pbs-storage` | | Use this PBS storage of the node. |
| `--pbs-host` | | The PBS host, as the node reaches it. |
| `--pbs-port` | `8007` | The PBS API port. |
| `--pbs-datastore` | | The PBS datastore, with `--pbs-host`. |
| `--pbs-namespace` | the PBS storage's, else the earlier `controller.env`'s for the same PBS and datastore; else setup asks | The PBS namespace; the PBS user is granted only it. `/` is the root namespace: the PBS user can then read every namespace of the datastore. |
| `--pbs-fingerprint` | | The PBS certificate's fingerprint, when setup cannot read it. A value that is not 32 hex pairs joined by colons is refused before anything connects. |
| `--pbs-ssh` | `root@<PBS host>` | How to reach the PBS as root over your own `ssh`: `user@host`, a host, or a `Host` alias of your ssh configuration. Options go in `~/.ssh/config`; a value that starts with `-` or holds a space is refused. |
| `--pbs-manual` | off | Write `pbs-access.sh` instead of using `ssh`. Not with `--yes`. |

When a `controller.env` exists, its values are the defaults. Setup exits `0` when every step is done and `check` passed, `2` when it was refused or could not finish, and `130` when interrupted. Ctrl-C undoes nothing.

### What setup writes and creates

In the setup directory, owner-only except the public key and the CA: `known_hosts`, the key pair `id_ed25519` (no passphrase, made only when absent), `pve-root-ca.pem`, `controller.env`, the earlier file as `controller.env.bak-<UTC time>`, an encrypted PBS storage's key as `<ID>.enc`, `pbs-access.sh` (paste fallback only), and `controller.env.partial`, which keeps new token secrets until `controller.env` is written. If you cannot write to `/var/lib/certistack/reports`, setup makes a `reports` directory beside the setup directory and sets `CERTISTACK_OUTPUT_DIR`.

`PVE_URL` is `https://HOST:8006`, HOST being the first that the API certificate names of: the address you gave, the node's name, `127.0.0.1`, the certificate's own DNS name. For a certificate an administrator installed (ACME, say), setup leaves `CERTISTACK_PVE_CA_SOURCE` out, or keeps an earlier value.

On the node it adds the packages, the overlay storage, the key line in root's `authorized_keys`, and the role `CertiStackRole`, user `certistack-svc@pve` and token `certistack-svc@pve!automation`. On the PBS it adds the read-only `certistack-ro@pbs` and its token. What these allow, and how to remove them: [What it changes on your node](what-it-changes.md).

**A cluster node** has no default overlay directory: name one on a disk the cluster does not use. Setup refuses the root disk and adds the storage for this node only. It warns below 25 GiB free. It also says, once, that every run applies SDN twice and PVE reloads the network on all the cluster's nodes each time, and that `network.lifecycle: preprovisioned` avoids it ([Things to plan around](what-it-changes.md#things-to-plan-around)).

**An encrypted PBS storage.** Setup offers to copy its key from `/etc/pve/priv/storage/<ID>.enc` and set `CERTISTACK_PBS_KEYFILE` ([Encrypted backups](configuration.md#encrypted-backups)). The key decrypts every backup in the storage, so the default is no.

**The `ssh` to the PBS** is your own (your keys, `~/.ssh/known_hosts` and password). It asks before it trusts an unknown PBS host key: compare it with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` in the PBS web shell. Do not authorize the controller's key on the PBS. In the paste fallback, you paste the token's secret back at a prompt that does not echo.

**Running it again** reuses what exists. A token's secret cannot be read back: setup offers the one `controller.env` or `controller.env.partial` holds, or asks whether to replace the token. Replacing it stops the old secret working: anything still using it (a scheduled job, another controller) fails until it gets the new one. A no stops setup with `the token's secret is needed`. The new `controller.env` keeps the earlier lines setup does not set, except `CERTISTACK_SSH_SUDO`, `PVE_TLS_INSECURE` and its lab opt-in. A rerun that grants a namespace where an earlier one granted the whole datastore does not take that grant back by itself: it says `The PBS user can still read every namespace of datastore ...` and offers to remove it (default yes; it removes only setup's own `DatastoreReader` grant on `/datastore/<datastore>`).

**Unattended**, `--yes` answers yes to each change (removing an earlier grant on the whole datastore too), and no to replacing a token, to an install that would remove packages and to copying an encrypted storage's key. It picks the first PBS storage. A question with no default stops setup and names its flag, and so does an empty PBS namespace: give `--pbs-namespace`, or let an earlier `controller.env` name one. With `--pbs-host`, a missing `--pbs-datastore` or namespace stops setup before it creates anything; a PBS storage of the node is read at 3/9.

```bash
certistack setup --yes --fingerprint SHA256:... --node-host pve-node-01.example.com \
  --pbs-host pbs.example.com --pbs-datastore datastore1 --pbs-namespace NAMESPACE
```

In a new setup directory the first `--yes` run makes the controller's key and stops at 2/9 with the line to append to `/root/.ssh/authorized_keys` on the node: add it, then run the same command again. (Or run setup once at a terminal, where `ssh-copy-id` adds it.) A refused key is tried once: on PVE 9, repeated failed sign-ins make the node refuse the controller for up to 10 minutes. Let `ssh` reach the PBS without a prompt.

### setup trust-node

```text
certistack setup trust-node --host HOST [--port N] [--known-hosts FILE] [--fingerprint SHA256:...] [--yes]
```

Reads the ED25519 host key the node offers, prints its fingerprint and the `known_hosts` line, and writes the line only after you type `yes` or pass a matching `--fingerprint`. Compare it first with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` at the node's console; an ECDSA or RSA fingerprint never matches.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--host` | | The node, exactly as `CERTISTACK_SSH_HOST` names it. Required. |
| `--port` | `22` | The node's SSH port. |
| `--known-hosts` | `CERTISTACK_SSH_KNOWN_HOSTS`, else `/secure/certistack/known_hosts` | The file to write. Other commands read only the file `CERTISTACK_SSH_KNOWN_HOSTS` names. |
| `--fingerprint` | | The fingerprint you verified. Any other key is refused. |
| `--yes` | off | Skip the prompt. Only with `--fingerprint`. |

For a port other than 22 the line names `[host]:PORT`, as `ssh` looks it up. It never replaces a *different* key the file holds for that host: a changed key is also what an impersonated node looks like. It exits `0` when the line is there, `2` otherwise.

### setup pve-ca

```text
certistack setup pve-ca --env-file FILE [--out FILE]
```

A stock PVE node signs its API certificate with the cluster's own CA. Until `CERTISTACK_PVE_CA_SOURCE` names it, `init --vm`, `plan` and `run` stop with `x509: certificate signed by unknown authority`. This command fetches `/etc/pve/pve-root-ca.pem` over your pinned SSH access, writes it (mode `0644`) and prints the line to add. It never edits the environment file or writes over a file that is not a certificate. It exits `0` when the CA is there, `2` otherwise.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--env-file` | | The environment file; its SSH settings are used. Required. |
| `--out` | `pve-root-ca.pem` next to it | Where to write the CA. |

### setup rbac

```text
certistack setup rbac --node NAME --overlay-storage ID [--zone ZONE | --sandbox-zones a,b] [--pbs-datastore DS] [--pbs-namespace NS] [--part pve|pbs]
```

Prints a shell script for you to read and run. **It runs nothing and never sees the secrets.** Part 1, as root on the PVE node, creates the role, user, token and ACLs. Part 2, as root on the PBS, creates the read-only user and token. Details: [Manual setup](manual-setup.md#the-pve-role-and-its-permissions).

| Flag | Meaning |
| --- | --- |
| `--node` | The PVE node, as PVE names it. Required. |
| `--overlay-storage` | The overlay storage's ID. Required. |
| `--zone` | A pre-provisioned sandbox zone, granted instead of `/sdn` and `/sdn/zones`. |
| `--sandbox-zones` | Several such zones, comma-separated. |
| `--pbs-datastore` | The PBS datastore. Adds part 2. |
| `--pbs-namespace` | Grant only this namespace. |
| `--part` | Print only `pve` or `pbs`. Default: both. |

```bash
certistack setup rbac --node pve-node-01 --overlay-storage certistack-scratch --pbs-datastore datastore1 --part pve | ssh root@pve-node-01 sh -s
```

Each secret is printed once, on your terminal. Each part checks its host and stops at a failing step. Running it again is safe: the role gets the current privileges, and an existing user or token is left as it is. It exits `2` when a value is refused.

## check

```text
certistack check --env-file FILE [plan.yaml]
```

Tests each layer between this controller and `certistack plan`, stops at the first that fails, and prints the fix. It exits `0` when every layer passes, `2` when one fails, and `130` when interrupted. When every layer passes, its last line is the next command: [`plan`](#plan) when you gave a plan; without one, [`init`](#init) to write a first plan, or `check` again with a plan you have.

| Layer | What it checks |
| --- | --- |
| 1. Environment file | It exists, is owner-only (`0600`), every value has the right shape, and it sets `PVE_URL`, `PBS_REPOSITORY`, `PBS_PASSWORD`, `CERTISTACK_NODE` and `CERTISTACK_SSH_HOST`. |
| 2. SSH files | The identity file is private; `known_hosts` has the node (fix: [`setup trust-node`](#setup-trust-node)); no other user can change either: no group or other write, and owned by you or root. |
| 3. SSH connection | `ssh` works without a prompt, to the node `CERTISTACK_NODE` names. |
| 4. Node tools | `qemu-img`, `proxmox-backup-client`, `guestfish`, `ip` and `nft` (`nft` only for network probes). The fix is [`setup`](#setup), which shows what `apt-get` would install, upgrade and remove before it installs. |
| 5. PVE API | PVE accepts `PVE_TOKEN_ID` and `PVE_TOKEN_SECRET` (fix: [`setup rbac`](#setup-rbac) or [`setup pve-ca`](#setup-pve-ca)). |
| 6. PBS | The PBS credential lists the repository. |
| 7. Plan | With a plan: the file exists. |
| 8. Sandbox network | With a plan: it validates, and its `network` passes `doctor`'s `sandbox_range` and `sandbox_network`. |

## init

```text
certistack init [--vm ID]... | --all [flags]
```

Lists the VMs that have a complete PBS backup; with `--vm` or `--all`, writes a plan for them. Without an SSH host it runs on the node, as root.

```bash
certistack init --env-file /secure/certistack/controller.env --vm 100 --vm 101 -o nightly.yaml
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--vm` | | A VM ID for the plan. Repeat it, or separate with commas. |
| `--all` | off | Every VM that has a backup. |
| `--inspect` | off | Probe the services found in each Linux VM's backup ([`--inspect`](#init-inspect)). |
| `-o`, `--output` | `certistack-plan.yaml` | The plan file. Its directory must exist. |
| `--force` | off | Replace the plan file. |
| `--yes` | off | Do not ask before writing a plan of every VM (`--all`) or of more than 500 GiB of disks. |
| `--plan-id` | `recovery-<node>` | The plan's `plan_id`: letters, digits, `_` and `-`, at most 128 characters. Another value is refused before init reads anything. |
| `--name` | | The plan's `name`. |
| `--overlay-storage` | `CERTISTACK_OVERLAY_STORAGE`, else the roomiest usable one | The overlay storage. |
| `--namespace` | `PBS_NAMESPACE` | The PBS namespace to read. |
| `--first-vmid` | `9100` | The first sandbox VM ID to consider. |
| `--node` | `CERTISTACK_NODE`, else this host's name | The PVE node name. |
| `--scratch` | `CERTISTACK_SCRATCH_DIR`, else `/var/lib/certistack/scratch` (on the node: a temporary directory) | The private node directory it reads into. |
| `--state-dir` | `CERTISTACK_STATE_DIR`, else `/var/lib/certistack` | The node state directory. |
| `--env-file` | | The [environment file](configuration.md#the-environment-file). |
| [SSH flags](#ssh-flags) | | `--ssh-host`, `--ssh-user`, `--ssh-port`, `--ssh-identity`, `--ssh-known-hosts`, `--ssh-sudo`. |

With `--vm` or `--all`, `init` first prints what a run of the plan reads and holds: the disks it reads in full, about how long that takes (reading at 100 MB/s, a rate measured on older servers, plus 2 minutes of preparation per VM), and the RAM it reserves (each VM's memory plus 256 MiB). At a terminal it then asks `Write the plan? [y/N]` when you gave `--all` or the disks come to more than 500 GiB; the default is no. `--yes` skips the question, and without a terminal it is never asked.

The plan gets free sandbox VM IDs and SDN IDs that no other plan in its directory uses, `retention_days: 90`, and `frameworks: [NONE]` (no standard) with a comment on the labels. It is valid as written. Each VM gets a first probe that shows the guest came up; change each `CHANGE` probe to the VM's service.

| Guest | First probe |
| --- | --- |
| Linux with a NIC | SSH (TCP 22) on its sandbox address |
| Windows with the guest agent | `sc query EventLog` through the agent |
| Another guest with the agent | the agent answering (`ping`) |
| No agent, and not Linux with a NIC | left out, with the reason |

Also left out: a VM a run could not restore (an encrypted backup without its key), and a VM whose `net0` MAC repeats an earlier one's (clones): put those in separate plans. With `--ssh-host`, `init` always sends the scratch directory it chose: the SSH account must be able to create it, otherwise `init` stops at "prepare scratch directory".

### `--inspect` { #init-inspect }

With `--inspect`, `init` maps the newest backup of each Linux VM read-only, one at a time, and reads which services it runs; nothing is written or booted. It knows nginx, Apache, PostgreSQL, MariaDB, MySQL, Redis and sshd, and writes up to six probes per VM, each with `timeout_sec: 300`, a `CHANGE` mark and a comment naming the evidence:

| What it found | Probe |
| --- | --- |
| Plain HTTP on every address | `http` of `/` |
| HTTPS only, or another service on every address | `tcp` on its port |
| A service bound to one guest address | `tcp`, which fails until the service listens on every address |
| A service on localhost only | none; the comment says why |
| Only sshd, or nothing it knows | the SSH probe |

A VM it cannot inspect keeps the SSH probe, and the plan says why (not Linux, the host lock held, `guestfish` missing, a busy node, an encrypted volume). It does not find other services, services not started by a systemd unit enabled in `/etc/systemd/system`, or ports set on a command line. It reads no keys, passwords or data. If the cleanup cannot be verified, `init` writes the plan, says how to recover the node and exits `2`.

## plan

```text
certistack plan [plan.yaml] [flags]
```

Shows, step by step, what `run` would do, changing nothing in PVE or PBS. Without an SSH host it runs on the node, as root. It exits `0` when a run would go ahead, `1` when a run would refuse the plan, and `2` when the plan could not be worked out.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-p`, `--plan` | | The plan file, instead of the argument. |
| `--json` | off | Print the plan as JSON. |
| `--node` | `CERTISTACK_NODE`, else this host's name | The PVE node name. |
| `--scratch` | `CERTISTACK_SCRATCH_DIR`, else the plan's, else `/var/lib/certistack/scratch` | The scratch directory a run would use. |
| `--state-dir` | `CERTISTACK_STATE_DIR`, else `/var/lib/certistack` | The node state directory. |
| `--overlay-storage` | `CERTISTACK_OVERLAY_STORAGE`, else the plan's | The overlay storage. |
| `--env-file` | | The [environment file](configuration.md#the-environment-file). |
| [SSH flags](#ssh-flags) | | `--ssh-host`, `--ssh-user`, `--ssh-port`, `--ssh-identity`, `--ssh-known-hosts`, `--ssh-sudo`. |

Each line starts with a symbol: `✓` a check passes, `<` reads the backup, `+` creates (teardown deletes it), `~` changes what the run created, `>` starts a VM or a probe, `-` deletes, `=` evidence kept, `!` a warning, `✗` a refusal, `·` not reached. The first checks are the Proxmox versions ([Supported versions](compatibility.md#supported-versions)), the node's clock, and whether `network.ip_range` overlaps the PVE API, the PBS server or the node's networks. `--json` prints `plan_id`, `node`, `mode`, `steps`, `warnings` and `refusals`; no `refusals` means a run would go ahead.

## run

```text
certistack run [plan.yaml] [flags]
```

Runs a validation: a temporary worker on the node maps the PBS snapshot read-only, boots the sandbox VM, runs the probes and tears it all down. The controller checks the evidence and saves the report, unsigned.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-p`, `--plan` | | The plan file, instead of the argument. |
| `--node` | `CERTISTACK_NODE` | The PVE node. Required. |
| `--output` | `CERTISTACK_OUTPUT_DIR`, else `/var/lib/certistack/reports` | The report directory, an absolute path that no group or other user can write. |
| `--state-dir` | `CERTISTACK_STATE_DIR`, else `/var/lib/certistack` | The node directory for the journal and workspaces. |
| `--scratch` | `CERTISTACK_SCRATCH_DIR`, else the plan's, else `/var/lib/certistack/scratch` | The node's private work directory. |
| `--overlay-storage` | `CERTISTACK_OVERLAY_STORAGE`, else the plan's | The overlay storage. Required on stock Proxmox VE. |
| `--env-file` | | The [environment file](configuration.md#the-environment-file). |
| [SSH flags](#ssh-flags) | | `--ssh-host`, `--ssh-user`, `--ssh-port`, `--ssh-identity`, `--ssh-known-hosts`, `--ssh-sudo`. |

```console
$ certistack run my-first-plan.yaml --env-file /secure/certistack/controller.env
[00:00:01] INFO [Phase 1 of 8] Admission checks: node support and host capacity
...
✓ Controller report saved to: /var/lib/certistack/reports/recovery-pve-node-01/<report-id>.json
Next: certistack report show /var/lib/certistack/reports/recovery-pve-node-01/<report-id>.json
```

It exits `0` when the validation passed and `1` when it failed, both with the teardown verified; the report says why. It exits `2` for anything else, such as cleanup not verified, report not saved, or `another CertiStack operation holds the host lock` (one operation per node at a time). It exits `130` when interrupted.

- It needs seven variables and a `known_hosts` file ([What each command needs](configuration.md#what-each-command-needs)).
- It warns when the node's clock is 5 minutes or more off, and refuses a node whose clock would get its report refused.
- It refuses PVE older than 8, or PBS or `proxmox-backup-client` older than 3; an untested pair runs with a warning.
- It saves a report only for a worker result that matches the plan, node, run, report schema (1.7), VMs and probes. Any other result is kept as `<output>/refused/<run-id>.refused.txt`, which is not evidence.

**What it prints.** Each phase starts with `[Phase N of M]`, counting only the phases the plan has. After 30 seconds without news, `Still working:` repeats the last line. The integrity scan prints each GiB verified and, after 10 seconds and 5%, the time left. After a pass, one line follows the saved-report line: the `report show` command. After a failure, that command and a pointer to `docs/troubleshooting.md`; the command's note says it shows which probe failed, or, when no probe ran (a refusal before the VMs started), why the run stopped.

## doctor

```text
certistack doctor [plan.yaml] [flags]
```

Runs read-only checks on the PVE node, as root. With a plan it also reads each VM's backup as a run would. `run` makes the same checks itself; `doctor` shows why a node is refused. It exits `0` when every check passes or warns, `2` when one fails, and `130` on Ctrl-C.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-p`, `--plan` | | A plan to check as well. |
| `--env-file` | | An environment file, or a kept worker's `runtime.env`. |
| `--scratch` | `CERTISTACK_SCRATCH_DIR`, else the plan's, else `/var/lib/certistack/scratch` | The scratch directory to check. |
| `--state-dir` | `/var/lib/certistack` | The state directory to check. |
| `--overlay-storage` | the plan's | The overlay storage. |
| `--json` | off | Print `{"ready": bool, "checks": [{"name", "status", "detail"}], "versions": {"pve", "pbs", "pbs_client", "support", "reason"}}`. |

Each check shows `✓` passed, `!` warning, `✗` failed or `-` skipped.

| Check | What it verifies |
| --- | --- |
| `plan`, `privileges` | The plan validates; it runs as root. |
| `sandbox_range`, `sandbox_network` | `network.ip_range` holds neither the PVE API nor the PBS server, overlaps none of the node's routes or addresses, and holds no gateway, DNS server, SSH client or `vxlan` peer. |
| `kvm`, `qemu-img`, `proxmox-backup-client`, `ip`, `nft`, `guestfish` | `/dev/kvm` works and the tools are installed (`nft` for wire probes, `guestfish` for guest network recovery). |
| `pbs_keyfile`, `pbs_key_passphrase` | The PBS key is private, with its passphrase if needed. |
| `memory` | The node has the RAM the plan's VMs need together. |
| `scratch_path`, `scratch_space`, `state_path` | The directories are private (`0700`, owned by you, no symbolic link), with 5 GiB free for scratch. |
| `stale_loops` | No loop device is left on an unmounted file. |
| `pve_connectivity`, `pve_privileges` | The API accepts the token, and it holds the privileges the plan needs. |
| `version_support` | The PVE, PBS and client versions; `untested` and `unknown` warn, `unsupported` fails ([Supported versions](compatibility.md#supported-versions)). |
| `overlay_disk` | The overlays do not share a disk with the cluster database. |
| `backup_sources`, `backup_vm_<id>` | Each VM's backup can be restored as a run would. |

A ready node ends with `System is ready for DR validation.` A node that never hosted a run fails `scratch_path`: run `sudo install -d -m 0700 /var/lib/certistack` and then `sudo install -d -m 0700 /var/lib/certistack/scratch`, or let a run make them. For a run whose cleanup failed, use its workspace's files, which hold your secrets:

```bash
sudo /path/to/certistack doctor /var/lib/certistack/workers/<run-uuid>/plan.yaml \
  --env-file /var/lib/certistack/workers/<run-uuid>/runtime.env
```

With no kept workspace, use `certistack check`, or [Run doctor on the node](manual-setup.md#run-doctor-on-the-node).

## inspect

```text
certistack inspect [vmid] [flags]
```

With a VM ID, reports whether that sandbox VM's QMP and QGA sockets answer; without one, prints the run journal (`active.json`). Run it on the node: use a kept workspace's `/var/lib/certistack/workers/<run>/certistack-node`, or copy the controller's binary there.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--qmp` | `/var/run/qemu-server/<vmid>.qmp` | The QMP socket. |
| `--qga` | `/var/run/qemu-server/<vmid>.qga` | The QGA socket. |
| `--state-dir` | `/var/lib/certistack` | Whose `active.json` to print. |

## recover

```text
certistack recover [flags]
```

Cleans up an interrupted run on the node from its journal; the next run on the node does the same first. It removes only what the journal records, after checking CertiStack owns it. Run the kept worker's copy:

```bash
/var/lib/certistack/workers/<run>/certistack-node recover \
  --state-dir /var/lib/certistack \
  --env-file /var/lib/certistack/workers/<run>/runtime.env
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--state-dir` | `/var/lib/certistack` | The directory that holds `active.json`. |
| `--env-file` | | The kept worker's `runtime.env`. |

It exits `0` when the journal is reconciled, `2` when recovery failed, and `130` when interrupted; what was not done stays in the journal, so run it again. Do not delete a kept workspace before recovery succeeds.

## telemetry

```text
certistack telemetry status | show | enable [--business] | disable | reset
```

Controls the opt-in [usage statistics](telemetry.md): off unless you say yes, sent at most once a day after a completed `run`. `CERTISTACK_TELEMETRY=1` turns it on without storing an answer; it keeps the install id and the last send in `telemetry.json`, and sends nothing where it cannot; a `run` whose file cannot be written ends with one warning that names it ([Scheduled runs](telemetry.md#scheduled-runs)).

| Subcommand | What it does |
| --- | --- |
| `status` | Prints on or off, why, and the state file's path. Without `CERTISTACK_TELEMETRY=1`, an install that runs with it keep is named as such, with its last send. |
| `show` | Prints the exact JSON the next report would carry. Under `CERTISTACK_TELEMETRY=1`, before the first report, the install ID is a sample. |
| `enable` | Opts in and writes `telemetry.json`. `--business` answers yes to the business-use question. |
| `disable` | Opts out and forgets the install ID on this machine. |
| `reset` | Deletes `telemetry.json`, so the first-run question is asked again. With no file, it says `Nothing to reset: there is no telemetry state file at` and the path it looked at. |

`disable` and `reset` print the forgotten install ID, which support needs to delete a record. While `CERTISTACK_TELEMETRY=1` is set they say that reports continue, from a new install. The first-run question comes only at a terminal, never with `CI` set.

## SSH flags

`init`, `plan` and `run` share these. The controller needs the OpenSSH client (`ssh` and `scp`). SSH never prompts (`BatchMode=yes`), so the key must work unattended.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--ssh-host` | `CERTISTACK_SSH_HOST` | The node's SSH host. Required for `run`; without it, `init` and `plan` run on this node. |
| `--ssh-user` | `CERTISTACK_SSH_USER`, else `certistack` | The SSH account. |
| `--ssh-port` | `CERTISTACK_SSH_PORT`, else `22` | The SSH port. |
| `--ssh-identity` | `CERTISTACK_SSH_IDENTITY` | The private key's absolute path. |
| `--ssh-known-hosts` | `CERTISTACK_SSH_KNOWN_HOSTS`, else `~/.ssh/known_hosts` | A `known_hosts` file with the node's key. Strict checking is always on. |
| `--ssh-sudo` | `CERTISTACK_SSH_SUDO`, else off | Run the worker through passwordless `sudo` ([the sudoers rule](manual-setup.md#the-sudoers-rule-for-a-non-root-account)). |
