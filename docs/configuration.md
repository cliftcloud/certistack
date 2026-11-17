# Commands and settings

Every command, flag, environment variable and file. Plan keys are in [Plans](plan-reference.md).

## Commands

Every command takes `--debug` and `--help`.

### Exit status

| Code | Meaning |
| --- | --- |
| `0` | Success. For `run`: the validation passed and the teardown was verified |
| `1` | No: an invalid or refused plan, a failed validation with verified teardown, a report not accepted |
| `2` | Anything else: an error, an untrusted report, or a `run` whose cleanup was not verified or whose report was not saved |
| `130` | Interrupted |

A second Ctrl-C stops `run`'s cleanup and leaves the workspace for [`recover`](#recover).

### validate

Checks a plan, or every `.yaml` and `.yml` file in a directory, without credentials. Lines starting `!` are advice.

| Flag | Meaning |
| --- | --- |
| `-p`, `--plan` | Plan file or directory, instead of the argument |
| `--env-file` | An environment file to check too; it does not change the result |

### verify-report

Judges a report as evidence ([Reports](reports.md#verify-a-report)). Give `--unsigned` for a Community report, or one
trust source for a signed one.

| Flag | Meaning |
| --- | --- |
| `--unsigned` | Expect no signature, as on Community reports |
| `--keyring` | A trusted-signer keyring |
| `--public-key` | A file with one hex public key |
| `--trusted-key` | One 64-character hex public key |
| `--format` | `text` (default) or `json` |
| `--expect-outcome` | `pass` (default), `fault` or `denied` |
| `--expect-plan` | Exactly this plan file |
| `--expect-node` | This PVE node |
| `--expect-version`, `--expect-commit`, `--expect-build-date` | This build |
| `--expect-worker-sha256` | This `worker_sha256` |
| `--expect-validation-mode` | `full_integrity`, or `test_skip_integrity` |
| `--expect-version-support` | `tested` or `untested` |
| `--allow-test-mode` | Accept a test-mode report |

### report show

Prints one report in reading order and judges nothing ([Reports](reports.md#read-a-report)). With no file named, it
shows the newest report run saved.

| Flag | Meaning |
| --- | --- |
| `--keyring` | Verify the signature against this keyring and add `verify-report`'s verdict |
| `--json` | Same facts as JSON |
| `--reports-dir` | Where to look for the newest report (default `/var/lib/certistack/reports`) |

<a id="schema"></a>

### schema, version and completion

`certistack schema` prints the plan's JSON Schema ([editor completion](plan-reference.md#editor-completion-and-checks));
`version` prints the version, commit, build time, Go version and platform; `completion` prints a `bash`, `zsh`, `fish`
or `powershell` completion script. None has flags of its own.

### setup

The [first-run wizard](quickstart.md#2-run-the-setup): connects to one PVE node and its PBS as `root`, asks before each
change, writes `controller.env`, records it as the [default](#the-environment-file) and runs [`check`](#check). A
rerun reuses what exists and takes its defaults from `controller.env`. Without root:
[manual setup](manual-setup.md#set-up-by-hand).

| Flag | Meaning |
| --- | --- |
| `--dir` | Setup directory. Default `/secure/certistack` if writable, else `~/certistack/secure` |
| `--node-host` | The node's DNS name or IP address, as the controller reaches it |
| `--port` | The node's SSH port. Default `22` |
| `--fingerprint` | The node's ED25519 fingerprint (`SHA256:...`) you verified |
| `--yes` | Take the default of every question. Needs `--fingerprint`, and `--pbs-namespace` unless the PBS storage names one |
| `--overlay-storage` | The overlay storage's ID. Default `certistack-scratch` |
| `--overlay-path` | Directory for a new overlay storage. Default `/var/lib/vz/<ID>`; none on a cluster |
| `--pbs-storage` | Use this PBS storage of the node |
| `--pbs-host` | PBS host, as the node reaches it |
| `--pbs-port` | PBS API port. Default `8007` |
| `--pbs-datastore` | PBS datastore, with `--pbs-host` |
| `--pbs-namespace` | The only namespace the PBS user is granted; `/` grants every namespace of the datastore |
| `--pbs-fingerprint` | The PBS certificate's fingerprint, when setup cannot read it |
| `--pbs-ssh` | How to reach the PBS as root over your own `ssh`. Default `root@<PBS host>` |
| `--pbs-manual` | Write `pbs-access.sh` for the PBS web shell instead of using `ssh` |

### setup trust-node

Records the node's ED25519 host key in `known_hosts` after you compare its fingerprint with
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` at the node's console. It never replaces a different key.

| Flag | Meaning |
| --- | --- |
| `--host` | Required. The node, exactly as `CERTISTACK_SSH_HOST` names it |
| `--port` | The node's SSH port. Default `22` |
| `--known-hosts` | File to write. Default `CERTISTACK_SSH_KNOWN_HOSTS`, else `/secure/certistack/known_hosts` |
| `--fingerprint` | Fingerprint you verified; any other key is refused |
| `--yes` | Skip the prompt. Only with `--fingerprint` |

### setup pve-ca

Fetches the cluster CA (`/etc/pve/pve-root-ca.pem`) over your pinned SSH access and prints the
`CERTISTACK_PVE_CA_SOURCE` line to add. Use it when `plan` or `run` stops with `x509: certificate signed by unknown
authority`.

| Flag | Meaning |
| --- | --- |
| `--env-file` | The environment file whose SSH settings it uses. Default: the one `setup` recorded |
| `--out` | Where to write the CA. Default `pve-root-ca.pem` next to the environment file |

### setup rbac

Prints, and never runs, a script: part 1 for root on the node (the PVE role, user, token and ACLs), part 2 for root
on the PBS (the read-only PBS user and token). Rerunning is safe.

| Flag | Meaning |
| --- | --- |
| `--node` | Required. The PVE node, as PVE names it |
| `--overlay-storage` | Required. The overlay storage's ID |
| `--zone` | A pre-provisioned sandbox zone, granted instead of `/sdn` and `/sdn/zones` |
| `--sandbox-zones` | Several such zones, comma-separated |
| `--pbs-datastore` | PBS datastore; adds part 2 |
| `--pbs-namespace` | Grant only this namespace |
| `--part` | Print only `pve` or `pbs`. Default both |

### check

On the controller: tests each layer up to `certistack plan` (the environment file, SSH, node tools, the PVE API, PBS,
and with a plan its sandbox network), stops at the first that fails, and prints the fix.

| Flag | Meaning |
| --- | --- |
| `--env-file` | The [environment file](#the-environment-file). Default: the one `setup` recorded |

### init

Lists the VMs that have a complete PBS backup; with `--vm` or `--all`, writes a plan for them. Change each `CHANGE`
probe to the VM's service.

| Flag | Meaning |
| --- | --- |
| `--vm` | A source VM ID. Repeat it, or separate with commas |
| `--all` | Every VM that has a backup |
| `--inspect` | Read each Linux VM's newest backup, read-only, and write a probe for each service it finds |
| `-o`, `--output` | Plan file. Default `certistack-plan.yaml` |
| `--force` | Replace the plan file |
| `--yes` | Skip the question before a plan of every VM or of over 500 GiB of disks |
| `--plan-id` | `plan_id`. Default `recovery-<node>` |
| `--name` | The plan's `name` |
| `--first-vmid` | First sandbox VM ID to consider. Default `9100` |
| `--namespace` | PBS namespace to read. Default `PBS_NAMESPACE` |
| `--env-file`, `--node`, `--scratch`, `--state-dir`, `--overlay-storage`, `--ssh-*` | [Shared and SSH flags](#shared-flags) |

### plan

Shows, step by step, what `run` would do, and changes nothing. Lines start with `✓` passes, `+` creates, `-` deletes,
`!` warns or `✗` refuses.

| Flag | Meaning |
| --- | --- |
| `-p`, `--plan` | Plan file, instead of the argument |
| `--json` | Print the plan as JSON; no `refusals` means a run would go ahead |
| `--env-file`, `--node`, `--scratch`, `--state-dir`, `--overlay-storage`, `--ssh-*` | [Shared and SSH flags](#shared-flags) |

### run

On the controller: a temporary worker on the node maps the backup read-only, boots the sandbox VM, runs the probes and
tears it down; the controller saves the [report](reports.md).

| Flag | Meaning |
| --- | --- |
| `-p`, `--plan` | Plan file, instead of the argument |
| `--output` | Report directory, an absolute path. Overrides `CERTISTACK_OUTPUT_DIR` |
| `--env-file`, `--node`, `--scratch`, `--state-dir`, `--overlay-storage`, `--ssh-*` | [Shared and SSH flags](#shared-flags) |

### doctor

On the node, as root: read-only checks of the node and, with a plan, each VM's backup, showing why `run` would refuse
it.

| Flag | Meaning |
| --- | --- |
| `-p`, `--plan` | A plan to check as well |
| `--json` | Print the checks as JSON |
| `--env-file`, `--scratch`, `--state-dir`, `--overlay-storage` | [Shared flags](#shared-flags); `--env-file` also takes a kept worker's `runtime.env` |

### inspect

On the node: with a VM ID, reports whether that sandbox VM's QMP and QGA sockets answer; without one, prints the run
journal.

| Flag | Meaning |
| --- | --- |
| `--qmp` | QMP socket. Default `/var/run/qemu-server/<vmid>.qmp` |
| `--qga` | QGA socket. Default `/var/run/qemu-server/<vmid>.qga` |
| `--state-dir` | Whose `active.json` to print. Default `/var/lib/certistack` |

### recover

On the node: cleans up an interrupted run, removing only what its journal records, as the next run would first. Run
the kept worker's copy, again if it exits `2`; keep the workspace until it succeeds.

```bash
/var/lib/certistack/workers/<run>/certistack-node recover \
  --state-dir /var/lib/certistack \
  --env-file /var/lib/certistack/workers/<run>/runtime.env
```

| Flag | Meaning |
| --- | --- |
| `--state-dir` | Directory that holds `active.json`. Default `/var/lib/certistack` |
| `--env-file` | The kept worker's `runtime.env` |

### telemetry

Controls the opt-in [usage statistics](telemetry.md): `status`, `show` (the exact JSON the next report would carry),
`enable` (`--business` answers yes to the business-use question), `disable` and `reset` (deletes `telemetry.json`).

<a id="shared-flags"></a>

### Shared and SSH flags

Each flag overrides the [variable](#variables) it names. `init`, `plan` and `run` reach the node with OpenSSH (`ssh`
and `scp`), which never prompts.

| Flag | Meaning |
| --- | --- |
| `--env-file` | The [environment file](#the-environment-file). Default: the one `setup` recorded, unless `PVE_URL` is set |
| `--node` | `CERTISTACK_NODE`; else, except for `run`, this host's name |
| `--scratch` | `CERTISTACK_SCRATCH_DIR` |
| `--state-dir` | `CERTISTACK_STATE_DIR`, except for `doctor` |
| `--overlay-storage` | `CERTISTACK_OVERLAY_STORAGE`, except for `doctor`; for `init`, else the roomiest usable storage |
| `--ssh-host` | `CERTISTACK_SSH_HOST`. Without it, `init` and `plan` run on this node, as root |
| `--ssh-user` | `CERTISTACK_SSH_USER` |
| `--ssh-port` | `CERTISTACK_SSH_PORT` |
| `--ssh-identity` | `CERTISTACK_SSH_IDENTITY`, as an absolute path |
| `--ssh-known-hosts` | `CERTISTACK_SSH_KNOWN_HOSTS`, as an absolute path |
| `--ssh-sudo` | `CERTISTACK_SSH_SUDO` |

## Variables

`certistack setup` writes the PVE, PBS, node, SSH, CA, overlay storage and report directory settings to
`controller.env`, and keeps any other variable of an earlier file except `CERTISTACK_SSH_SUDO`, `PVE_TLS_INSECURE` and
`CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB`: it connects as root and trusts the node's CA. Add `PBS_ENCRYPTION_PASSWORD`
by hand. `run`, and `plan` and `init` with an SSH host, need the seven marked required, and a `known_hosts` file with
the node's key.

| Variable | Meaning |
| --- | --- |
| `PVE_URL` | Required. The PVE address, such as `https://pve-node-01.example.com:8006`; HTTPS only |
| `PVE_TOKEN_ID` | Required. The API token ID, `user@realm!tokenname` |
| `PVE_TOKEN_SECRET` | Required. The token's secret, the UUID PVE shows once |
| `CERTISTACK_PVE_CA_SOURCE` | A PEM file of CA certificates to trust, such as the cluster CA from [`setup pve-ca`](#setup-pve-ca) |
| `PVE_TLS_INSECURE` | Lab only, never production. `1` or `true` turns off PVE certificate checks; needs `CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB` |
| `CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB` | Lab only. `1` or `true` confirms the checks are off in a throwaway lab |
| `PBS_REPOSITORY` | Required. `user@realm!token@host:port:datastore` (`!token` and `:port` optional), with a read-only credential |
| `PBS_PASSWORD` | Required. The PBS token secret or password |
| `PBS_FINGERPRINT` | The PBS certificate's SHA-256 fingerprint (`proxmox-backup-manager cert info`), for a self-signed certificate |
| `PBS_NAMESPACE` | PBS namespace to read, without leading or trailing `/` |
| `CERTISTACK_PBS_KEYFILE` | For encrypted backups: the PBS encryption key, a regular file readable by its owner only |
| `PBS_ENCRYPTION_PASSWORD` | The key's passphrase, when it has one |
| `CERTISTACK_NODE` | Required. The name PVE shows for the node `CERTISTACK_SSH_HOST` reaches |
| `CERTISTACK_SSH_HOST` | Required. The node's SSH host name or address, not `user@host` or `host:port` |
| `CERTISTACK_SSH_USER` | SSH account. Default `certistack` |
| `CERTISTACK_SSH_PORT` | Default `22` |
| `CERTISTACK_SSH_IDENTITY` | The SSH private key's path |
| `CERTISTACK_SSH_KNOWN_HOSTS` | `known_hosts` file `setup trust-node` writes. Default `~/.ssh/known_hosts` |
| `CERTISTACK_SSH_SUDO` | `1`, `true` or `yes`: run the worker through passwordless `sudo` ([the rule](manual-setup.md#the-sudoers-rule-for-a-non-root-account)). Default off |
| `CERTISTACK_OUTPUT_DIR` | The controller's report directory, which no group or other user may write. Default `/var/lib/certistack/reports` |
| `CERTISTACK_STATE_DIR` | Node directory for the journal, workspaces and logs. Default `/var/lib/certistack` |
| `CERTISTACK_SCRATCH_DIR` | The node's private work directory. Default the plan's, else `/var/lib/certistack/scratch` |
| `CERTISTACK_OVERLAY_STORAGE` | PVE storage for the overlays. Default the plan's |
| `DO_NOT_TRACK` | Any value but `0`, `false`, `no` or `off` turns [usage statistics](telemetry.md) off |
| `CERTISTACK_TELEMETRY` | `1` turns them on without storing an answer; `0` turns them off |
| `CERTISTACK_TELEMETRY_BUSINESS` | With `CERTISTACK_TELEMETRY=1`, `1` answers the business-use question yes |
| `CERTISTACK_TELEMETRY_URL` | Where reports are posted, for testing. Default `https://certistack.dev/api/telemetry` |
| `CERTISTACK_ALLOW_TEST_MODE` | Test only. `1` allows `run`'s `--skip-integrity` mode, whose report is not evidence |
| `CERTISTACK_PROGRESS_EVENTS` | Internal. The controller sets it for the worker |
| `CERTISTACK_API_TOKEN` | Reserved for the Enterprise Edition; Community ignores it |

### The environment file

- `NAME=value` lines, at most 256 KiB, UTF-8, owner-only (`0600`), outside any repository. `#` starts a comment line.
- Never shell-sourced: `$VAR` stays literal; one pair of matching quotes is removed. Relative paths resolve from the
  file's directory.
- Only the names above, once each, without `export`. The four usage statistics variables are read from the process
  environment only, and refused in a file.
- A wrong value is refused with its line and the fix; `certistack check` lists them all. No message prints a secret.
- `certistack setup` records the file it writes in `~/.config/certistack/env-file` (under `$XDG_CONFIG_HOME` if set).
  Without `--env-file`, `init`, `plan`, `run`, `validate`, `doctor`, `check` and `setup pve-ca` use that file, unless
  `PVE_URL` is set in the environment; `--debug` says which file was used.

<a id="precedence"></a>

### Which setting wins

1. The flag.
2. The environment. An `--env-file`, or the file `setup` recorded, replaces the process environment, except the four
   usage statistics variables.
3. The plan's `storage` key; `run` still needs `PBS_REPOSITORY` in the environment.
4. The default.

## Files

### On the controller

| Path | What it is |
| --- | --- |
| `/var/lib/certistack/reports/<plan_id>/<report_id>.json` | Reports: files `0600`, directories `0700`. Never deleted or rotated |
| `/var/lib/certistack/reports/refused/<run-id>.refused.txt` | A worker result the controller refused; not evidence |
| The setup directory | `controller.env` (with `.bak-<UTC time>` copies, and `.partial` holding new secrets until it is written), the key pair `id_ed25519`, `known_hosts`, `pve-root-ca.pem`, an encrypted storage's key `<ID>.enc`, `pbs-access.sh`. Owner-only but the public key and CA |
| `~/.config/certistack/telemetry.json` | Your usage statistics answer and install ID |
| `~/.config/certistack/env-file` | The path of the `controller.env` setup wrote, which commands use without `--env-file` |

Every command refuses an SSH key or `known_hosts` file that another user can write or owns (root aside).

### On the node

| Path | What it is |
| --- | --- |
| `/var/lib/certistack/` | State directory: `0700`, owned by root |
| `/var/lib/certistack/active.json` | Run journal: every resource a run creates |
| `/var/lib/certistack/workers/<uuid>/` | The run's workspace: the worker `certistack-node`, `plan.yaml` and `runtime.env`, which holds your credentials. Kept only when cleanup could not be verified |
| `/var/lib/certistack/logs/<uuid>.log` | What a recovery on the node did, without credentials. Written only when a run is recovered. Kept |
| `/var/lib/certistack/scratch/` | Private scratch space, and the overlays when no overlay storage is set |
| `<overlay storage>/images/<vmid>/certistack-delta-*` | Overlays and UEFI or TPM firmware copies. Removed at teardown |
| `/run/certistack.lock` | The node's lock: one CertiStack operation at a time |
