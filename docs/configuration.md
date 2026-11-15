# Settings and files

Where CertiStack reads its settings, what every environment variable does, and which files it keeps on the controller and the node. Read it when you edit `controller.env` by hand or want to know what a setting changes.

CertiStack reads settings from four places:

| Source | What it holds |
| --- | --- |
| A **plan** (YAML) | What to test: VMs, probes, sandbox network, limits ([The plan file](plan-reference.md)). |
| The **environment file** (`controller.env`) or exported variables | Connections: PVE and PBS credentials, SSH settings, paths. |
| **Command-line flags** | A per-command override ([Commands](cli-reference.md)). |
| **Key files** | Public keys that `verify-report` trusts for reports the Enterprise Edition signed. Community signs nothing. |

Credentials never go in a plan: plans are kept as evidence and may be shared, and the plan loader refuses credential keys such as `pbs_password`.

## Which setting wins {#precedence}

The first match wins:

1. The command-line flag.
2. The environment: the `--env-file` if you pass one, otherwise the process environment.
3. The plan, where it has the same setting: `storage.scratch_dir`, `storage.overlay_storage`, `storage.pbs_namespace`, and the discouraged `storage.pbs_repository` and `storage.pbs_fingerprint`. `run` needs `PBS_REPOSITORY` in the environment all the same; the plan's value is used only by `plan` and `doctor` on the node.
4. The built-in default.

**An `--env-file` replaces the process environment.** Every variable in the tables below is cleared from the process environment first, so one you exported is discarded, not merged. The usage statistics variables are the exception: an exported `DO_NOT_TRACK` still applies. A file that fails to parse changes nothing. An empty `--env-file ""` (an unset variable in a script) is refused: `--env-file is empty`.

## The environment file

A plain `NAME=value` list that keeps secrets out of plans, command lines and shell history. `certistack setup` writes it; pass it with `--env-file` to `run`, `plan`, `init`, `check`, `doctor` or `setup pve-ca`. Keep it owner-only, outside any repository, and never commit it.

```dotenv
# /secure/certistack/controller.env  (mode 0600)
PVE_URL=https://pve-node-01.example.com:8006
PVE_TOKEN_ID=certistack-svc@pve!automation
PVE_TOKEN_SECRET=your-pve-token-secret
PBS_REPOSITORY=certistack-ro@pbs!ro@pbs.example.com:8007:datastore1
PBS_PASSWORD=your-pbs-token-secret
PBS_FINGERPRINT=ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89
CERTISTACK_NODE=pve-node-01
CERTISTACK_SSH_HOST=pve-node-01.example.com
# a stock PVE node has no "certistack" account
CERTISTACK_SSH_USER=root
CERTISTACK_SSH_IDENTITY=/secure/certistack/id_ed25519
CERTISTACK_SSH_KNOWN_HOSTS=/secure/certistack/known_hosts
CERTISTACK_PVE_CA_SOURCE=/secure/certistack/pve-root-ca.pem
CERTISTACK_OVERLAY_STORAGE=certistack-scratch
```

The rules, checked when the file is read:

| Rule | Detail |
| --- | --- |
| File | A regular file of at most 256 KiB. On Linux and macOS, owner-only: no group or other permission (`0600`, say). |
| Encoding | UTF-8; a byte order mark is accepted. UTF-16 (what PowerShell's `>` writes) is refused with a message that says so. |
| Lines | `NAME=value`. Blank lines and lines that start with `#` are ignored. A `#` later in a line is never a comment. In `PVE_URL`, `PVE_TOKEN_ID`, `PVE_TOKEN_SECRET`, `PBS_REPOSITORY`, `PBS_FINGERPRINT`, `PBS_NAMESPACE`, `CERTISTACK_NODE`, `CERTISTACK_SSH_HOST` and `CERTISTACK_SSH_USER` a ` #` is refused; in any other variable it becomes part of the value, and `check` notes it. |
| Names | Only the names in the tables below, once each, in capitals, without `export`. Any other name (`PATH`, say) is an error, and the message says that the name is not a CertiStack setting. |
| Values | Read literally: the file is never shell-sourced, so `$VAR`, `$(command)` and backticks stay as written. One pair of matching quotes is removed. No newline, carriage return or NUL. An empty value counts as left out. |
| Relative paths | In `CERTISTACK_PVE_CA_SOURCE`, `CERTISTACK_PBS_KEYFILE`, `CERTISTACK_SSH_IDENTITY`, `CERTISTACK_SSH_KNOWN_HOSTS` and `CERTISTACK_OUTPUT_DIR`, resolved from the file's directory. |
| Shape | Each value must look as its table says. A wrong one is refused with its line and the fix, not defaulted; `certistack check` lists them all at once. |

The shape rules apply to an `--env-file` only. For variables you export instead, ports and yes-or-no values get the same check, but a malformed URL or repository fails later, where it is used. Put the values in a file to have them checked up front.

An error never prints a secret: not `PVE_TOKEN_SECRET`, `PBS_PASSWORD`, `PBS_ENCRYPTION_PASSWORD` or `CERTISTACK_API_TOKEN`, and not the credentials inside `PVE_URL`, `PBS_REPOSITORY` and `PVE_TOKEN_ID`. A refusal of a line in the file never shows its value either, even a host, an account or a port: it says what is wrong (`is not a port: it has 6 digits`), in case a secret went into the wrong line.

Some commands read the file differently. `validate --env-file` checks the file but uses none of its values. `recover --env-file` accepts only a worker's variables. `doctor --env-file` also accepts the `runtime.env` the controller writes for a worker, to diagnose a blocked run on the node.

## Variables

### What each command needs

`run`, and `plan` and `init` when `CERTISTACK_SSH_HOST` is set, need seven variables, from the process environment or the `--env-file`: `PVE_URL`, `PVE_TOKEN_ID`, `PVE_TOKEN_SECRET`, `PBS_REPOSITORY`, `PBS_PASSWORD`, `CERTISTACK_NODE` and `CERTISTACK_SSH_HOST`. A `known_hosts` file that holds the node's key must exist too. Every other variable is optional.

`check` asks for the same seven in two steps, so a file written before the token exists still gets its first four layers. Layer 1 counts five ("the 5 required variables are set"); layer 5 asks for `PVE_TOKEN_ID` and `PVE_TOKEN_SECRET`.

### Proxmox VE connection

| Variable | Required | Meaning |
| --- | --- | --- |
| `PVE_URL` | yes | The address of the PVE web interface, for example `https://pve-node-01.example.com:8006`: not `.../api2/json`. HTTPS only (plain HTTP only for loopback). No credentials, path, query or fragment; one trailing `/` is dropped. Ports 22 and 8007 are refused. |
| `PVE_TOKEN_ID` | yes | The API token ID, `user@realm!tokenname`. A user without `!tokenname`, a pasted `PVEAPIToken=` prefix and a `=secret` suffix are refused. Its permissions: [Manual setup](manual-setup.md#the-pve-role-and-its-permissions). |
| `PVE_TOKEN_SECRET` | yes | The token's secret: the UUID PVE shows once, with no space, tab or quote. |
| `CERTISTACK_PVE_CA_SOURCE` | no | A controller path to a PEM file of CA certificates to trust besides the system roots, such as a stock node's cluster CA (`certistack setup pve-ca` fetches it). A regular file of at most 1 MiB. The controller copies it into the run's private workspace. |
| `PVE_TLS_INSECURE` | lab only | `1` or `true` turns off PVE certificate checks (any letter case); `0` or `false` leaves them on. Refused unless `CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB` is also set. Never against a production node. |
| `CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB` | lab only | `1` or `true` confirms that checks are off in a throwaway lab (`0` or `false` for no). |

### Proxmox Backup Server connection {#proxmox-backup-server-connection}

| Variable | Required | Meaning |
| --- | --- | --- |
| `PBS_REPOSITORY` | yes | `user@realm!token@host:port:datastore`; `!token` and `:port` are optional, and the datastore is always last. The host is a name, an IPv4 address or an IPv6 address in brackets. A URL, or a port with no datastore, is refused. The credential must be read-only. |
| `PBS_PASSWORD` | yes | The PBS token secret or password. |
| `PBS_FINGERPRINT` | no | The PBS certificate's SHA-256 fingerprint (Dashboard, Show Fingerprint, or `proxmox-backup-manager cert info` on the PBS): 32 hex pairs with colons, or 64 hex digits; a `sha256:` prefix is removed. Used only when no CA the system trusts signed the certificate, as for a default self-signed one. |
| `PBS_NAMESPACE` | no | The PBS namespace to read, without a leading or trailing `/`, up to 7 levels of letters, digits, `_`, `-` and `.`. Overrides the plan's `storage.pbs_namespace` and is the default of `init --namespace`; a VM's `source_pbs.namespace` must match it. |

CertiStack runs `proxmox-backup-client` with `HOME` and the `XDG_CONFIG_*` paths pointing at nothing. The client's own fingerprint cache is never used, so set `PBS_FINGERPRINT` for a self-signed certificate. It passes the namespace as `--ns` on each command that takes one, because the 3.x client on a PVE 8 node ignores the variable.

### Encrypted backups

A backup that PBS encrypted needs its key on the controller. Without it, a run stops before it restores anything and names the missing setting. `certistack setup` offers to copy the key of an encrypted PBS storage and set the variable.

| Variable | Required | Meaning |
| --- | --- | --- |
| `CERTISTACK_PBS_KEYFILE` | for encrypted backups | A controller path to the PBS encryption key: a regular file (not a symbolic link) of at most 64 KiB, readable by its owner only, and a valid PBS key file. |
| `PBS_ENCRYPTION_PASSWORD` | when the key has a passphrase | The key's passphrase, at least 5 characters. A key that needs one is refused without it. |

The controller copies the key into the run's private worker workspace, and the worker refuses a key other users can read. A run whose cleanup cannot be verified keeps its workspace, but the key is removed at once. Because the client sees no per-user configuration, a default key in the account's `~/.config/proxmox-backup` is never used. Each VM in the report records the weakest crypt mode of its disks and whether the key verified the backup's manifest. To make a VM fail unless its backup is signed and verified, set `require_signed_backup: true` ([The plan file](plan-reference.md)).

### Controller to node SSH {#controller-to-node-ssh}

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `CERTISTACK_NODE` | `run`, `plan`, `init`, `check` | | The node's name as PVE shows it: case-sensitive, letters, digits and hyphens, no domain. It must be the node `CERTISTACK_SSH_HOST` reaches; the worker refuses to run on another. |
| `CERTISTACK_SSH_HOST` | `run`, `check`; selects remote mode for `plan` and `init` | | The node's SSH host name or address and nothing else: not `ssh://...`, `user@host` or `host:port`. Letters, digits, `.`, `-` and `:`; an IPv6 address without brackets. |
| `CERTISTACK_SSH_USER` | no | `certistack` | The SSH account: at most 32 letters, digits, `_` and `-`, starting with a letter or `_`. |
| `CERTISTACK_SSH_PORT` | no | `22` | The SSH port, 1 to 65535. A value that is not a port is an error, not a default. |
| `CERTISTACK_SSH_IDENTITY` | no | | The private key's path. |
| `CERTISTACK_SSH_KNOWN_HOSTS` | no | `~/.ssh/known_hosts` | A `known_hosts` file that holds the node's approved key. `certistack setup trust-node` writes it; set this variable to the same file, because the other commands read only this one. Strict checking is always on. |
| `CERTISTACK_SSH_SUDO` | no | off | Run the worker through passwordless `sudo`. On: `1`, `true`, `yes`; off: `0`, `false`, `no`, in any case. Anything else is an error. The rule: [Manual setup](manual-setup.md#the-sudoers-rule-for-a-non-root-account). |

### Paths

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTISTACK_OUTPUT_DIR` | `/var/lib/certistack/reports` | The controller directory for reports (`run`). A clean absolute path, or relative to the file. The `--output` flag takes only a clean absolute path, and a relative one is refused with its absolute form. No group or other user may write it. |
| `CERTISTACK_STATE_DIR` | `/var/lib/certistack` | The node directory for the journal, workspaces and logs (`run`, `plan`, `init`). |
| `CERTISTACK_SCRATCH_DIR` | the plan's `storage.scratch_dir`, else `/var/lib/certistack/scratch` | The node's private work directory (`run`, `plan`, `init`, `doctor`). |
| `CERTISTACK_OVERLAY_STORAGE` | the plan's `storage.overlay_storage` | The PVE storage for the overlays (`run`, `plan`, `init`). |

### Usage statistics {#usage-statistics-opt-in}

Off unless you opt in. These are read from the process environment only, never from an environment file (a file that names them is refused), and are not passed to the node. See [Usage statistics](telemetry.md).

| Variable | Default | Meaning |
| --- | --- | --- |
| `DO_NOT_TRACK` | unset | Any value but `0`, `false`, `no` or `off` turns the statistics off, whatever else is set or stored. |
| `CERTISTACK_TELEMETRY` | unset | `0`, `off`, `false` or `no` (or any unknown value) turns them off. `1`, `on`, `true` or `yes` turns them on, for CI and containers: no answer is stored, but the install is kept in `telemetry.json`, so a report goes at most once a day. Where that file cannot be written, nothing is sent, and a run says so in one warning ([Scheduled runs](telemetry.md#scheduled-runs)). Unset: your stored answer, off until you give one. |
| `CERTISTACK_TELEMETRY_BUSINESS` | unset | With `CERTISTACK_TELEMETRY=1` and no stored answer, `1`, `on`, `true` or `yes` answers the business-use question yes. |
| `CERTISTACK_TELEMETRY_URL` | `https://certistack.dev/api/telemetry` | Where a report is posted, for testing: `https`, or `http` for loopback only. Any other value sends nothing. |

### Test-only and internal

| Variable | Meaning |
| --- | --- |
| `CERTISTACK_ALLOW_TEST_MODE` | Only `1` counts (a file accepts `0` or `1`). It allows the test-only `--skip-integrity` mode of `run`, which skips the full integrity scan. Such a report says `test_skip_integrity`, is not evidence, and `verify-report` rejects it without `--allow-test-mode`. |
| `CERTISTACK_PROGRESS_EVENTS` | Set by the controller in the worker's environment (`1`), never by you. |
| `CERTISTACK_API_TOKEN` | Reserved for the Enterprise Edition. Community accepts it in a file, so one file serves both, and ignores it. |

## Files and directories

### On the controller

| Path | What it is |
| --- | --- |
| `/var/lib/certistack/reports/<plan_id>/<report_id>.json` | Reports, unsigned in Community. Files `0600`, directories `0700`; a run refuses a report or plan directory that group or other users can write. `--output` changes the base. Never deleted or rotated: `compliance.retention_days` is only recorded in them. |
| `/var/lib/certistack/reports/refused/<run-id>.refused.txt` | A worker result the controller refused. Not JSON and not evidence; mode `0600`, never deleted ([Reports](reports.md)). |
| `controller.env`, the SSH private key, `known_hosts`, the PBS key | Connection material, owner-only. Every command refuses a `known_hosts` file or SSH key that group or other users can write, or that a user other than you or root owns, as OpenSSH does: such a user could stand in for the node or the controller. The PVE CA is public: `setup pve-ca` writes it mode `0644`. The controller container image runs as UID and GID `65532`, so mounted secrets must be owned by that ID. |
| `telemetry.json` in `~/.config/certistack/` | Your answer to the [usage statistics](telemetry.md) question and the install id, mode `0600`. `CERTISTACK_TELEMETRY=1` keeps the install id and the last send there too, with no answer. Absent until you answer or the first report; `certistack telemetry reset` deletes it. |
| Your keyring or public key | What `verify-report` trusts. Not secret: keep it where an auditor can get it, apart from the reports. |
| Your plans | Not secret, but they name your VMs. Keep site-specific plans out of public repositories. |

### On the PVE node {#on-the-pve-node-while-an-operation-runs}

| Path | What it is |
| --- | --- |
| `/var/lib/certistack/` | The state directory (`--state-dir`). Created private (`0700`) when a run is staged; an existing one must already be `0700` and owned by root. |
| `/var/lib/certistack/active.json` | The run journal: every resource a run creates, so an interrupted run can be cleaned up. A clean run leaves it in the `cleaned` phase. `certistack inspect` prints it. |
| `/var/lib/certistack/workers/<uuid>/` | The run's private workspace (`0700`): the worker binary `certistack-node`, `plan.yaml`, `runtime.env`, and the PVE CA and PBS key when set. Removed at the end of a run; kept only when cleanup could not be verified, so [`recover`](cli-reference.md#recover) has what it needs. |
| `/var/lib/certistack/logs/<uuid>.log` | The worker supervisor's log, with no credentials. Kept after the workspace is gone. |
| `/var/lib/certistack/scratch/` | Private scratch space (`--scratch`, `0700`): guest network work, screenshots, and the overlays when no overlay storage is set. Not a shared directory such as `/tmp`. |
| `<overlay storage>/images/<vmid>/certistack-delta-*.qcow2`, and `certistack-delta-*.raw` for a UEFI or TPM VM | The overlays, and the firmware copies (which hold the source's Secure Boot variables and TPM state). Removed at teardown. |
| `/run/certistack.lock` | The node's lock: one CertiStack operation at a time. |

A kept workspace holds the PVE token and the PBS credential. It loses the PBS encryption key at once, and its other credentials when the node's next clean run finds its controller has been silent for 15 minutes. Its logs stay. Apart from the packages, the storage and the access that setup creates, each run leaves only `/var/lib/certistack` (journal and logs) on the node.
