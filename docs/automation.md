# Run it on a schedule

Run a plan every night and hear when a restore fails. Community has no scheduler: use a systemd timer or cron. First,
make the plan probe the service each VM is for, not only SSH ([The plan file](plan-reference.md)).

## The wrapper script

The script runs one plan, judges the report with `verify-report --expect-plan`, and exits `0` only for a pass with
verified cleanup. It passes a stop request on and never overlaps itself. It needs `bash`, `flock`, `sed` and `jq`.

It is `scripts/certistack-validate` in the release's source. On the controller, fetch it pinned to the release, read
it, and install it:

```bash
curl -fsSLo certistack-validate https://raw.githubusercontent.com/cliftcloud/certistack/v0.1.0/scripts/certistack-validate
cat certistack-validate
sudo install -m 0755 certistack-validate /usr/local/bin/certistack-validate
```

It reads two settings from its environment: `CERTISTACK_ENV_FILE`, the controller's environment file (default
`/secure/certistack/controller.env`), and `CERTISTACK_KEYRING`, empty for Community reports, which are unsigned, or a
keyring file for reports the Enterprise Edition signs. This is the whole script:

```bash
--8<-- "scripts/certistack-validate"
```

It prints the JSON summary ([Reports](reports.md#a-machine-readable-summary)); progress goes to standard error.

| Exit | Meaning |
| --- | --- |
| `0` | Verified pass |
| `1` | Verified failure: a finding, not an outage |
| `2` | Unreadable plan, or no report, or one that does not verify |
| `75` | The plan's previous run is still going |
| other | `certistack run`'s own status ([Commands](cli-reference.md#exit-status)) |

## Run it from systemd

On the controller, create the account that runs the job, and its directories:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin certistack
sudo install -d -m 0700 -o certistack /secure/certistack
sudo install -d -m 0700 -o certistack /var/lib/certistack/plans
sudo install -d -m 0700 -o certistack /var/lib/certistack/reports
```

Hand it the environment file, SSH key, `known_hosts` and earlier reports:

```bash
sudo chown -R certistack /secure/certistack /var/lib/certistack/reports && sudo chmod -R go-rwx /secure/certistack
```

From now on, run every `certistack` command as that user (`sudo -u certistack certistack ...`): only it can
read the environment file and the reports. Put the plan in place, as `nightly`:

```bash
sudo install -m 0600 -o certistack my-first-plan.yaml /var/lib/certistack/plans/nightly.yaml
```

One service and one timer template serve every plan:

```bash
sudo tee /etc/systemd/system/certistack-validate@.service >/dev/null <<'EOF'
[Unit]
Description=CertiStack recovery validation of plan %i
Wants=network-online.target
After=network-online.target
OnFailure=certistack-alert@%i.service

[Service]
Type=oneshot
User=certistack
StateDirectory=certistack
StateDirectoryMode=0700
# The account has no home directory: its own state (the usage statistics',
# if you opt in) goes in /var/lib/certistack/certistack.
Environment=XDG_CONFIG_HOME=%S/certistack
ExecStart=/usr/local/bin/certistack-validate /var/lib/certistack/plans/%i.yaml
# After a stop request certistack waits up to 20 minutes for the node to finish
# cleaning up; do not let systemd kill it sooner. KillMode=mixed signals only
# the wrapper, which forwards the stop to certistack.
KillMode=mixed
TimeoutStopSec=25min
EOF
```

```bash
sudo tee /etc/systemd/system/certistack-validate@.timer >/dev/null <<'EOF'
[Unit]
Description=Nightly CertiStack recovery validation of plan %i

[Timer]
# CHANGE the time to after your last backup job ends (Datacenter > Backup).
OnCalendar=*-*-* 05:30:00
# No Persistent=true: a missed run is not started at the next boot, in working hours.

[Install]
WantedBy=timers.target
EOF
```

The alert writes to the system log; replace its `ExecStart` with your mail, webhook or monitoring:

```bash
sudo tee /etc/systemd/system/certistack-alert@.service >/dev/null <<'EOF'
[Unit]
Description=Alert: CertiStack recovery validation of plan %i failed

[Service]
Type=oneshot
ExecStart=/usr/bin/logger -p user.err -t certistack "recovery validation of plan %i failed"
EOF
```

Enable the timer, then run it once and read the result:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now certistack-validate@nightly.timer
systemctl list-timers 'certistack-validate@*'
```

```bash
sudo systemctl start certistack-validate@nightly.service
sudo journalctl -u certistack-validate@nightly.service -n 50
```

Test the alert with `sudo systemctl start certistack-alert@nightly.service` and `sudo journalctl -t certistack`. To add a
plan, install it as `/var/lib/certistack/plans/web.yaml`, give it its own time with
`sudo systemctl edit certistack-validate@web.timer` (an empty `OnCalendar=`, then yours), and run
`sudo systemctl enable --now certistack-validate@web.timer`.

### More than one site

Give each site its own setup directory and plans ([More than one site](going-further.md#more-than-one-site)). The
script reads `CERTISTACK_ENV_FILE`, so one copy serves every site: give each site's plan its file in its own unit,
with `sudo systemctl edit certistack-validate@site-a.service` (the plan `/var/lib/certistack/plans/site-a.yaml`):

```ini
[Service]
Environment=CERTISTACK_ENV_FILE=/secure/certistack/site-a/controller.env
```

## Run it from cron

Create the account and directories as for systemd, then write `/etc/cron.d/certistack` (`30 5` is minute and hour):

```bash
sudo tee /etc/cron.d/certistack >/dev/null <<'EOF'
# m h dom mon dow user command
PATH=/usr/local/bin:/usr/bin:/bin
30 5 * * * certistack /usr/local/bin/certistack-validate /var/lib/certistack/plans/nightly.yaml
EOF
```

cron mails every run's output: redirect it to a log and alert on failure yourself (`|| your-alert-command`).

## Run it from the controller container

The image holds only `certistack`, not the wrapper. In the `crontab -e` of a user that can run `docker`:

```cron
CERTISTACK_CONTROLLER_IMAGE=PASTE-THE-CONTENTS-OF-CONTAINER-IMAGE.txt
30 5 * * * cd /opt/certistack && docker compose -f deploy/controller/compose.yaml run --rm -T controller run /plans/nightly.yaml --env-file /run/certistack-secrets/controller.env
```

Compose needs that digest-pinned image (or a local build); `-T` is for cron, which has no terminal. Reports land in `state/reports` beside the Compose
file (uid 65532, mode `0600`): judge each with a second container run of `verify-report --unsigned --expect-plan`. See
the [controller README](https://github.com/cliftcloud/certistack/blob/main/deploy/controller/README.md).

## Rules for scheduled runs

- **One operation per node.** Every run, recovery and `init --inspect` takes a lock (`/run/certistack.lock`); another
  is refused with `another CertiStack operation holds the host lock` (exit `2`). Stagger one node's plans.
- **Own IDs for plans that can overlap.** Sandbox VM IDs, `zone_id` and `vnet_id` are cluster-wide.
- **After the backup window.** During backups Windows guests boot slowly
  ([Issue 19](troubleshooting.md#issue-19-a-windows-guests-agent-or-services-never-start-in-the-sandbox)), and a job
  can back up a sandbox VM ([How it works](architecture.md#backup-jobs-and-vm-ids)).
- **No upgrades under a running job.** Finish or recover every active run first.
- **Prune reports yourself.** CertiStack never deletes one.

## Test it before you trust it

Point a probe at a closed port: the job must exit `1` and alert. Stop a run with `systemctl stop`: no workspace may stay
in `/var/lib/certistack/workers/` on the node ([Commands](cli-reference.md#inspect)), and the alert fires, since that
run has no evidence. An alert that has never fired is an assumption.
