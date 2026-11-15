# Usage statistics (opt-in)

**The statistics are off by default.** CertiStack tells Clift Cloud nothing unless you say yes.
Until you opt in, it makes no network connection for them, and an air-gapped controller never
notices the feature exists. If you opt in, this page lists exactly what is sent, when, and how to
stop it.

## The five fields

The report is exactly these five fields, as `certistack telemetry show` prints them:

```json
{
  "install_id": "3f0c8a5e-6b1d-4e2a-9c47-0d5e1b7a92f4",
  "version": "v0.1.0",
  "cluster_count": 2,
  "last_test_run": "2026-10-01",
  "business_use": false
}
```

| Field | Example | What it is | Why |
| --- | --- | --- | --- |
| `install_id` | `3f0c8a5e-6b1d-4e2a-9c47-0d5e1b7a92f4` | A random UUID made when you opt in. It is not derived from your hardware, host name, addresses or user name. | To count an installation once |
| `version` | `v0.1.0` | The CertiStack version: printable ASCII, at most 64 characters | To know when a release can be retired |
| `cluster_count` | `2` | How many distinct Proxmox VE clusters you ran a test on, counted from salted hashes that stay on your machine. A cluster is the certificate in the `CERTISTACK_PVE_CA_SOURCE` file: every node of one cluster shares it, and a standalone node has its own. | To tell a lab from a fleet |
| `last_test_run` | `2026-10-01` | The UTC date (never the time) of your last completed restore test; empty until one completes | To see whether people keep testing |
| `business_use` | `false` | Your yes or no to "Do you use CertiStack for a business or commercial purpose?" | To learn whether it is used at work |

Nothing else is sent: no host names, addresses, VM names or IDs, plan contents, credentials,
report contents or test results. A test runs a full `run` with distinctive names, addresses and
tokens planted everywhere, and fails if any of them reaches the request.

## When it is sent

- Only after a completed `run` that tested at least one VM. No other command sends, and it is
  never from the PVE node.
- At most once every 24 hours. The `install_id` and the time of the last report are kept in
  `telemetry.json`. That holds for a stored answer and for `CERTISTACK_TELEMETRY=1` alike.
- As one `POST` to `https://certistack.dev/api/telemetry`, with `Content-Type: application/json`
  and the user agent `certistack-telemetry/<version>`.
- Within 3 seconds, end to end. There is no retry, and a redirect is not followed. The command
  waits at most 2 seconds for it. A failure is silent (`--debug` shows it) and never changes the
  exit status. When the statistics are on but `telemetry.json` cannot be written, nothing is sent
  either, and the run ends with one warning that names the file and the fix.
- It honours the standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`).

`certistack telemetry show` prints the exact bytes a report sent now would carry. When the statistics
are off, it says `nothing is sent: disabled` and why. With `CERTISTACK_TELEMETRY=1` and no report
sent yet, no install exists, so the `install_id` it prints is a sample. Without the variable, where
`telemetry.json` holds an install that runs with it keep (a scheduled unit's), `status` and `show`
say so: `this shell does not set it`, and when that install last sent.

## What counts as a cluster

The `cluster_count` counts Proxmox VE clusters, not nodes. A run identifies its cluster by the
SHA-256 fingerprint of the first CA certificate in the file that `CERTISTACK_PVE_CA_SOURCE` names,
the cluster CA the controller already trusts. Every node of a cluster signs with the same CA, and
a standalone node has its own. The fingerprint is hashed again with the random salt of your install
and kept as that hash only. Neither the fingerprint nor the hash is sent.

Without a CA file, or with a file that holds no certificate, the node name is counted instead. The
same cluster then counts once by name and once by CA when you add the file later.

## Turn it on or off

The first `run`, `plan`, `doctor` or `init` at a terminal asks once:

```text
Share anonymous usage statistics with Clift Cloud? Nothing but the five fields shown by `certistack telemetry show` is sent. [y/N]
```

If you answer yes, it also asks:

```text
Do you use CertiStack for a business or commercial purpose? [y/N]
```

Enter, or anything but `y` or `yes`, means no. Your answer is stored, so you are asked only once.
Scheduled jobs, CI and the appliance have no terminal, so they are never asked and stay off. A
`docker compose run` started at a terminal has one (unless you pass `-T`): it asks once and keeps
the answer in the state mount (see [CI, containers, the appliance](#ci-containers-the-appliance)).
Pass `-T`, or set `DO_NOT_TRACK=1` in the Compose file's `environment:`, to never be asked.

To change your mind later:

| Command | Does |
| --- | --- |
| `certistack telemetry status` | Says whether it is on, and why |
| `certistack telemetry show` | Prints what would be sent now |
| `certistack telemetry enable [--business]` | Opts in |
| `certistack telemetry disable` | Opts out and forgets the install ID on this machine |
| `certistack telemetry reset` | Deletes `telemetry.json`, so the question is asked again. With no file, it says `Nothing to reset` and names the file it looked for |

While `CERTISTACK_TELEMETRY=1` is still set, `disable` and `reset` say so: they forget the install,
but the next completed run reports as a new one. Unset the variable to stop the reports.

Environment variables override the stored answer (strongest first). They are read from the
process environment only, never from an `--env-file`:

| Variable | Effect |
| --- | --- |
| `DO_NOT_TRACK=1` | Off, whatever else is set |
| `CERTISTACK_TELEMETRY=0` (or `off`, `false`, `no`) | Off |
| `CERTISTACK_TELEMETRY=1` (or `on`, `true`, `yes`) | On, for CI and containers. It stores no answer. It keeps the install (the `install_id`, the salt and the time of the last report) in `telemetry.json`, so it counts once and reports at most once every 24 hours. Where that file cannot be read or written, it sends nothing; a run whose file cannot be written says so in one warning ([Scheduled runs](#scheduled-runs)). Add `CERTISTACK_TELEMETRY_BUSINESS=1` to answer the business question with yes. |
| `CERTISTACK_TELEMETRY_URL` | Another address, for testing only (`https`, or `http` to a loopback host) |

Your answer lives in `telemetry.json` in your configuration directory
(`~/.config/certistack/` on Linux), mode `0600`. A missing or unreadable file means off. The
install that `CERTISTACK_TELEMETRY=1` keeps goes in the same file, with no answer stored beside it,
so the first-run question is still asked at a terminal when the variable is unset.

## Scheduled runs

A job that [runs on a schedule](automation.md) has no terminal: it is never asked and stays off.
To opt it in, add the variable to its unit with
`sudo systemctl edit certistack-validate@nightly.service`:

```ini
[Service]
Environment=CERTISTACK_TELEMETRY=1
```

The `certistack` account has no home directory, so the unit on that page sets
`Environment=XDG_CONFIG_HOME=%S/certistack`, and the install is kept in
`/var/lib/certistack/certistack/telemetry.json`. To see what the unit does, give `telemetry status`
or `show` the unit's environment, both variables:
`sudo -u certistack env CERTISTACK_TELEMETRY=1 XDG_CONFIG_HOME=/var/lib/certistack certistack telemetry status`.

A unit without that line has nowhere to keep the install, so it sends nothing, and each run ends
with `Warning: no usage statistics were sent`, the file it could not write and this fix. A cron job
needs the same: `CERTISTACK_TELEMETRY=1` and `XDG_CONFIG_HOME=/var/lib/certistack` on their own
lines in `/etc/cron.d/certistack`, and the directory
`sudo install -d -m 0700 -o certistack /var/lib/certistack/certistack`.

## CI, containers, the appliance

- A CI job has no terminal: it is never asked and stays off. To opt a CI job in, set
  `CERTISTACK_TELEMETRY=1`. To make sure it never reports, set `DO_NOT_TRACK=1`. A job that starts
  from an empty home directory keeps no `telemetry.json` between jobs, so each job reports as a new
  install. Keep `~/.config/certistack/` between jobs, for example in the CI cache, to count once.
- The controller container and the appliance send nothing as shipped. To opt in, add
  `CERTISTACK_TELEMETRY=1` to the container's own environment: the `environment:` block of
  `deploy/controller/compose.yaml`, or `docker compose run -e CERTISTACK_TELEMETRY=1`. On the
  appliance, add it to the `podman run` command in `/usr/local/bin/certistack-controller`
  (`podman run --env CERTISTACK_TELEMETRY=1 ...`). It is not read from `controller.env`: the
  controller loads that file literally and refuses any name that is not one of its own settings.
- The container has no home directory and a read-only root. The Compose file and the appliance
  wrapper set `XDG_CONFIG_HOME` to `/var/lib/certistack/.config`, inside the state mount, so the
  install is kept in `/var/lib/certistack/.config/certistack/telemetry.json` (`state/.config/certistack/telemetry.json`
  beside the Compose file). With a state mount that is read-only, or a `docker run` that sets neither
  `XDG_CONFIG_HOME` nor a writable home, the container sends nothing.

## Retention and deletion

The server keeps only the latest report for each `install_id` and when it arrived. It stores no IP
address, and it deletes a record after 45 days without a new report. To delete yours sooner:

1. Run `certistack telemetry show` and note the `install_id`.
2. Run `certistack telemetry reset`. Nothing more is sent, and the ID is forgotten on your machine.
3. Send the ID to `privacy@certistack.dev` with the subject "Telemetry deletion". The ID is random,
   so it is the only way to find your record.

The code that sends the report is in one place, `pkg/telemetry`, and its tests check every promise
on this page.
