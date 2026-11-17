# Usage statistics

Off by default. Until you opt in, CertiStack makes no connection for them.

## What is sent

Five fields, as `certistack telemetry show` prints them:

```json
{
  "install_id": "3f0c8a5e-6b1d-4e2a-9c47-0d5e1b7a92f4",
  "version": "v0.1.1",
  "cluster_count": 2,
  "last_test_run": "2026-10-01",
  "business_use": false
}
```

- `install_id`: a random UUID made when you opt in, not derived from your hardware, names or addresses.
- `version`: the CertiStack version, printable ASCII, at most 64 characters.
- `cluster_count`: how many Proxmox VE clusters you tested, counted on your machine from salted hashes of each
  cluster's CA (`CERTISTACK_PVE_CA_SOURCE`), or of the node name without one.
- `last_test_run`: the UTC date of your last completed test.
- `business_use`: your answer to "Do you use CertiStack for a business or commercial purpose?"

Nothing else: no host names, addresses, VM names or IDs, plans, credentials, reports or results.

## When it is sent

After a completed `run` that tested at least one VM, at most once every 24 hours, never from the node.
It is one `POST` to `https://certistack.dev/api/telemetry` that honors `HTTPS_PROXY` and `NO_PROXY`, with no retry. A
failure is silent (`--debug` shows it) and never changes the exit status.

## Turn it on or off

The first `run`, `plan`, `doctor` or `init` at a terminal asks once; the default is no. To change your mind:

| Command | Does |
| --- | --- |
| `certistack telemetry status` | Says whether it is on, and why |
| `certistack telemetry show` | Prints what would be sent now |
| `certistack telemetry enable [--business]` | Opts in |
| `certistack telemetry disable` | Opts out and forgets the install ID |
| `certistack telemetry reset` | Deletes `telemetry.json`, so the question is asked again |

Environment variables win over the stored answer, strongest first. They are never read from `controller.env`.

| Variable | Effect |
| --- | --- |
| `DO_NOT_TRACK=1` | Off |
| `CERTISTACK_TELEMETRY=0` | Off |
| `CERTISTACK_TELEMETRY=1` | On, storing no answer. Unset it to stop: `disable` and `reset` only forget the install |
| `CERTISTACK_TELEMETRY_BUSINESS=1` | With `CERTISTACK_TELEMETRY=1`: business use is yes |

Your answer lives in `~/.config/certistack/telemetry.json`; a missing or unreadable file means off.

<a id="service-accounts"></a>

## Under a service account

An account without a terminal is never asked: set `CERTISTACK_TELEMETRY=1` to opt it in. It also needs a writable
`telemetry.json`, or nothing is sent and each run warns `no usage statistics were sent`: set `XDG_CONFIG_HOME` to a
directory the account can write.

The controller container and appliance send nothing as shipped. Add `CERTISTACK_TELEMETRY=1` to the container's
environment: `environment:` in `deploy/controller/compose.yaml`, or `podman run --env` in the appliance's
`/usr/local/bin/certistack-controller`.

<a id="retention-and-deletion"></a>

## Deletion

The server keeps only the latest report for each `install_id`, stores no IP address, and deletes a record after 45
days without a new one. To delete yours sooner, note the `install_id` from `certistack telemetry show`, run
`certistack telemetry reset`, and send the ID to `privacy@certistack.dev` with the subject "Telemetry deletion".
