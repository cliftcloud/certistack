# Controller container

The controller image runs CertiStack on a management VM, not on a Proxmox VE host. It has no KVM device, host
filesystem mount, Docker socket or Linux capabilities, publishes no network port, and leaves no service running on the
node; a `run` copies the executable over verified SSH into a unique `/var/lib/certistack/workers/<uuid>` directory on
the node and removes it afterwards. The controller keeps the report, unsigned. An account that may run an uploaded root
worker is root-equivalent on the node ([SECURITY.md](../../SECURITY.md)).

Run every command from the repository root. The container runs as UID/GID 65532, so its files belong to that user.

## Prepare controller secrets

```bash
sudo install -d -m 0700 -o 65532 -g 65532 deploy/controller/secrets deploy/controller/state deploy/controller/plans
sudo install -m 0600 -o 65532 -g 65532 deploy/controller/secrets/controller.env.example deploy/controller/secrets/controller.env
sudo install -m 0600 -o 65532 -g 65532 deploy/controller/secrets/known_hosts.example deploy/controller/secrets/known_hosts
```

`install` sets owner and mode as it writes; a plain `cp` would leave root-owned files the container cannot read. Edit
both files as root (`sudoedit`). A default PBS certificate is self-signed, so uncomment `PBS_FINGERPRINT` in
`controller.env` and fill in the fingerprint from the PBS dashboard (Show Fingerprint) or
`proxmox-backup-manager cert info`. Then install the SSH identity at the path `controller.env` names:

```bash
sudo install -m 0600 -o 65532 -g 65532 /path/to/controller_ed25519 deploy/controller/secrets/id_ed25519
```

A stock Proxmox VE node signs its API certificate with the cluster's own CA, which the container does not trust;
without it, `certistack check` fails at layer 5 with "unknown authority". Run `certistack setup pve-ca --env-file FILE`
on the host, where the SSH paths in that file exist; it writes `pve-root-ca.pem` next to the file. Or copy
`/etc/pve/pve-root-ca.pem` from the node. Install it and uncomment `CERTISTACK_PVE_CA_SOURCE` in `controller.env`; while
that line is active, a missing CA file stops every run before the transfer:

```bash
sudo install -m 0600 -o 65532 -g 65532 pve-root-ca.pem deploy/controller/secrets/pve-ca.pem
```

A PVE certificate signed by a CA in the container's trust store needs no CA file.

Fill `known_hosts` with a host key approved through your change process. Never use `StrictHostKeyChecking=no`,
`UserKnownHostsFile=/dev/null` or `PVE_TLS_INSECURE=true` in production.

## Use the published image

Each release publishes `ghcr.io/cliftcloud/certistack-controller:<version>` (the release tag without its `v`, such as
`0.1.2`) and records its digest in the release asset `CONTAINER-IMAGE.txt`. Download that file,
`certistack-linux-amd64`, `SHA256SUMS-bin.txt` and `SHA256SUMS-bin.txt.asc` from the same release, import the release
key as described in [Verifying release integrity](../../SECURITY.md#verifying-release-integrity), and verify the
signature and both checksums before you use the image reference:

```bash
gpgv --keyring /secure/certistack/release-signing-key.gpg \
  SHA256SUMS-bin.txt.asc SHA256SUMS-bin.txt
sha256sum --strict --check SHA256SUMS-bin.txt
export CERTISTACK_CONTROLLER_IMAGE="$(cat CONTAINER-IMAGE.txt)"
sudo --preserve-env=CERTISTACK_CONTROLLER_IMAGE \
  docker compose -f deploy/controller/compose.yaml run --rm controller version
```

The Compose file sets `pull_policy: missing`: an image already on the host is used as it is, and the registry is
contacted only for a missing one. Add `--pull always` to `run` to fetch it again.

## Build and run

```bash
docker build -f deploy/controller/Dockerfile -t certistack-controller:dev .
export CERTISTACK_CONTROLLER_IMAGE=certistack-controller:dev
sudo --preserve-env=CERTISTACK_CONTROLLER_IMAGE \
  docker compose -f deploy/controller/compose.yaml run --rm controller \
  run /plans/my-first-plan.yaml --node pve-01 --ssh-host pve-01.example.internal \
  --ssh-identity /run/certistack-secrets/id_ed25519 \
  --ssh-known-hosts /run/certistack-secrets/known_hosts \
  --env-file /run/certistack-secrets/controller.env
```

The Dockerfile needs BuildKit, the default from Docker 23; older engines need `DOCKER_BUILDKIT=1` in front of
`docker build` (`make container` sets it), because the legacy builder fails on the `release-binary` stage.

Plans are mounted read-only at `/plans`, and reports are kept in the state volume at `/var/lib/certistack`. The example
environment file connects as root; to connect as another account, see
[the sudoers rule for a non-root account](https://certistack.dev/docs/manual-setup/#the-sudoers-rule-for-a-non-root-account).

### The environment file

The controller reads `controller.env` itself, with `--env-file`, and takes each value literally. Compose's `env_file` is
not used: it interpolates `$VAR` and `${VAR}`, processes escapes in quoted values and strips inline `#` comments, so a
credential could reach the container changed. Settings the file does not hold, such as `CERTISTACK_TELEMETRY`, go in the
container's own environment (`environment:` in the Compose file, or `run -e NAME=value`). An opt-in to
[usage statistics](https://certistack.dev/docs/telemetry/) keeps its install ID in the state mount, under
`XDG_CONFIG_HOME`.
