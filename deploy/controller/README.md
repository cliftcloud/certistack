# CertiStack Controller container

This image is the CertiStack installation point. It runs on a management VM,
not on a Proxmox host. It has no KVM device, host filesystem mount, Docker
socket, Linux capabilities, or persistent PVE-side service.

The `run` command uses verified SSH to place the same controller executable into a
unique `/var/lib/certistack/workers/<uuid>` directory on the selected PVE node. That
worker maps PBS images, creates COW overlays, accesses QMP, runs Stage 2 probes
from the isolated VNet, returns evidence, and is removed. The controller
retains the report, unsigned (the Community Edition has no signing key to send
anywhere).

Every command below runs from the Community repository root, and the ones that
touch the secrets run as root. The container runs as UID/GID 65532, so its
secrets belong to that user with mode 0600 or 0700, which only root (or 65532)
can then read.

## Prepare controller secrets

```bash
sudo install -d -m 0700 -o 65532 -g 65532 deploy/controller/secrets deploy/controller/state deploy/controller/plans
sudo install -m 0600 -o 65532 -g 65532 deploy/controller/secrets/controller.env.example deploy/controller/secrets/controller.env
sudo install -m 0600 -o 65532 -g 65532 deploy/controller/secrets/known_hosts.example deploy/controller/secrets/known_hosts
```

`install` gives each file its owner and mode as it writes it. A plain `cp`
would leave root-owned files that the container's UID cannot read, and the
directory's owner is not inherited by the files in it. Edit both files as root
(`sudoedit`). A default PBS certificate is self-signed, so uncomment
`PBS_FINGERPRINT` in `controller.env` and fill in the fingerprint from the PBS
dashboard (Show Fingerprint) or `proxmox-backup-manager cert info`. Then place the
SSH identity at the path `controller.env` names, the same way:

```bash
sudo install -m 0600 -o 65532 -g 65532 /path/to/controller_ed25519 deploy/controller/secrets/id_ed25519
```

A stock Proxmox VE node signs its API certificate with the cluster's own CA, so
install that CA in almost every setup. Fetch it with
`certistack setup pve-ca --env-file FILE` on a host where the SSH paths in that
file exist (it writes `pve-root-ca.pem` next to the file), or copy
`/etc/pve/pve-root-ca.pem` from the node. Then install it and uncomment
`CERTISTACK_PVE_CA_SOURCE` in `controller.env`. While that line is active, a
missing CA file stops every run before the transfer:

```bash
sudo install -m 0600 -o 65532 -g 65532 pve-root-ca.pem deploy/controller/secrets/pve-ca.pem
```

A PVE certificate that a CA in the container's trust store signed needs no CA
file. Without the CA, `certistack check` in the container fails at layer 5 with
"unknown authority" and says to fetch the CA on the host, as above, because the
secrets directory is mounted read-only and `setup pve-ca` cannot write there.

Populate `known_hosts` from a host key approved through your normal change
process. Do not use `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`,
or `PVE_TLS_INSECURE=true` in production.

## Use the published image

Each Community release publishes `ghcr.io/cliftcloud/certistack-controller:<version>`
and records its digest in the release asset `CONTAINER-IMAGE.txt`. Download
that file, `certistack-linux-amd64`, `SHA256SUMS-bin.txt`, and
`SHA256SUMS-bin.txt.asc` from the same release. Obtain the release public key
through a separate trusted channel and compare its fingerprint out of band,
as described in [release verification](../../SECURITY.md#verifying-release-integrity).
Verify the signature and both checksums before using the image reference:

```bash
gpgv --keyring /secure/certistack/release-signing-key.gpg \
  SHA256SUMS-bin.txt.asc SHA256SUMS-bin.txt
sha256sum --strict --check SHA256SUMS-bin.txt
export CERTISTACK_CONTROLLER_IMAGE="$(cat CONTAINER-IMAGE.txt)"
sudo --preserve-env=CERTISTACK_CONTROLLER_IMAGE \
  docker compose -f deploy/controller/compose.yaml run --rm controller version
```

The image reference is a digest, so Compose uses an image this host already
holds and contacts the registry only to fetch a missing one
(`pull_policy: missing`). Add `--pull always` to `run` to fetch it again
deliberately.

## Build and run

From the same repository root:

```bash
docker build -f deploy/controller/Dockerfile -t certistack-controller:dev .
export CERTISTACK_CONTROLLER_IMAGE=certistack-controller:dev
sudo --preserve-env=CERTISTACK_CONTROLLER_IMAGE \
  docker compose -f deploy/controller/compose.yaml run --rm controller \
  run /plans/nightly.yaml --node pve-01 --ssh-host pve-01.example.internal \
  --ssh-user certistack --ssh-identity /run/certistack-secrets/id_ed25519 \
  --ssh-known-hosts /run/certistack-secrets/known_hosts \
  --env-file /run/certistack-secrets/controller.env
```

The controller reads `controller.env` itself, with `--env-file`, and takes each
value literally: Compose's own `env_file` is not used, because it interpolates
`$VAR` and `${VAR}`, processes escapes in quoted values and strips an inline
`#` comment, so a credential would reach the container different from the file.
The container's own environment (`environment:` in the Compose file, or
`run -e NAME=value`) holds only what that file does not, such as
`CERTISTACK_TELEMETRY`. The Compose file also sets `XDG_CONFIG_HOME` to
`/var/lib/certistack/.config`, inside the `state` mount, so that
`CERTISTACK_TELEMETRY=1` has a writable place to keep its install id (see
[usage statistics](../../docs/telemetry.md)).

The locally built `certistack-controller:dev` is used as it is: the policy above
never pulls an image that exists locally, so a build needs no registry. Rebuild
it after every source change.

The Dockerfile needs BuildKit, which Docker 23 and later use by default (older
engines need `DOCKER_BUILDKIT=1` in front of `docker build`; `make container`
sets it). Its `release-binary` stage names a file that exists only for a
release build, and BuildKit skips a stage the target does not use, where the
legacy builder builds every stage and fails on the missing file.

Mount plans read-only at `/plans` and mount the controller report volume at
`/var/lib/certistack`. The image intentionally does not publish a network port.
It is a Community controller image, not the separately packaged Enterprise
service; see the [edition boundary](../../docs/editions.md).

## PVE access model

The bootstrap mode is appropriate for Community and lab use, but a PVE account
that may execute an uploaded root worker is root-equivalent. Enterprise should
use a small, separately audited, signed node connector with a fixed RPC allow
list and mTLS authorization. Both choices avoid installing the full controller
stack on the hypervisor.
