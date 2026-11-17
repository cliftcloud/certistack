# Contributing to CertiStack

Thank you for helping improve CertiStack. Pull requests are reviewed as maintainers have time; the Community Edition is
supported on a best-effort basis ([SUPPORT.md](SUPPORT.md)).

## Contributor License Agreement

Every pull request must be covered by the [Contributor License Agreement](CLA.md) before it can be merged. You keep the
copyright in your contribution. The CLA grants Clift Cloud LLC the rights to offer CertiStack under the AGPL and under a
separate commercial license ([LICENSING-FAQ.md](LICENSING-FAQ.md) explains why).

1. Open your pull request.
2. The CLA bot comments with a link to [CLA.md](CLA.md).
3. Reply to that comment with the exact text it asks for.
4. The bot updates the check once your signature is recorded. You sign once for all future contributions.

A pull request cannot be merged until the check passes. The check identifies each commit author by GitHub account, so
author your commits with an e-mail address linked to your account; a commit GitHub cannot link to an account cannot be
signed for. The check refuses a pull request of more than 100 commits: squash or split it. Only pull requests opened
by GitHub's Dependabot account are exempt.

## Issues

Report bugs and request features in the [issue tracker](https://github.com/cliftcloud/certistack/issues/new/choose).
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

A bug report needs the output of `certistack version`, your Proxmox VE and PBS versions, the steps to reproduce,
expected and actual behaviour, and the relevant `--debug` output.

## Development

You need Go 1.26.11, the version in `go.mod`, and Linux (or Windows with WSL). Integration testing needs a Proxmox VE
test cluster.

```bash
# Build all binaries
make build

# Cross-compile for Linux (for deploying to PVE nodes)
make build-linux

# Run tests
make test

# Run tests with coverage
make cover

# Format code, or only check the formatting
make fmt
make fmt-check

# Run static analysis
make vet

# Build the documentation site (first: python3 -m pip install -r requirements-docs.txt)
make docs
```

### Tests

- Every package under `pkg/` and `internal/` should have `_test.go` files. Prefer table-driven tests.
- Integration tests that need PVE or PBS access should use build tags.
- The `chaos` build tag turns on fault triggers in `pkg/orchestrator` for manual fault testing: the runner's
  `ChaosTrigger` option (`panic` or `kill-daemon`) then panics, or exits with status 137, as a VM's probes start.
  Without the tag, as in every release build, the option does nothing.
- Tests that run the controller's commands through the host's real `systemd-run` need root on a systemd host and are
  off by default: `sudo CERTISTACK_TEST_SYSTEMD=1 go test ./pkg/controller -run Live -v` (add `-short` to skip the one
  that waits out a 90-second lease). Run them when you change a script the controller sends to a node.
- The guest-network tests in `internal/guestnet` run netplan's generator and skip without it (`apt install netplan.io`
  on Debian or Ubuntu). CI sets `CERTISTACK_REQUIRE_NETPLAN=1`, which makes a missing generator fail them; set it
  yourself to check that none is skipped.

CI runs the unit tests (including the contract tests in `internal/repocontract`), the race detector, `make fmt-check`,
`make vet` and `govulncheck` on every pull request. Before a release, a maintainer also runs the built executable
against a real Proxmox VE and PBS: restores of each supported kind of VM, an injected probe fault that must fail exactly
that probe, and an interrupted run that recovery must clean up, with every report judged by `verify-report --expect-*`.
The executable that passes is the one released ([How releases are built](SECURITY.md#how-releases-are-built)). The
scripts in `scripts/` that drive those runs are maintainer tooling.

### Layout

The Community Edition is a CLI and a local recovery-validation engine. It has no web server, dashboard, daemon, webhook
listener or entitlement code; rendering, delivery, scheduling and multi-tenant features belong to the
[Enterprise Edition](https://certistack.dev/docs/editions/). When you add or change a plan field, update "The keys"
in `docs/plan-reference.md` in the same pull request.

| Path | Purpose |
| --- | --- |
| `cmd/certistack` | The CLI, and the hidden `node-run`, `node-plan`, `node-discover`, `node-inspect` and `node-check` modes the controller runs on a PVE node. |
| `pkg/config` | Plan parser, alias normalisation and validator ([the keys](https://certistack.dev/docs/plan-reference/#the-keys)). |
| `pkg/initplan` | `init`: read-only discovery of VMs with backups, overlay storages and free IDs, and a first plan that validates. |
| `pkg/runner` | The local execution path: host lock, journal, PVE and PBS clients, orchestrator, RTO check, report writing. |
| `pkg/controller` | SSH bootstrap of the node worker, result retrieval, teardown verification, controller-side report writing. |
| `pkg/nodeapi` | The versioned controller/worker result contract. |
| `pkg/orchestrator` | Tiered recovery: admission, snapshot resolution, mapping, overlays, sandbox VM lifecycle, guest network, probes, soak, teardown evidence. |
| `pkg/pbs`, `pkg/pve`, `pkg/sdn` | PBS map/unmap client; PVE REST client with task tracking; sandbox SDN zone and VNet. |
| `pkg/admission` | Host admission control and capacity reservation from `/proc/meminfo` and `/proc/stat`. |
| `pkg/probe` | Probes: `qmp`, `synthetic` (TCP, HTTP/TLS, DNS, LDAP, SQL Server, SMB), `qga` and `screendump`. |
| `pkg/attest` | Canonical JSON (RFC 8785), the `Signer` hook the Enterprise Edition fills, keyring loading, report verification and limits, and the report schema (`attest.CurrentReportSchemaVersion`). Community has no code that makes a signature. |
| `pkg/cleanup` | LIFO teardown stack with signal and panic unwinding. |
| `pkg/telemetry` | The opt-in usage report ([usage statistics](https://certistack.dev/docs/telemetry/)). |
| `pkg/progress`, `pkg/runphase` | The run's progress timeline and its `[Phase N of M]` lines. |
| `pkg/recovery` | Public crash-recovery entry point for programs built on the engine. |
| `internal/journal`, `internal/process` | The run journal (`active.json`) and host lock; process identity so recovery never acts on a reused PID. |
| `internal/preflight` | Node preflight checks used by `doctor` and by the worker. |
| `internal/recovery` | Journal-scoped cleanup of loops, overlays, VMs, host addresses and SDN objects. |
| `internal/guestnet` | Guest network adapter for the sandbox, applied to the overlay with `guestfish`. |
| `internal/sysutil` | Overlays, loop devices, private directories, `nft`/`sysctl` containment and the command runner. |
| `internal/support` | The table of tested, untested and unsupported Proxmox VE and PBS versions. |
| `internal/nodecheck`, `internal/nodesetup` | `certistack check` and `certistack setup`. |
| `internal/guestinspect` | `init --inspect`: finds the services in a Linux backup from its read-only files. |
| `internal/diskslot`, `ifname`, `macaddr`, `ldapdn`, `httptarget`, `qgacommand`, `vmlimits`, `envtypes` | Small shared validation rules. |
| `internal/repocontract` | Tests that tie the workflows, deployment files and documentation to the code. |
| `examples/`, `testdata/plans` | Plans to copy, and larger fixtures; the tests validate both. |
| `deploy/controller`, `deploy/appliance`, `terraform/` | Controller image and Compose file; Packer VM template; Terraform module for the PVE role, user and token. |
| `scripts/`, `release/` | Release build and checksum tooling, the release registry, maintainer test tooling. |
| `docs/`, `mkdocs.yml` | The documentation site (`make docs`). |

`certistack run` loads a plan and stages a worker on the node over SSH (`pkg/controller`). The worker's `node-run` takes
the host lock and hands over to `pkg/runner`, which records the run in the journal, calls the orchestrator and marks the
journal clean. The controller then checks the node's journal and writes the report. `certistack recover` cleans up
from the same journal after an interrupted run.

## Code style

- Standard Go conventions (`gofmt`, `go vet`).
- `log/slog` for structured logging in library code; `fmt.Printf` only for CLI output.
- Wrap errors with `fmt.Errorf("context: %w", err)`.
- `crypto/subtle.ConstantTimeCompare` for secret comparisons.
- File modes: `0600` for keys, credentials and reports, `0700` for directories that hold them; `0644` and `0755` only
  for files meant to be world-readable, such as a CA certificate.

## Pull requests

1. Fork the repository and create a feature branch.
2. Make sure `make test`, `go test -race ./...`, `make fmt-check` and `make vet` pass.
3. Update the documentation for new features or commands.
4. Add an entry under `[Unreleased]` in `CHANGELOG.md`.
5. Open a pull request with a clear description.

## License

CertiStack Community Edition is licensed under the [GNU Affero General Public License, version 3 or any later
version](LICENSE) (AGPL-3.0-or-later). By contributing, you agree to the [Contributor License Agreement](CLA.md), which
permits Clift Cloud LLC to distribute your contribution under the AGPL and, separately, under commercial terms.
