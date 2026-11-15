# Contributing to CertiStack

Thank you for your interest in improving CertiStack! This document provides guidelines for contributing.

CertiStack Community Edition is supported on a best-effort basis; see
[SUPPORT.md](SUPPORT.md). Pull requests are reviewed as maintainers have time.

## Contributor License Agreement (CLA)

Every contribution (pull request) must be covered by our
[Contributor License Agreement](CLA.md) before it can be merged. This
isn't about taking anything from you — you keep full copyright ownership
of your contribution. It grants Clift Cloud LLC the rights needed to
offer CertiStack under both the AGPL (this repository) and a separate
commercial license (see [LICENSING-FAQ.md](LICENSING-FAQ.md) for why
that matters).

The process is automated:

1. Open your pull request as normal.
2. A CLA-assistant bot comments with a link to [CLA.md](CLA.md) and
   instructions.
3. Reply to that comment with the exact text it asks for to sign.
4. The bot updates the PR status once your signature is recorded. You
   only need to sign once — it's remembered for future contributions.

A PR cannot be merged until this check passes. The check identifies every
commit author by GitHub account, so author your commits with an email
address linked to your account: a commit GitHub cannot link to an account
cannot be signed for, whatever name it carries. The check also refuses a PR
of more than 100 commits; squash or split it. Only pull requests opened by
GitHub's Dependabot account are exempt.

## Reporting Issues

- Use this repository's issue tracker for bug reports and feature requests
- For security vulnerabilities, see [SECURITY.md](SECURITY.md) — **do not** open a public issue

### Bug Reports

Please include:
1. CertiStack version (`certistack version`)
2. Proxmox VE and PBS versions
3. Steps to reproduce
4. Expected vs actual behavior
5. Relevant log output (`--debug` flag)

## Development Setup

### Prerequisites

- Go 1.26.11+
- Linux development environment (recommended) or Windows with WSL
- Access to a Proxmox VE test cluster (for integration testing)

### Building

```bash
# Build all binaries
make build

# Cross-compile for Linux (for deploying to PVE nodes)
make build-linux

# Run tests
make test

# Run tests with coverage
make cover

# Format code
make fmt

# Run static analysis
make vet

# Build the documentation site (first: python3 -m pip install -r requirements-docs.txt)
make docs
```

### Project Structure

When you add or change a plan field, update "The keys" in
[docs/plan-reference.md](docs/plan-reference.md) in the same pull request.
The Community Edition is a CLI and a local recovery-validation engine. It has
no web server, dashboard, daemon, webhook listener or entitlement code; a pull
request that adds rendering, delivery, scheduling or multi-tenant features
crosses the [edition boundary](docs/editions.md).

| Path | Purpose |
| --- | --- |
| `cmd/certistack` | The CLI: `init`, `check`, `setup`, `validate`, `plan`, `doctor`, `run`, `verify-report`, `report`, `schema`, `inspect`, `recover`, `telemetry`, `version`, plus the hidden `node-run`, `node-plan`, `node-discover`, `node-inspect` and `node-check` modes the controller uploads to a PVE node. |
| `pkg/config` | YAML plan parser, alias normalisation, and validator. Every accepted, aliased, and rejected key is listed in the [plan reference](docs/plan-reference.md#the-keys). |
| `pkg/initplan` | `init`: discovery of the VMs with backups, their guests, the node's overlay storages and free IDs (read-only), and composition of a first plan that must validate. |
| `pkg/runner` | The local execution path used by the CLI and by products built on the engine: host lock, journal, PVE/PBS clients, orchestrator, RTO target check, report writing. |
| `pkg/controller` | Strict-SSH bootstrap of the temporary node worker, result retrieval, teardown verification and retry, controller-side report writing (`retention_days` is only recorded; a signer, when the Enterprise Edition sets one, signs the report; Community sets none). |
| `pkg/nodeapi` | Versioned controller/worker result contract. |
| `pkg/orchestrator` | Tiered recovery: admission, snapshot resolution, mapping, overlays, sandbox VM lifecycle, guest network recovery, probes, soak periods, teardown evidence. |
| `pkg/pbs`, `pkg/pve`, `pkg/sdn` | PBS map/unmap client; PVE REST client with UPID task tracking; isolated SDN zone and VNet lifecycle and read-only validation. |
| `pkg/admission` | `/proc/meminfo` and `/proc/stat` host admission controller and capacity reservation. |
| `pkg/probe` | Probe result types, with `qmp` (hypervisor state), `synthetic` (TCP, HTTP/TLS, DNS, LDAP, SQL Server, SMB), `qga` (constrained guest-agent checks) and `screendump` (PPM to PNG framebuffer capture). |
| `pkg/attest` | RFC 8785 canonical JSON, the `Signer` hook the Enterprise Edition fills (Community has no code that reads a private key or makes a signature; `pkg/attest/attesttest` makes signed reports for tests only), keyring loading, pinned-signer verification, the one-pass report scanner and its size and structure limits, and the report schema (`attest.CurrentReportSchemaVersion`, currently 1.7; every minor is additive, see the schema history in [docs/reports.md](docs/reports.md)). |
| `pkg/cleanup` | LIFO teardown stack with signal and panic unwinding. |
| `pkg/telemetry` | The opt-in usage report, off by default: the five-field payload, the `telemetry.json` state, the first-run question, the controls (`DO_NOT_TRACK`, `CERTISTACK_TELEMETRY`) and the one POST. Imported only by the command-line layer; it asks the first-run question before `run`, `plan`, `doctor` and `init`, and sends only after a completed `run`; see [usage statistics](docs/telemetry.md). |
| `pkg/progress` | Elapsed-time timeline printer used by the controller during a run. |
| `pkg/runphase` | The phases of a run, counted from the plan, and the integrity scan's time-left estimate: the `[Phase N of M]` lines of a run's progress. |
| `pkg/recovery` | Public crash-recovery entry point for programs built on the engine. |
| `internal/journal`, `internal/process` | Durable run journal (`active.json`) and host lock; process identity (kernel start ticks) so recovery never acts on a reused PID. |
| `internal/preflight` | Node preflight checks used by `doctor` and by the worker before any mutation. |
| `internal/recovery` | Journal-scoped reconciliation of loops, overlays, VMs, host addresses, and SDN objects; no host-wide sweep. |
| `internal/guestnet` | COW-only guest network adapter (ifcfg, NetworkManager, Netplan, systemd-networkd, ifupdown, firewalld probe rule) applied with `guestfish`. |
| `internal/sysutil` | `qemu-img` overlays, loop-device inspection, private directories, `nft`/`sysctl` containment, and the audited command runner. |
| `internal/support` | The one table of tested, untested and unsupported Proxmox VE and PBS version pairs. |
| `internal/nodecheck`, `internal/nodesetup` | `certistack check` (the layers a controller must pass before `plan`, the node-side ones run by a temporary worker) and `certistack setup` (the first-run wizard, and trust-node, pve-ca and the printed account script). |
| `internal/guestinspect` | `init --inspect`: finds the services a Linux backup runs from its read-only files (units and the listen settings of nginx, Apache, PostgreSQL, MariaDB/MySQL, Redis, sshd). |
| `internal/diskslot`, `ifname`, `macaddr`, `ldapdn`, `httptarget`, `qgacommand`, `vmlimits`, `envtypes` | Small packages that hold one validation rule each, shared by the plan loader, the runner and the verifier. |
| `internal/repocontract` | Tests that tie the workflows, deployment files and documentation to the code. |
| `examples/`, `testdata/plans` | Documentation-conformant plans to copy, and larger fixtures; the test suite validates both. |
| `deploy/controller`, `deploy/appliance`, `terraform/` | Unprivileged OCI image and Compose reference; Packer VM-template recipe; PVE role, service user, token and reference-VM example. |
| `scripts/`, `release/` | Release build and checksum tooling, the release registry, and maintainer test tooling. |
| `docs/`, `mkdocs.yml` | This documentation site (`make docs`). |

`certistack run` loads a plan and stages a temporary worker on the node over
SSH (`pkg/controller`). The worker's hidden `node-run` takes the host lock and
delegates to `pkg/runner`, which records durable run state, creates the PVE/PBS
clients, calls the orchestrator and marks the journal clean. The controller then
verifies the node's journal and writes the report. `certistack recover`
reconciles resources from the same journal after an interrupted run.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use `log/slog` for structured logging in library code
- Use `fmt.Printf` only for CLI user-facing output
- Wrap errors with `fmt.Errorf("context: %w", err)` for diagnostic chains
- Use `crypto/subtle.ConstantTimeCompare` for any secret comparisons
- Write file permissions as `0600` for keys, credentials and reports, and `0700` for directories that hold them; use `0644` and `0755` only for files meant to be world-readable (a CA certificate, for example)

## Testing

- All packages under `pkg/` and `internal/` should have `_test.go` files
- Use table-driven tests where applicable
- Integration tests requiring PVE/PBS access should use build tags
- Chaos tests use the `chaos` build tag: `go test -tags=chaos ./...`
- Tests that run the controller's commands through the host's real
  `systemd-run` need root on a systemd host and are off by default:
  `sudo CERTISTACK_TEST_SYSTEMD=1 go test ./pkg/controller -run Live -v`
  (add `-short` to skip the one that waits out a 90-second lease). Run them
  when you change a script the controller sends to a node; no other test of
  the package sees what systemd does to a script on its way to the shell.
- The guest-network tests in `internal/guestnet` run netplan's own generator to
  see which `.network` file networkd applies. They skip on a machine without
  netplan (`apt install netplan.io` on Debian or Ubuntu runs them). CI and the
  release gate install it and set `CERTISTACK_REQUIRE_NETPLAN=1`, which makes a
  missing generator fail those tests instead of skipping them; set it yourself
  to check that none of them is skipping.

### How maintainers test a release

Unit tests, `go vet`, the race detector and the contract tests in
`internal/repocontract` run in CI on every pull request. Before a release, a
maintainer also runs the built executable against a real Proxmox VE and PBS
pair. The runs restore the supported kinds of backed-up VM, inject one fault
into a probe and check that exactly that probe fails, interrupt a run to check
that recovery leaves nothing behind, and judge every report with
`verify-report --expect-*`. The executable that passes is the executable that
is released; [SECURITY.md](SECURITY.md) ("How releases are built") says how
that is enforced. The scripts in `scripts/` that drive those runs are
maintainer tooling and not documented for general use.

## Pull Request Process

1. Fork the repository and create a feature branch
2. Ensure `make test` and `make vet` pass
3. Update documentation if adding new features or CLI commands
4. Update `CHANGELOG.md` under the `[Unreleased]` section
5. Submit a pull request with a clear description

## License

CertiStack Community Edition is licensed under the [GNU Affero General
Public License, version 3 or any later version](LICENSE)
(AGPL-3.0-or-later). By contributing, you agree to
the terms of the [Contributor License Agreement](CLA.md) described
above, which permits Clift Cloud LLC to distribute your contribution
under the AGPL and, separately, under commercial license terms.
