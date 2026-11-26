# Examples

Plans to copy from. Each one is validated by the test suite (`cmd/certistack/examples_test.go`), uses only keys from
[the plan reference](https://certistack.dev/docs/plan-reference/), and uses RFC 5737 documentation addresses.

| File | What it shows |
| --- | --- |
| [`minimal-single-vm.yaml`](minimal-single-vm.yaml) | One tier, one VM, one TCP probe, backup-config inheritance. Start here. |
| [`three-tier-app.yaml`](three-tier-app.yaml) | A Linux database, application and web tier restored in dependency order, with TCP, HTTP, verified-HTTPS and guest-agent probes and an RTO target. |
| [`windows-domain.yaml`](windows-domain.yaml) | A Windows domain controller, then a SQL Server and a file server, with LDAP Root DSE, DNS SRV, SQL Server, SMB and `sc query` probes, and `network_recovery.mode: preserve`. |

[The plan reference](https://certistack.dev/docs/plan-reference/#examples) explains each one and how to choose probes
for other services. For completion and checks in an editor, `certistack schema > certistack-plan.schema.json` prints a
JSON Schema for these files
([editor completion](https://certistack.dev/docs/plan-reference/#editor-completion-and-checks)).

[`sample-report-unsigned.json`](sample-report-unsigned.json) is an unsigned sample report from a test run on a
demonstration Proxmox VE and Backup Server. An earlier build wrote it (engine v0.1.0, a pre-release), so its build
fields are not those of a current release. Read it with `certistack report show examples/sample-report-unsigned.json`,
and judge it with `certistack verify-report --unsigned --expect-outcome pass examples/sample-report-unsigned.json`. It
is a sample, not evidence about your systems.

Larger test fixtures are in `../testdata/plans/`: `valid_plan.yaml` is a three-tier identity, database and application
stack with guest-agent probes, and `multi_tier_sandbox.yaml` shows explicit `network_recovery` addresses and an
environment label.

Keep site-specific plans (real VM IDs, addresses, PBS namespaces) out of the repository.
