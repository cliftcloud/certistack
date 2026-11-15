# Examples

Small, documentation-conformant plans to copy from. Every file here is
validated by the test suite (`cmd/certistack/examples_test.go`), uses only
fields described in [the plan reference](../docs/plan-reference.md), and uses
RFC 5737 documentation addresses, which no production network should use.

| File | What it shows |
| --- | --- |
| [`minimal-single-vm.yaml`](minimal-single-vm.yaml) | One tier, one VM, one TCP probe, backup-config inheritance. Start here. |
| [`three-tier-app.yaml`](three-tier-app.yaml) | A Linux database, application and web tier restored in dependency order, with TCP, HTTP, verified-HTTPS and guest-agent probes and an RTO target. |
| [`windows-domain.yaml`](windows-domain.yaml) | A Windows domain controller, then a SQL Server and a file server, with LDAP Root DSE, DNS SRV, SQL Server, SMB and `sc query` probes, and `network_recovery.mode: preserve`. |

A report to read without a run: [`sample-report-unsigned.json`](sample-report-unsigned.json)
is the report of a test run on a demonstration Proxmox VE and Backup Server (the
same run as the website's sample), in the form this edition writes it, without
the signature members. Read it with `certistack report show
examples/sample-report-unsigned.json`; `certistack verify-report --unsigned
--expect-outcome pass examples/sample-report-unsigned.json` judges its contents. It
is a sample, not evidence of anything about your systems.

The [plan reference](../docs/plan-reference.md#examples) explains each one and how
to choose probes for other services.

For completion and checks in an editor, `certistack schema > certistack-plan.schema.json`
prints a JSON Schema for these files; see [the plan reference](../docs/plan-reference.md#editor-completion-and-checks).

Larger fixtures used by the tests live in `../testdata/plans/`:
`valid_plan.yaml` is a three-tier identity/database/application stack with
QGA probes, and `multi_tier_sandbox.yaml` shows explicit `network_recovery`
addresses and an environment label.

Keep site-specific plans (real VM IDs, addresses, PBS namespaces) out of the
repository.
