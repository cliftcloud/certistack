// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// The schema history in docs/reports.md has a row for the schema the
// code writes, and the row and the code's own note name the members the
// schema added, run_id among them (it was left out of both once). A new schema
// version fails here until its row is written.
func TestSchemaHistoryDocumentsTheCurrentSchema(t *testing.T) {
	guide, err := os.ReadFile(repoFile("docs", "reports.md"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(repoFile("pkg", "attest", "attest.go"))
	if err != nil {
		t.Fatal(err)
	}
	row := ""
	for _, line := range strings.Split(string(guide), "\n") {
		if strings.HasPrefix(line, "| "+attest.CurrentReportSchemaVersion+" |") {
			row = line
		}
	}
	if row == "" {
		t.Fatalf("docs/reports.md has no schema history row for %s, the schema the code writes", attest.CurrentReportSchemaVersion)
	}
	note := string(source)
	if at := strings.Index(note, "const CurrentReportSchemaVersion"); at > 0 {
		note = note[:at]
		if start := strings.LastIndex(note, "\n\n"); start >= 0 {
			note = note[start:]
		}
	}
	// The members each schema added that its row and the code's note must name.
	// A schema not listed here has no member this test knows to look for, and
	// whoever adds one lists it.
	members := map[string][]string{
		"1.6": {"run_id", "plan_sha256", "worker_sha256"},
		"1.7": {"rto_target_seconds", "admission", "soak", "status_reads", "validated_plan_sha256", "resolved_plan_sha256", "plan_digest_format", "required_available_mib", "preflight_denied_memory", "pve_version", "pbs_version", "pbs_client_version", "version_support"},
	}
	want, known := members[attest.CurrentReportSchemaVersion]
	if !known {
		t.Fatalf("schema %s has no members listed in this test: name what it added so its row and note are held to it", attest.CurrentReportSchemaVersion)
	}
	for _, member := range want {
		if !strings.Contains(row, "`"+member+"`") {
			t.Errorf("the schema %s row of docs/reports.md does not list %s", attest.CurrentReportSchemaVersion, member)
		}
		if !strings.Contains(note, member) {
			t.Errorf("the note on CurrentReportSchemaVersion in pkg/attest/attest.go does not list %s", member)
		}
	}
}

// The signer lifecycle is documented where an operator meets signing
// keys, and says what a keyring does not do. The behaviours it describes are
// pinned by pkg/attest TestKeyringHasNoTemporalAuthorization; this keeps the
// documentation in place and the pages that send a reader to it linked.
func TestSignerLifecycleIsDocumentedAndLinked(t *testing.T) {
	read := func(parts ...string) string {
		t.Helper()
		data, err := os.ReadFile(repoFile(parts...))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(data)), " ")
	}
	architecture := read("docs", "architecture.md")
	for _, want := range []string{
		"Signer Lifecycle: Rotation, Retirement and Compromise",
		"A keyring is the set of keys the verifier accepts today, and it keeps no dates",
		"Keeping a key in a keyring keeps trusting it for everything",
		"Deleting a key from a keyring stops the verification of everything it ever signed",
		"Rotate without losing verification",
		"a separate historical keyring",
		"If a signing key may have been exposed",
		"a report's `timestamp` is chosen by whoever signed it",
		"`created_at`, `name` and `node` are labels the verifier does not evaluate",
	} {
		if !strings.Contains(architecture, want) {
			t.Errorf("docs/architecture.md no longer says %q", want)
		}
	}
	const anchor = "architecture.md#6-signing-and-verification"
	for _, page := range []string{"reports.md", "troubleshooting.md"} {
		text := read("docs", page)
		index := strings.Index(text, "signer lifecycle")
		if index < 0 || !strings.Contains(text[index:], anchor) {
			t.Errorf("docs/%s does not send the reader to the signer lifecycle (%s)", page, anchor)
		}
	}
	// The troubleshooting advice to delete a revoked signer carries its cost.
	if troubleshooting := read("docs", "troubleshooting.md"); !strings.Contains(troubleshooting, "Remove a revoked signer by deleting its entry, but that also stops the verification of every genuine report the key signed") {
		t.Error("docs/troubleshooting.md tells the reader to delete a revoked signer's entry without saying it also drops the verification of its history")
	}
}

// The guides say what the tier soak checks, because an operator sizes a probe's
// timeout and reads a failed soak by it. The behaviour is pinned by
// pkg/orchestrator and pkg/attest; this keeps the sentences that describe it,
// and the pages that send a reader to them, in place.
func TestTierSoakIsDocumentedAsServiceChecks(t *testing.T) {
	read := func(parts ...string) string {
		t.Helper()
		data, err := os.ReadFile(repoFile(parts...))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(data)), " ")
	}
	reference := read("docs", "plan-reference.md")
	for _, want := range []string{
		"### Tier soak: what it checks",
		"Every 30 seconds, counted from the end of the previous round of checks, and once more when the period is over",
		"an outage that ends inside that budget is not a failed check; one that outlasts it is",
		"A failed check fails the VM** and the tier, at the first one",
		"A read that fails is not evidence that the VM runs",
		"A wait in which not one read worked fails its VMs too, however short it was",
		"Only the last tier's soak is outside the RTO",
		"runs each VM's service probes (the wire probes and `qga`) again every 30 seconds and once more when the period is over",
	} {
		if !strings.Contains(reference, want) {
			t.Errorf("docs/plan-reference.md no longer says %q", want)
		}
	}
	for _, stale := range []string{
		"it does not run the probes again at its end, so it does not show that a service which answered once still answers",
		"The soak only watches that QEMU keeps each VM running",
	} {
		if strings.Contains(reference, stale) {
			t.Errorf("docs/plan-reference.md still says %q, which an earlier change made false", stale)
		}
	}
	guide := read("docs", "reports.md")
	for _, want := range []string{
		"**Tier soak.** A report of schema 1.7 or later records",
		"`NOT BOUND: soak service checks (...)`",
	} {
		if !strings.Contains(guide, want) {
			t.Errorf("docs/reports.md no longer says %q", want)
		}
	}
	// The schema 1.7 row names the soak's members, wherever in the row they are
	// (the row also carries the other members 1.7 added).
	for _, line := range strings.Split(string(mustRead(t, repoFile("docs", "reports.md"))), "\n") {
		if strings.HasPrefix(line, "| 1.7 |") {
			for _, member := range []string{"`soak`", "`status_reads`", "`first_sample_at`", "`worst_duration`"} {
				if !strings.Contains(line, member) {
					t.Errorf("the schema 1.7 row of docs/reports.md does not name %s", member)
				}
			}
		}
	}
	troubleshooting := read("docs", "troubleshooting.md")
	for _, want := range []string{
		`### Issue 22: "service check N of the soak failed"`,
		"so its liveness is unknown",
		"it needs `VM.Audit` on the VM",
	} {
		if !strings.Contains(troubleshooting, want) {
			t.Errorf("docs/troubleshooting.md no longer says %q", want)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
