// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
)

// preflightRefusedReport is the report of a run the node's preflight refused before it
// created anything, as the worker builds it and the controller completes it
// (the cleanup confirmed from the node's journal).
func preflightRefusedReport(t *testing.T, result preflight.Result) *attest.Report {
	t.Helper()
	report := preflightFailureResult(mustLoadFixturePlan(), "pve-node-01", result, false).Report
	report.RunID = "run-refused"
	report.TeardownEvidence.JournalRecoveryVerified = true
	return report
}

// `report show` of an unsigned report of a run refused before any restore says
// what happened and nothing that did not: no disk read back, no recovery time,
// no memory reserved, no sandbox VM destroyed. It records the versions the run
// read, and it suggests the verify-report outcome that fits: denied for a
// capacity refusal, which verify-report then accepts, and none for a refusal
// for the node's versions.
func TestReportShowOfARunRefusedBeforeAnyRestore(t *testing.T) {
	neverAdmissible := preflightRefusedReport(t, preflight.Result{
		Checks:           []preflight.CheckItem{{Name: "memory", Status: "failed", Detail: admission.ErrNeverAdmissible.Error() + ": 15616 MiB is more than this node can ever hold"}},
		MemoryEvaluation: &admission.Evaluation{Checks: 1, Decision: admission.DecisionNeverAdmissible, HostTotalMiB: 15992, HostAvailableMiB: 13596},
		Versions:         preflightVersions("9.2.2", "4.2.0", "4.2.0"),
	})
	unsupported := preflightRefusedReport(t, preflight.Result{
		Checks:   []preflight.CheckItem{{Name: preflight.VersionCheckName, Status: "failed", Detail: "PVE 8.0.3, PBS 4.2.0, proxmox-backup-client 2.99.0: unsupported (proxmox-backup-client 2.99.0 is older than proxmox-backup-client 3, the oldest this release supports); this release refuses to run with them"}},
		Versions: preflightVersions("8.0.3", "4.2.0", "2.99.0"),
	})
	common := []string{
		"Outcome:       FAIL (as the file states)",
		"Validation:    full_integrity, but no disk image was read: the run stopped before any restore",
		"RTO:           none: no VM was restored",
		"sandbox VM: none was created",
	}
	for name, tc := range map[string]struct {
		report *attest.Report
		want   []string
	}{
		"never admissible": {neverAdmissible, []string{
			"Judge it: certistack verify-report --unsigned --expect-outcome denied <report.json>",
			"Proxmox:       PVE 9.2.2, PBS 4.2.0, proxmox-backup-client 4.2.0 (tested)",
			"not reserved; never_admissible",
		}},
		"unsupported client": {unsupported, []string{
			"Judge it: no verify-report outcome accepts it: the run stopped before any restore, and not for capacity",
			"Proxmox:       PVE 8.0.3, PBS 4.2.0, proxmox-backup-client 2.99.0 (unsupported)",
			"not reserved: the run stopped before admission",
		}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeFixtureBytes(t, dir, "report.json", tc.report)
			out, _, err := runReportCommand(t, "report", "show", path)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range append(common, tc.want...) {
				if !strings.Contains(out, want) {
					t.Errorf("report show lacks %q:\n%s", want, out)
				}
			}
			for _, claim := range []string{"every mapped disk image was read back", "--expect-outcome pass", "reserved ", "sandbox VM destroyed", "(the RTO)"} {
				if strings.Contains(out, claim) {
					t.Errorf("report show says %q of a run that restored nothing:\n%s", claim, out)
				}
			}
		})
	}

	// The suggested command accepts the capacity refusal.
	dir := t.TempDir()
	path := writeFixtureBytes(t, dir, "report.json", neverAdmissible)
	if out, err := runVerifyReport("--unsigned", "--expect-outcome", "denied", path); err != nil {
		t.Errorf("verify-report --unsigned --expect-outcome denied refused the capacity refusal: %v\n%s", err, out)
	}
}
