// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/internal/support"
	"github.com/cliftcloud/certistack/pkg/admission"
)

// preflightVersions is the version result a preflight gives for the three
// versions, as its version check makes it.
func preflightVersions(pve, pbs, client string) *preflight.VersionReport {
	status := support.Classify(support.ParseVersion(pve), support.ParseVersion(pbs), support.ParseVersion(client))
	return &preflight.VersionReport{PVE: status.PVE.String(), PBS: status.PBS.String(), PBSClient: status.Client.String(), Support: status.Verdict(), Reason: status.Reason, Status: status}
}

// A run the node's preflight refuses before it creates anything records the
// Proxmox versions the preflight read, whichever check refused it: a full node
// on a tested pair says tested, and a node refused for its client says
// unsupported. It records the PBS identity the run would have, as every report
// does.
func TestAPreflightRefusalRecordsTheVersionsItRead(t *testing.T) {
	t.Setenv("PBS_FINGERPRINT", "22:bd:96:7a:31")
	t.Setenv("PBS_NAMESPACE", "")
	plan := mustLoadFixturePlan()
	for name, tc := range map[string]struct {
		checks   []preflight.CheckItem
		versions *preflight.VersionReport
		memory   *admission.Evaluation
		want     [4]string
	}{
		"memory, on a tested pair": {
			checks:   []preflight.CheckItem{{Name: "memory", Status: "failed", Detail: admission.ErrNeverAdmissible.Error()}},
			versions: preflightVersions("9.2.2", "4.2.0", "4.2.0"),
			memory:   &admission.Evaluation{Checks: 1, Decision: admission.DecisionNeverAdmissible, HostTotalMiB: 15992, HostAvailableMiB: 13596},
			want:     [4]string{"9.2.2", "4.2.0", "4.2.0", "tested"},
		},
		"the client of PVE 8.0": {
			checks:   []preflight.CheckItem{{Name: preflight.VersionCheckName, Status: "failed", Detail: "PVE 8.0.3, PBS 4.2.0, proxmox-backup-client 2.99.0: unsupported"}},
			versions: preflightVersions("8.0.3", "4.2.0", "2.99.0"),
			want:     [4]string{"8.0.3", "4.2.0", "2.99.0", "unsupported"},
		},
		"no version read": {
			checks:   []preflight.CheckItem{{Name: "kvm", Status: "failed", Detail: "no /dev/kvm"}},
			versions: preflightVersions("", "", ""),
			want:     [4]string{"", "", "", "unknown"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			result := preflightFailureResult(plan, "node-a", preflight.Result{Checks: tc.checks, Versions: tc.versions, MemoryEvaluation: tc.memory}, false)
			report := result.Report
			if report == nil || report.AllPassed || len(report.VMRecords) != 0 || !strings.HasPrefix(report.FailureReason, "node preflight failed: ") {
				t.Fatalf("result = %+v", result)
			}
			if got := [4]string{report.PVEVersion, report.PBSVersion, report.PBSClientVersion, report.VersionSupport}; got != tc.want {
				t.Errorf("versions = %v, want %v", got, tc.want)
			}
			if report.PBSFingerprint != "22:bd:96:7a:31" || report.PBSNamespace != "root" {
				t.Errorf("PBS identity = %q, %q", report.PBSFingerprint, report.PBSNamespace)
			}
		})
	}

	// A preflight that read no versions (a non-Linux build) leaves the members
	// out.
	result := preflightFailureResult(plan, "node-a", preflight.Result{Checks: []preflight.CheckItem{{Name: "kvm", Status: "failed"}}}, false)
	if report := result.Report; report.PVEVersion != "" || report.VersionSupport != "" {
		t.Errorf("a refusal that read no versions records %q, %q", report.PVEVersion, report.VersionSupport)
	}
}
