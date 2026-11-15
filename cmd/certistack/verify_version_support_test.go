// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/json"
	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"strings"
	"testing"
)

// The Proxmox version members of a report (pve_version, pbs_version,
// pbs_client_version, version_support) are optional: a report of an earlier
// build, or a refusal before the versions were read, is judged as before.
// When version_support is there it is one of tested, untested or unknown, and
// a tested pair names the versions it was judged on. "unsupported" is not a
// value a signed report can hold: a run of such a pair is refused.
func TestReportAcceptanceVersionSupport(t *testing.T) {
	plan := mustLoadFixturePlan()
	exp := fixtureExpectations(plan, accept.OutcomePass)

	report := passReport(plan)
	expectAccepted(t, "a report that records no versions", report, exp)

	report = passReport(plan)
	report.PVEVersion, report.PBSVersion, report.PBSClientVersion, report.VersionSupport = "9.1.1", "4.2.7", "4.2.5", "tested"
	expectAccepted(t, "a tested pair with its three versions", report, exp)

	report = passReport(plan)
	report.PVEVersion, report.PBSVersion, report.PBSClientVersion, report.VersionSupport = "8.3.5", "3.4.0", "3.3.7", "untested"
	expectAccepted(t, "an untested pair", report, exp)

	report = passReport(plan)
	report.PVEVersion, report.PBSClientVersion, report.VersionSupport = "9.1.1", "4.2.5", "unknown"
	expectAccepted(t, "a server version that could not be read", report, exp)

	report = passReport(plan)
	report.PVEVersion, report.PBSClientVersion, report.VersionSupport = "9.1.1", "4.2.5", "tested"
	expectRejected(t, "tested without the PBS server version", report, exp, "tested but does not record all of pve_version, pbs_version and pbs_client_version")

	report = passReport(plan)
	report.VersionSupport = "tested"
	expectRejected(t, "tested with no versions at all", report, exp, "tested but does not record all of")

	for _, value := range []string{"unsupported", "Tested", "ok", " tested"} {
		report = passReport(plan)
		report.PVEVersion, report.PBSVersion, report.PBSClientVersion, report.VersionSupport = "7.4-20", "4.2.7", "4.2.5", value
		expectRejected(t, "version_support "+value, report, exp, "none of tested, untested or unknown")
	}

	// Versions without a verdict (a build that wrote the first and not the
	// second) are not required to have one.
	report = passReport(plan)
	report.PVEVersion = "9.1.1"
	expectAccepted(t, "a version with no verdict", report, exp)
}

func TestVerifyReportShowsTheProxmoxVersions(t *testing.T) {
	report := auditFailedReport()
	report.PVEVersion, report.PBSVersion, report.PBSClientVersion, report.VersionSupport = "9.1.1", "4.2.7", "4.2.5", "tested"

	text := verifyAuditReport(t, report, "text")
	if want := "  Proxmox:     PVE 9.1.1, PBS 4.2.7, proxmox-backup-client 4.2.5 (tested)\n"; !strings.Contains(text, want) {
		t.Errorf("verify-report text lacks %q:\n%s", want, text)
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(verifyAuditReport(t, report, "json")), &summary); err != nil {
		t.Fatal(err)
	}
	for member, want := range map[string]string{"pve_version": "9.1.1", "pbs_version": "4.2.7", "pbs_client_version": "4.2.5", "version_support": "tested"} {
		if summary[member] != want {
			t.Errorf("verify-report JSON %s = %v, want %q", member, summary[member], want)
		}
	}

	// A server version that was not read is shown as unknown, and the JSON
	// leaves its member out.
	report.PBSVersion, report.VersionSupport = "", "unknown"
	text = verifyAuditReport(t, report, "text")
	if want := "PVE 9.1.1, PBS unknown, proxmox-backup-client 4.2.5 (unknown)"; !strings.Contains(text, want) {
		t.Errorf("verify-report text lacks %q:\n%s", want, text)
	}
	summary = nil
	if err := json.Unmarshal([]byte(verifyAuditReport(t, report, "json")), &summary); err != nil {
		t.Fatal(err)
	}
	if _, present := summary["pbs_version"]; present {
		t.Errorf("verify-report JSON carries pbs_version for a version nobody read: %v", summary)
	}

	// A report without the members shows none and needs none.
	plain := auditFailedReport()
	text = verifyAuditReport(t, plain, "text")
	if strings.Contains(text, "Proxmox:") {
		t.Errorf("verify-report shows Proxmox versions for a report that records none:\n%s", text)
	}
	summary = nil
	if err := json.Unmarshal([]byte(verifyAuditReport(t, plain, "json")), &summary); err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{"pve_version", "pbs_version", "pbs_client_version", "version_support"} {
		if _, present := summary[member]; present {
			t.Errorf("verify-report JSON carries %s for a report that records none", member)
		}
	}

	// What a signed report holds is display text, not a terminal's input.
	hostile := auditFailedReport()
	hostile.PVEVersion, hostile.VersionSupport = "9.1\x1b[31m\nforged line", "tested"
	text = verifyAuditReport(t, hostile, "text")
	if strings.Contains(text, "\x1b") || strings.Contains(text, "\nforged line") {
		t.Errorf("verify-report passed a hostile version through:\n%q", text)
	}
}
