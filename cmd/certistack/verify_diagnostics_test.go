// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// A signed failed run whose phase timings hold all fourteen values (1234.56 s
// of integrity verification and 789.12 s of soak among them), a top-level
// failure reason, one failed TCP probe with an error and a detail, and cleanup
// errors of both kinds.
const (
	auditTopLevelFailure = "AUDIT_TOP_LEVEL_FAILURE: admission recovered but service validation failed"
	auditProbeError      = "AUDIT_PROBE_ERROR: TLS listener refused the isolated connection"
	auditProbeDetail     = "AUDIT_PROBE_DETAIL: address reachable; application listener absent"
	auditCleanupError    = "AUDIT_CLEANUP_ERROR: sandbox VM absence could not be confirmed"
	auditInitialError    = "AUDIT_INITIAL_CLEANUP_ERROR: stale overlay review required"
)

func auditFailedReport() *attest.Report {
	return &attest.Report{
		ReportSchemaVersion: attest.CurrentReportSchemaVersion,
		ReportID:            "00000000-0000-4000-8000-000000000196",
		Timestamp:           "2026-09-30T22:30:00Z",
		PlanID:              "verify-evidence-visibility",
		PlanName:            "Verifier evidence visibility audit",
		ValidationMode:      attest.ValidationModeFullIntegrity,
		NodeFQDN:            "pve-audit.example.invalid",
		EngineVersion:       "v0.1.0-audit",
		GitCommit:           "d8691564",
		Frameworks:          []string{"DORA-Article-12"},
		RetentionDays:       90,
		VMRecords: []probe.VMValidationRecord{{
			VMID: 9196, SourceVMID: 196, Name: "audit-failed-vm", VerificationStatus: "complete",
			ProbeResults: []probe.Result{{
				Type: "tcp", Target: "192.0.2.196:443", Description: "Audit TLS listener", Origin: "worker",
				Duration: 250 * time.Millisecond, Detail: auditProbeDetail, Error: auditProbeError,
			}},
		}},
		PhaseTimings: &attest.PhaseTimings{
			AdmissionCheckSec: 1.01, SDNProvisioningSec: 2.02, PBSMappingSec: 3.03, OverlayCreationSec: 4.04,
			COWGuestNetworkRecoverySec: 5.05, VMRegistrationSec: 6.06, VMStartSec: 7.07, QMPRunningWaitSec: 8.08,
			IntegrityVerificationSec: 1234.56, StartupGracePeriodSec: 9.09, ProbesExecutionSec: 10.10,
			SoakTimeSec: 789.12, TeardownSec: 11.11, TotalRTOSec: 2090.34,
		},
		TeardownEvidence: &attest.TeardownEvidence{
			CleanupErrors: []string{auditCleanupError}, InitialCleanupErrors: []string{auditInitialError},
			VerifiedAt: "2026-09-30T22:40:00Z",
		},
		RTOSeconds:    2090.34,
		FailureReason: auditTopLevelFailure,
	}
}

// verifyAuditReport signs report and runs verify-report on it, as text or JSON.
func verifyAuditReport(t *testing.T, report *attest.Report, format string) string {
	t.Helper()
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	path := writeSignedFixture(t, t.TempDir(), report, private)
	output, err := runVerifyReport("--format", format, "--trusted-key", hex.EncodeToString(public), path)
	if err != nil {
		t.Fatalf("verify-report %s of a genuine failed report: %v", format, err)
	}
	return output
}

// The human phase breakdown printed twelve lines and never read the
// integrity verification (usually the largest phase) or the tier soak.
func TestVerifyReportPrintsTheIntegrityScanAndTheSoak(t *testing.T) {
	text := verifyAuditReport(t, auditFailedReport(), "text")
	for _, want := range []string{
		"Image Integrity Scan:  1234.56s",
		"Tier Soak Hold:        789.12s",
		"Total RTO Time:        2090.34s",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the phase breakdown lacks %q:\n%s", want, text)
		}
	}
}

// phaseTimingsNotShown lists the phase timings the text breakdown deliberately
// leaves out. It is empty: a field added to attest.PhaseTimings has to be
// rendered, or named here with the reason it need not be.
var phaseTimingsNotShown = map[string]string{}

// phaseTimingLabels is the label each phase timing is printed under.
var phaseTimingLabels = map[string]string{
	"admission_check_sec":            "Host Admission:",
	"sdn_provisioning_sec":           "SDN Sandbox Setup:",
	"pbs_mapping_sec":                "PBS Chunk Mapping:",
	"overlay_creation_sec":           "Delta Overlay Create:",
	"cow_guest_network_recovery_sec": "COW Guest Network Prep:",
	"vm_registration_sec":            "VM Registration:",
	"vm_start_sec":                   "QEMU Launch & Boot:",
	"qmp_running_wait_sec":           "Stage 1 QMP Wait:",
	"integrity_verification_sec":     "Image Integrity Scan:",
	"startup_grace_period_sec":       "Startup Soak Grace:",
	"probes_execution_sec":           "Probes Execution:",
	"soak_time_sec":                  "Tier Soak Hold:",
	"teardown_sec":                   "Post-Test Teardown:",
	"total_rto_sec":                  "Total RTO Time:",
}

// Every PhaseTimings field, whatever is added to it next, is either printed on
// its own line with its value or classified as shown elsewhere. Each field gets
// a value no other has, so a line that prints another field's value fails.
func TestEveryPhaseTimingIsPrintedOrClassified(t *testing.T) {
	report := auditFailedReport()
	timings := reflect.ValueOf(report.PhaseTimings).Elem()
	kind := timings.Type()
	values := map[string]string{}
	for i := 0; i < kind.NumField(); i++ {
		name := strings.Split(kind.Field(i).Tag.Get("json"), ",")[0]
		value := float64(100*(i+1)) + 0.37
		timings.Field(i).SetFloat(value)
		values[name] = fmt.Sprintf("%.2fs", value)
	}
	text := verifyAuditReport(t, report, "text")
	for name, value := range values {
		if reason, classified := phaseTimingsNotShown[name]; classified {
			if reason == "" {
				t.Errorf("%s is classified as not shown without a reason", name)
			}
			continue
		}
		label, known := phaseTimingLabels[name]
		if !known {
			t.Errorf("PhaseTimings has a field %q that the verify-report breakdown does not print: render it in cmd_verify.go and give it a label here, or classify it in phaseTimingsNotShown with the reason", name)
			continue
		}
		printed := false
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, label) && strings.HasSuffix(strings.TrimSpace(line), value) {
				printed = true
			}
		}
		if !printed {
			t.Errorf("the breakdown has no %q line ending in %s (%s):\n%s", label, value, name, text)
		}
	}
}

// A failed report's text and JSON summary said that it failed, and
// nothing of why. Every diagnostic class of the original report is now shown.
func TestVerifyReportShowsWhyARunFailed(t *testing.T) {
	text := verifyAuditReport(t, auditFailedReport(), "text")
	for _, want := range []string{
		"All Passed:  false",
		"Failure:     " + auditTopLevelFailure,
		"Failed Probes (1):",
		`VM 9196 (audit-failed-vm): tcp 192.0.2.196:443 "Audit TLS listener"`,
		"error:  " + auditProbeError,
		"detail: " + auditProbeDetail,
		"Cleanup Errors (1):",
		auditCleanupError,
		"Cleanup Errors Before the Run (1):",
		auditInitialError,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the text output lacks %q:\n%s", want, text)
		}
	}

	var summary reportVerificationSummary
	if err := json.Unmarshal([]byte(verifyAuditReport(t, auditFailedReport(), "json")), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.FailureReason != auditTopLevelFailure || summary.CleanupErrorCount != 2 ||
		len(summary.CleanupErrors) != 1 || summary.CleanupErrors[0] != auditCleanupError ||
		len(summary.InitialCleanupErrors) != 1 || summary.InitialCleanupErrors[0] != auditInitialError {
		t.Errorf("the JSON summary lacks the failure reason or the cleanup errors: %+v", summary)
	}
	if len(summary.FailedProbes) != 1 || summary.FailedProbes[0].VMID != 9196 || summary.FailedProbes[0].Description != "Audit TLS listener" ||
		summary.FailedProbes[0].Error != auditProbeError || summary.FailedProbes[0].Detail != auditProbeDetail {
		t.Errorf("the JSON summary lacks the failed probe's error or detail: %+v", summary.FailedProbes)
	}
}

// The kinds of failure a report can carry alone, and a clean pass says nothing
// extra: nothing is printed for what the report does not record.
func TestVerifyReportShowsOnlyTheFailuresAReportRecords(t *testing.T) {
	type kind struct {
		name   string
		mutate func(*attest.Report)
		want   []string
		absent []string
	}
	for _, tc := range []kind{
		{"an early failure with no VM record", func(r *attest.Report) {
			r.VMRecords, r.TeardownEvidence = nil, &attest.TeardownEvidence{AllCleaned: true, OrphanSweepClean: true}
		}, []string{"Failure:     " + auditTopLevelFailure}, []string{"Failed Probes", "Cleanup Errors"}},
		{"a probe failure alone", func(r *attest.Report) {
			r.FailureReason, r.TeardownEvidence = "", &attest.TeardownEvidence{AllCleaned: true, OrphanSweepClean: true}
		}, []string{"Failed Probes (1):", auditProbeError}, []string{"Failure:", "Cleanup Errors"}},
		{"a cleanup failure alone", func(r *attest.Report) {
			r.FailureReason, r.VMRecords = "", nil
		}, []string{"Cleanup Errors (1):", auditCleanupError}, []string{"Failure:", "Failed Probes"}},
		{"a skipped probe is not a failure", func(r *attest.Report) {
			r.VMRecords[0].ProbeResults[0].Skipped = true
			r.FailureReason, r.TeardownEvidence = "", &attest.TeardownEvidence{AllCleaned: true, OrphanSweepClean: true}
		}, nil, []string{"Failed Probes", "Failure:", "Cleanup Errors"}},
		{"a report of an earlier schema", func(r *attest.Report) { r.ReportSchemaVersion = "1.5" },
			[]string{"Failure:     " + auditTopLevelFailure, auditProbeError, auditCleanupError}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := auditFailedReport()
			tc.mutate(report)
			text := verifyAuditReport(t, report, "text")
			for _, want := range tc.want {
				if !strings.Contains(text, want) {
					t.Errorf("the output lacks %q:\n%s", want, text)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(text, absent) {
					t.Errorf("the output has %q for a report that records no such thing:\n%s", absent, text)
				}
			}
		})
	}
}

// What a signed report supplies is not safe because it is signed: control and
// format characters, line breaks and size are all dealt with in every place the
// diagnostics are printed, in text and in JSON.
func TestVerifyReportContainsTheDiagnosticsItShows(t *testing.T) {
	hostile := "forged\r\n  All Passed:  true\x1b[2J\x07 \u202egnirts\u2066 \u200b end"
	report := auditFailedReport()
	report.FailureReason = hostile
	report.VMRecords[0].Name = hostile
	report.VMRecords[0].ProbeResults[0].Error = hostile
	report.VMRecords[0].ProbeResults[0].Detail = hostile
	report.TeardownEvidence.CleanupErrors = []string{hostile}
	report.TeardownEvidence.InitialCleanupErrors = []string{hostile}
	for _, format := range []string{"text", "json"} {
		output := verifyAuditReport(t, report, format)
		for _, forbidden := range []string{"\x1b", "\x07", "\u202e", "\u2066", "\u200b", "\r"} {
			if strings.Contains(output, forbidden) {
				t.Errorf("%s: the output carries %q from a signed report:\n%q", format, forbidden, output)
			}
		}
		if format == "text" {
			// A forged line break cannot start a line of its own.
			for _, line := range strings.Split(output, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "All Passed:  true") {
					t.Errorf("a failure reason forged a line:\n%s", output)
				}
			}
		}
	}

	// Size: one long value is cut, and a long list is cut with a count of the rest.
	report = auditFailedReport()
	long := strings.Repeat("x", 5000)
	report.FailureReason = long
	report.VMRecords[0].ProbeResults[0].Error = long
	report.TeardownEvidence.CleanupErrors = nil
	for i := 0; i < 100; i++ {
		report.TeardownEvidence.CleanupErrors = append(report.TeardownEvidence.CleanupErrors, fmt.Sprintf("cleanup error %03d", i))
		report.VMRecords = append(report.VMRecords, probe.VMValidationRecord{VMID: 9300 + i, Name: "vm", ProbeResults: []probe.Result{{Type: "tcp", Target: "192.0.2.1:1", Description: "d", Error: "boom"}}})
	}
	text := verifyAuditReport(t, report, "text")
	for _, line := range strings.Split(text, "\n") {
		limit := maxDiagnosticRunes
		if strings.HasPrefix(strings.TrimSpace(line), "Failure:") {
			limit = maxFailureReasonRunes
		}
		if strings.Count(line, "x") > limit {
			t.Errorf("an oversized value was printed whole (%d characters): %.80s", strings.Count(line, "x"), line)
		}
	}
	for _, want := range []string{"Failed Probes (101):", "and 81 more", "Cleanup Errors (100):", "and 80 more", "cleanup error 019"} {
		if !strings.Contains(text, want) {
			t.Errorf("the output lacks %q", want)
		}
	}
	if strings.Contains(text, "cleanup error 020") {
		t.Error("more than maxDiagnosticItems cleanup errors were listed")
	}
	var summary reportVerificationSummary
	if err := json.Unmarshal([]byte(verifyAuditReport(t, report, "json")), &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.CleanupErrors) != maxDiagnosticItems || summary.CleanupErrorCount != 101 ||
		len([]rune(summary.FailureReason)) > maxFailureReasonRunes+1 || len([]rune(summary.FailedProbes[0].Error)) > maxDiagnosticRunes+1 {
		t.Errorf("the JSON summary is not bounded: %d cleanup errors, count %d, reason %d runes", len(summary.CleanupErrors), summary.CleanupErrorCount, len([]rune(summary.FailureReason)))
	}
}

// verify-report also judges unsigned reports (--unsigned), so the note that
// points at the rest of a long list must not call the report signed (hardening
// F9, CR1-09).
func TestDiagnosticsOverflowNoteDoesNotCallTheReportSigned(t *testing.T) {
	report := auditFailedReport()
	for i := 0; i < 30; i++ {
		report.TeardownEvidence.CleanupErrors = append(report.TeardownEvidence.CleanupErrors, fmt.Sprintf("cleanup error %03d", i))
		report.VMRecords = append(report.VMRecords, probe.VMValidationRecord{VMID: 9300 + i, Name: "vm", ProbeResults: []probe.Result{{Type: "tcp", Target: "192.0.2.1:1", Description: "d", Error: "boom"}}})
	}
	var out strings.Builder
	writeFailureDiagnostics(&out, report)
	text := out.String()
	if strings.Count(text, "more (see the report)") != 2 {
		t.Errorf("the overflow notes (failed probes and cleanup errors) do not point at the report:\n%s", text)
	}
	if strings.Contains(text, "signed") {
		t.Errorf("the diagnostics call the report signed:\n%s", text)
	}
}
