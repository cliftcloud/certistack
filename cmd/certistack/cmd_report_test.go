// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// runReportCommand runs the whole command line, as the binary does, and
// returns what it wrote to standard output and standard error.
func runReportCommand(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	// The root records the running command for the signal handler's wording;
	// leave it as other tests find it.
	t.Cleanup(func() { activeCommand.Store(""); remoteWorkerStaged.Store(false) })
	root := newRootCmd(nil)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err = root.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

// normalizeViewOutput hides the temporary directory a test wrote its files in.
func normalizeViewOutput(output, dir string) string {
	// JSON writes each backslash of a Windows path as two.
	output = strings.ReplaceAll(output, strings.ReplaceAll(dir, "\\", "\\\\"), "<dir>")
	output = strings.ReplaceAll(output, dir, "<dir>")
	output = strings.ReplaceAll(output, "<dir>\\\\", "<dir>/")
	return strings.ReplaceAll(output, "<dir>\\", "<dir>/")
}

var (
	twinPassTime = time.Date(2026, 10, 5, 14, 2, 57, 0, time.UTC)
	twinFailTime = time.Date(2026, 10, 5, 14, 18, 53, 0, time.UTC)
)

const (
	twinPassID = "d3f589f5-c499-4181-a804-29da944b7fa1"
	twinFailID = "49b8b0fe-1a7d-4dab-bb52-57bd89e9421b"
)

// The reports the golden outputs are made from. Each is a case of what a
// person reads a report for: a pass, a failure and why, the test mode, an
// older schema and a run refused before any VM existed.
func viewFixtureReports() map[string]*attest.Report {
	testMode := twinReport(twinPassID, twinPassTime, true, 342.945584747)
	testMode.ValidationMode = attest.ValidationModeTestSkipIntegrity
	testMode.PhaseTimings.IntegrityVerificationSec = 0
	for index := range testMode.VMRecords[0].SourceDisks {
		testMode.VMRecords[0].SourceDisks[index].IntegrityStatus = "skipped_test_mode"
		testMode.VMRecords[0].SourceDisks[index].ImageDigest = ""
	}
	testMode.VMRecords[0].PBSVerifyStatus = ""

	older := twinReport(twinPassID, twinPassTime, true, 342.945584747)
	older.ReportSchemaVersion = "1.5"
	older.Admission, older.PlanSHA256, older.WorkerSHA256 = nil, "", ""
	older.PVEVersion, older.PBSVersion, older.PBSClientVersion, older.VersionSupport = "", "", "", ""
	for index := range older.VMRecords[0].ProbeResults {
		result := &older.VMRecords[0].ProbeResults[index]
		result.TimeoutSec, result.Attempts, result.SourceInterface, result.SourceAddress = 0, 0, "", ""
	}

	denied := twinReport(twinFailID, twinFailTime, false, 0.62)
	denied.VMRecords, denied.PhaseTimings = nil, nil
	denied.FailureReason = "admission control guardrail triggered: max admission retries exceeded"
	// Eleven checks found the node too full: 2500 MiB free of 32094 MiB.
	evaluation := denied.Admission.Evaluation
	evaluation.Decision, evaluation.Checks, evaluation.HostAvailableMiB = "denied_ram", 11, 2500
	evaluation.HostRAMPercent = (evaluation.HostTotalMiB - evaluation.HostAvailableMiB) / evaluation.HostTotalMiB * 100
	evaluation.ProjectedRAMPercent = (evaluation.HostTotalMiB - evaluation.HostAvailableMiB + 1280) / evaluation.HostTotalMiB * 100
	denied.TeardownEvidence.OverlayFilesRemoved, denied.TeardownEvidence.LoopDevicesUnmapped = nil, nil
	denied.TeardownEvidence.SDNVNetRemoved, denied.TeardownEvidence.SDNZoneRemoved = "", ""
	denied.TeardownEvidence.VMStoppedAndDestroyed = false

	objective := twinReport(twinPassID, twinPassTime, true, 342.945584747)
	target := 300.0
	objective.RTOTargetSeconds = &target
	objective.AllPassed = false
	objective.FailureReason = "recovery time objective exceeded: 342.9s over the 300.0s objective"

	campaign := campaignFixtureReport(mustLoadFixturePlan(), campaignFixture{mode: accept.OutcomePass})
	campaign.ReportID = "5c1a2e30-0b7d-4a43-9d5e-3f0c1b2a4d66" // the fixture builder draws a random one

	return map[string]*attest.Report{
		"twin-pass":        twinReport(twinPassID, twinPassTime, true, 342.945584747),
		"twin-fail":        twinReport(twinFailID, twinFailTime, false, 459.110726474),
		"test-mode":        testMode,
		"schema-1.5":       older,
		"denied":           denied,
		"objective-missed": objective,
		"campaign-3vm":     campaign,
	}
}

// The golden outputs of `report show`: the text and the JSON of each fixture,
// with and without a keyring.
func TestReportShowGoldenOutputs(t *testing.T) {
	cases := []struct {
		name, golden string
		keyring      bool
		asJSON       bool
	}{
		{"twin-pass", "twin-pass.unverified.txt", false, false},
		{"twin-pass", "twin-pass.keyring.txt", true, false},
		{"twin-pass", "twin-pass.keyring.json", true, true},
		{"twin-fail", "twin-fail.keyring.txt", true, false},
		{"twin-fail", "twin-fail.unverified.json", false, true},
		{"test-mode", "test-mode.unverified.txt", false, false},
		{"test-mode", "test-mode.keyring.txt", true, false},
		{"schema-1.5", "schema-1.5.unverified.txt", false, false},
		{"denied", "denied.keyring.txt", true, false},
		{"objective-missed", "objective-missed.keyring.txt", true, false},
		{"campaign-3vm", "campaign-3vm.keyring.txt", true, false},
	}
	reports := viewFixtureReports()
	for _, tc := range cases {
		t.Run(tc.golden, func(t *testing.T) {
			dir := t.TempDir()
			report := *reports[tc.name]
			path := writeFixtureReport(t, dir, "report.json", &report, nil)
			args := []string{"report", "show", path}
			if tc.keyring {
				args = append(args, "--keyring", writeFixtureKeyring(t, dir))
			}
			if tc.asJSON {
				args = append(args, "--json")
			}
			stdout, stderr, err := runReportCommand(t, args...)
			if err != nil || stderr != "" {
				t.Fatalf("err = %v, stderr = %q", err, stderr)
			}
			compareGolden(t, "report-views", tc.golden, normalizeViewOutput(stdout, dir))
		})
	}
}

// What the text says first matters most: a reader who stops after the top
// lines must not take an unchecked file for evidence, or a test-mode report for
// a production one.
func TestReportShowSaysWhatItDidNotCheckAndFlagsTheTestMode(t *testing.T) {
	reports := viewFixtureReports()
	dir := t.TempDir()
	passed := writeFixtureReport(t, dir, "pass.json", reports["twin-pass"], nil)
	testMode := writeFixtureReport(t, dir, "test.json", reports["test-mode"], nil)
	keyring := writeFixtureKeyring(t, dir)

	out, _, err := runReportCommand(t, "report", "show", passed)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"signature NOT checked (no --keyring)", "not verified evidence", "PASS (as the file states)"} {
		if !strings.Contains(out, want) {
			t.Errorf("the unchecked view lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "VALID") || strings.Contains(out, "ACCEPTED") {
		t.Errorf("an unchecked report was described as valid or accepted:\n%s", out)
	}

	for _, withKeyring := range []bool{false, true} {
		args := []string{"report", "show", testMode}
		if withKeyring {
			args = append(args, "--keyring", keyring)
		}
		out, _, err := runReportCommand(t, args...)
		if err != nil {
			t.Fatal(err)
		}
		if first := strings.SplitN(out, "\n", 4); !strings.Contains(first[2], "TEST-MODE REPORT") || !strings.Contains(first[2], "not production evidence") {
			t.Errorf("keyring=%v: the test-mode banner is not at the top:\n%s", withKeyring, out)
		}
		if !strings.Contains(out, "TEST MODE (test_skip_integrity)") || !strings.Contains(out, "skipped_test_mode") {
			t.Errorf("keyring=%v: the test mode is not said in the body:\n%s", withKeyring, out)
		}
		if withKeyring && !strings.Contains(out, "REJECTED as pass evidence") {
			t.Errorf("a test-mode report was not rejected as pass evidence:\n%s", out)
		}
	}
}

// The acceptance verdict of the keyring view is the one verify-report gives the
// same report with no --expect-* flag, for every fixture.
func TestReportShowAcceptanceIsVerifyReportsVerdict(t *testing.T) {
	for name, report := range viewFixtureReports() {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeFixtureReport(t, dir, "report.json", report, nil)
			keyring := writeFixtureKeyring(t, dir)

			verifyOut, verifyErr := runVerifyReport("--keyring", keyring, "--allow-test-mode", "--format", "json", path)
			if verifyErr != nil {
				t.Fatalf("verify-report: %v", verifyErr)
			}
			var verified struct {
				Acceptance accept.Result `json:"acceptance"`
			}
			if err := json.Unmarshal([]byte(verifyOut), &verified); err != nil {
				t.Fatal(err)
			}

			stdout, _, err := runReportCommand(t, "report", "show", "--keyring", keyring, "--json", path)
			if err != nil {
				t.Fatal(err)
			}
			var shown reportView
			if err := json.Unmarshal([]byte(stdout), &shown); err != nil {
				t.Fatal(err)
			}
			if shown.Signature.Status != "valid" || shown.Acceptance == nil {
				t.Fatalf("signature = %+v, acceptance = %+v", shown.Signature, shown.Acceptance)
			}
			// verify-report is run with --allow-test-mode so it prints the verdict
			// for the test-mode fixture; show never allows it.
			want := verified.Acceptance.Verdict
			if report.ValidationMode == attest.ValidationModeTestSkipIntegrity {
				want = accept.Rejected
			}
			if shown.Acceptance.Verdict != want {
				t.Errorf("show says %q, verify-report says %q (%v)", shown.Acceptance.Verdict, want, verified.Acceptance.Reasons)
			}
			if shown.Acceptance.ExpectedOutcome != accept.OutcomePass {
				t.Errorf("the verdict is for %q, want %q", shown.Acceptance.ExpectedOutcome, accept.OutcomePass)
			}
			if want == accept.Accepted && (len(shown.Acceptance.Reasons) != 0 || shown.Report.Outcome != "pass") {
				t.Errorf("an accepted report lists reasons %v or is not a pass (%s)", shown.Acceptance.Reasons, shown.Report.Outcome)
			}
			if want == accept.Rejected && len(shown.Acceptance.Reasons) == 0 {
				t.Error("a rejected report lists no reason")
			}
		})
	}
}

// A report that cannot be shown is an error that says why, with exit status 2,
// and nothing of its contents is printed.
func TestReportShowRefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	reports := viewFixtureReports()
	keyring := writeFixtureKeyring(t, dir)
	good := writeFixtureReport(t, dir, "good.json", reports["twin-pass"], nil)

	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	newer := *reports["twin-pass"]
	newer.ReportSchemaVersion = "1.9"
	newerPath := writeFixtureReport(t, dir, "newer.json", &newer, nil)
	noSchema := *reports["twin-pass"]
	noSchema.ReportSchemaVersion = ""
	noSchemaPath := writeFixtureReport(t, dir, "noschema.json", &noSchema, nil)
	_, otherPrivate, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	untrusted := *reports["twin-pass"]
	untrustedPath := writeFixtureReport(t, dir, "untrusted.json", &untrusted, otherPrivate)

	tampered := *reports["twin-pass"]
	tamperedPath := writeFixtureReport(t, dir, "tampered.json", &tampered, nil)
	data, err := os.ReadFile(tamperedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tamperedPath, bytes.Replace(data, []byte(`"all_passed": true`), []byte(`"all_passed": false`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	unsigned := *viewFixtureReports()["twin-pass"]
	unsigned.Signature, unsigned.PublicKey, unsigned.SignerFingerprint = "", "", ""
	unsignedPath := writeFixtureBytes(t, dir, "unsigned.json", &unsigned)
	emptyKeyring := write("empty-keyring.json", `{"trusted_signers": []}`)

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"a missing file", []string{filepath.Join(dir, "missing.json")}, "failed to read report"},
		{"a directory", []string{dir}, "failed to read report"},
		{"an empty file", []string{write("empty.json", "")}, "cannot show this file"},
		{"not JSON", []string{write("junk.json", "this is not a report\n")}, "cannot show this file"},
		{"a JSON array", []string{write("array.json", "[1, 2, 3]")}, "not a CertiStack report"},
		{"a truncated report", []string{write("truncated.json", `{"report_id": "x", "vm_records": [{"vmid": `)}, "cannot show this file"},
		{"a repeated member", []string{write("dup.json", `{"report_id": "x", "report_id": "y"}`)}, "cannot show this file"},
		{"a newer schema", []string{newerPath}, `report schema version "1.9" is newer than this verifier understands`},
		{"a missing schema", []string{noSchemaPath}, `report schema version "" is not a supported 1.x schema`},
		{"a newer schema, checked", []string{newerPath, "--keyring", keyring}, `report schema version "1.9" is newer`},
		{"a tampered report", []string{tamperedPath, "--keyring", keyring}, "cryptographic signature mismatch"},
		{"an untrusted signer", []string{untrustedPath, "--keyring", keyring}, "untrusted signer"},
		{"an unsigned report, checked", []string{unsignedPath, "--keyring", keyring}, "unsigned"},
		{"an unreadable keyring", []string{good, "--keyring", filepath.Join(dir, "no-keyring.json")}, "failed to load keyring"},
		{"a keyring with no key", []string{good, "--keyring", emptyKeyring}, "holds no trusted signer keys"},
		{"an empty keyring path", []string{good, "--keyring", ""}, "--keyring must not be empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, err := runReportCommand(t, append([]string{"report", "show"}, tc.args...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
			if code := exitCodeForError(err); code != exitCodeInfrastructure {
				t.Errorf("exit status = %d, want %d", code, exitCodeInfrastructure)
			}
			if stdout != "" {
				t.Errorf("a refused report printed %q", stdout)
			}
		})
	}
}

// What a report says is not safe to print because it was signed: control
// characters, escape sequences and bidirectional controls in names, probe text
// and the failure reason never reach the terminal or the JSON, and a huge text
// is cut.
func TestReportShowPrintsReportTextSafely(t *testing.T) {
	hostile := "ok\x1b[31m red \u202e reversed\r\nnext line\x00" + strings.Repeat("A", 5000)
	report := twinReport(twinFailID, twinFailTime, false, 100)
	report.PlanName, report.Environment, report.FailureReason = hostile, hostile, hostile
	record := &report.VMRecords[0]
	record.Name, record.SourceSnapshot, record.NetworkRecoveryDiagnostic = hostile, hostile, hostile
	record.ProbeResults[0].Description, record.ProbeResults[0].Target, record.ProbeResults[0].Detail = hostile, hostile, hostile
	record.ProbeResults[1].Error = hostile
	report.TeardownEvidence.CleanupErrors = []string{hostile}
	dir := t.TempDir()
	path := writeFixtureReport(t, dir, "report.json", report, nil)

	for _, asJSON := range []bool{false, true} {
		args := []string{"report", "show", "--keyring", writeFixtureKeyring(t, dir), path}
		if asJSON {
			args = append(args, "--json")
		}
		stdout, _, err := runReportCommand(t, args...)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range stdout {
			if r == '\n' || r == '\t' {
				continue
			}
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				t.Fatalf("json=%v: the output carries the control or format character %U:\n%q", asJSON, r, stdout)
			}
		}
		if strings.Contains(stdout, strings.Repeat("A", 1500)) {
			t.Errorf("json=%v: a 5000-character text was not cut", asJSON)
		}
	}
}

// The text view is bounded: a report with thousands of probes does not flood a
// terminal, says how many were left out, and --json carries all of them.
func TestReportShowBoundsTheTextAndKeepsEverythingInJSON(t *testing.T) {
	report := twinReport(twinPassID, twinPassTime, true, 100)
	record := &report.VMRecords[0]
	for index := 0; index < 3*maxViewProbesPerVM; index++ {
		record.ProbeResults = append(record.ProbeResults, probe.Result{Type: "tcp", Target: "192.0.2.10:22", Description: "extra probe", Passed: true})
	}
	for index := 0; index < maxViewVMs+10; index++ {
		extra := *record
		extra.VMID = 9200 + index
		report.VMRecords = append(report.VMRecords, extra)
	}
	dir := t.TempDir()
	path := writeFixtureReport(t, dir, "report.json", report, nil)

	text, _, err := runReportCommand(t, "report", "show", path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "and 11 more VM(s)") || !strings.Contains(text, "more probe(s)") {
		t.Errorf("the bounded text does not say what it left out")
	}
	if lines := strings.Count(text, "\n"); lines > 3*maxViewVMs*(maxViewProbesPerVM*4+30) {
		t.Errorf("the text has %d lines", lines)
	}
	stdout, _, err := runReportCommand(t, "report", "show", "--json", path)
	if err != nil {
		t.Fatal(err)
	}
	var shown reportView
	if err := json.Unmarshal([]byte(stdout), &shown); err != nil {
		t.Fatal(err)
	}
	if len(shown.Report.VMs) != maxViewVMs+11 || len(shown.Report.VMs[0].Probes) != 1+3*maxViewProbesPerVM {
		t.Errorf("the JSON has %d VMs and %d probes of the first, want all", len(shown.Report.VMs), len(shown.Report.VMs[0].Probes))
	}
}

// A report with fields missing (a partial record) is shown, with what is
// missing said, rather than refused or printed as if it were complete.
func TestReportShowSaysWhatAReportDoesNotRecord(t *testing.T) {
	report := twinReport(twinPassID, twinPassTime, true, 100)
	report.TeardownEvidence = nil
	report.PhaseTimings = nil
	report.VMRecords[0].SourceDisks = nil
	report.VMRecords[0].SourceSnapshot = ""
	report.VMRecords[0].SourceVMID = 0
	report.VMRecords[0].NetworkRecoveryStrategy = ""
	dir := t.TempDir()
	path := writeFixtureReport(t, dir, "report.json", report, nil)
	out, _, err := runReportCommand(t, "report", "show", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"the report has no teardown evidence, so cleanup of the run's temporary resources is unknown",
		"NO disk evidence recorded",
		"source VM not recorded, snapshot not recorded",
		"none recorded (no network profile was written into the guest's overlay)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the view lacks %q:\n%s", want, out)
		}
	}
}

func TestVMOutcome(t *testing.T) {
	for _, tc := range []struct {
		status string
		passed bool
		want   string
	}{
		{"verified", true, vmPass},
		{"failed", false, vmFail},
		{"verified", false, vmFail},
		{"incomplete", false, vmIncomplete},
		{"unverified", true, vmUnverified},
		{"", true, vmUnverified},
		{"booted", false, vmFail},
		{"", false, vmFail},
	} {
		if got := vmOutcome(probe.VMValidationRecord{VerificationStatus: tc.status, AllPassed: tc.passed}); got != tc.want {
			t.Errorf("status %q, all_passed %v: %s, want %s", tc.status, tc.passed, got, tc.want)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	for seconds, want := range map[float64]string{
		0.5: "0.50 s", 4.44: "4.4 s", 59.94: "59.9 s", 60: "1m 00s", 342.9456: "5m 43s", 3599: "59m 59s", 3600: "1h 00m", 7384: "2h 03m",
		-1: "unknown",
	} {
		if got := humanDuration(seconds); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", seconds, got, want)
		}
	}
}

// report with no subcommand prints help and exits 0; a misspelled subcommand is
// a usage error, not a silent success.
func TestReportCommandGroup(t *testing.T) {
	if _, _, err := runReportCommand(t, "report"); err != nil {
		t.Errorf("report with no subcommand: %v", err)
	}
	if _, _, err := runReportCommand(t, "report", "shw"); err == nil {
		t.Error("an unknown subcommand was accepted")
	}
	if _, _, err := runReportCommand(t, "report", "show", "--reports-dir", t.TempDir()); err == nil {
		t.Error("show with no report named and none in the reports directory was accepted")
	}
	if _, _, err := runReportCommand(t, "report", "show", "a.json", "b.json"); err == nil {
		t.Error("show with two reports was accepted")
	}
}

// A tier's soak is shown as the service checks it ran, with the failed ones.
func TestReportShowSaysWhatTheSoakChecked(t *testing.T) {
	record := twinReport(twinPassID, twinPassTime, true, 100).VMRecords[0]
	record.Soak = &probe.SoakEvidence{ConfiguredSec: 300, IntervalSec: 30, Samples: 11, FailedSamples: 2}
	var out bytes.Buffer
	renderVMView(&out, buildVMView(record))
	if want := "Soak:              11 service check(s) over 300 s, 2 failed"; !strings.Contains(out.String(), want) {
		t.Errorf("the soak line is missing:\n%s", out.String())
	}
}
