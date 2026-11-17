// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/probe"
)

const (
	nextReport     = "/var/lib/certistack/reports/recovery-pve-demo-01/0f3a9c1e.json"
	nextTroubleOne = "Next: docs/troubleshooting.md lists the usual causes of a failed run and their fixes"
)

// savedReport is the report of a run that got as far as its probes: one VM,
// whose probe passed or failed.
func savedReport(passed bool, path string) *controller.Result {
	return &controller.Result{
		ReportPath: path,
		Report: &attest.Report{AllPassed: passed, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true},
			VMRecords: []probe.VMValidationRecord{{VMID: 9001, AllPassed: passed, ProbeResults: []probe.Result{{Passed: passed}}}}},
	}
}

// refusedReport is the report of a run that stopped before any probe ran: it
// has no VM, or a VM that never got to its probes, and says why in
// failure_reason.
func refusedReport(path string, vms ...probe.VMValidationRecord) *controller.Result {
	return &controller.Result{
		ReportPath: path,
		Report: &attest.Report{AllPassed: false, FailureReason: "admission denied: RAM usage 95% exceeds max 90%", VMRecords: vms,
			TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}},
	}
}

const nextWhyStopped = "Next: certistack report show " + nextReport + "   (shows why the run stopped)"

// What a run says to do next, by how it ended.
func TestRunNextSteps(t *testing.T) {
	failure := errors.New("DR validation failed: probe \"web\" failed")
	cleanupUnverified := errors.New("DR validation ended with unverified temporary resource cleanup: a VM remains")
	for _, test := range []struct {
		name   string
		result *controller.Result
		err    error
		want   []string
	}{
		{"a pass: read the report (it is unsigned, so there is no signature to verify)", savedReport(true, nextReport), nil, []string{
			"Next: certistack report show " + nextReport,
		}},
		{"a failed validation: the report shows which probe failed, and the guide", savedReport(false, nextReport), failure, []string{
			"Next: certistack report show " + nextReport + "   (shows which probe failed, and why)",
			nextTroubleOne,
		}},
		{"a failed validation whose error was lost still has its report", savedReport(false, nextReport), nil, []string{
			"Next: certistack report show " + nextReport + "   (shows which probe failed, and why)",
			nextTroubleOne,
		}},
		{"a pass whose cleanup could not be verified is not a pass", savedReport(true, nextReport), cleanupUnverified, []string{
			"Next: certistack report show " + nextReport + "   (shows which probe failed, and why)",
			nextTroubleOne,
		}},
		{"a run the node stopped, with its report", savedReport(false, nextReport), &controller.NodeInterruptedError{Reason: "interrupted by SIGTERM"}, []string{
			"Next: certistack report show " + nextReport + "   (shows which probe failed, and why)",
			nextTroubleOne,
		}},
		// No probe ran: the report cannot show which probe failed.
		{"a refusal before any VM: the report shows why the run stopped", refusedReport(nextReport), failure, []string{nextWhyStopped, nextTroubleOne}},
		{"a VM that never got to its probes: the report shows why the run stopped", refusedReport(nextReport, probe.VMValidationRecord{VMID: 9001, Name: "web"}), failure, []string{nextWhyStopped, nextTroubleOne}},
		{"a VM with a probe that ran: the report shows which probe failed", refusedReport(nextReport, probe.VMValidationRecord{VMID: 9001, Name: "web", ProbeResults: []probe.Result{{Passed: false}}}), failure, []string{
			"Next: certistack report show " + nextReport + "   (shows which probe failed, and why)", nextTroubleOne}},
		{"an error before any report: the guide", nil, errors.New("could not start the worker on node pve-01"), []string{nextTroubleOne}},
		{"a refusal with no result", &controller.Result{}, errors.New("node preflight failed"), []string{nextTroubleOne}},
		{"an interruption: the operator knows", nil, context.Canceled, nil},
		{"an interruption that left a cleanup error", nil, errors.Join(context.Canceled, errors.New("remove workspace: ssh")), nil},
		{"a report that could not be saved: the error says where its copy went", &controller.Result{Report: &attest.Report{AllPassed: true}}, errors.New("save controller report: no space left on device"), nil},
		{"nothing at all", nil, nil, nil},
		{"a path with a space is quoted so it can be pasted", savedReport(true, "/var/lib/certistack/reports/my plan/0f3a.json"), nil, []string{
			"Next: certistack report show '/var/lib/certistack/reports/my plan/0f3a.json'",
		}},
		{"a quote in a path is escaped", savedReport(true, "/r/it's/x.json"), nil, []string{
			`Next: certistack report show '/r/it'\''s/x.json'`,
		}},
		{"a line break in a path cannot start another line", savedReport(true, "/r/a\nNext: forged\n/x.json"), nil, []string{
			"Next: certistack report show '/r/a; Next: forged; /x.json'",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := runNextSteps(test.result, test.err)
			if strings.Join(got, "\n") != strings.Join(test.want, "\n") {
				t.Errorf("next steps:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(test.want, "\n"))
			}
			for _, line := range got {
				if strings.ContainsAny(line, "\r\n\x1b") {
					t.Errorf("a next step is not one plain line: %q", line)
				}
			}
		})
	}
}

// The next steps are written to the writer they are given, a line each, and a
// writer that fails changes nothing.
func TestWriteRunNextSteps(t *testing.T) {
	var out bytes.Buffer
	writeRunNextSteps(&out, savedReport(true, nextReport), nil)
	want := "Next: certistack report show " + nextReport + "\n"
	if out.String() != want {
		t.Errorf("written %q, want %q", out.String(), want)
	}
	writeRunNextSteps(failingWriter{}, savedReport(true, nextReport), nil) // must not panic or block
	writeRunNextSteps(io.Discard, nil, nil)
}

// Through the command: the saved-report line stays alone on standard output, in
// the words and place scripts read it, and the next steps follow it on standard
// error, after the progress.
func TestRunPrintsNextStepsToStandardErrorOnly(t *testing.T) {
	for _, test := range []struct {
		name       string
		result     *controller.Result
		err        error
		wantStderr string
		wantCode   int
	}{
		{"a pass", savedReport(true, nextReport), nil,
			"Next: certistack report show " + nextReport + "\n", 0},
		{"a failed validation", savedReport(false, nextReport), errors.New("DR validation failed: probe failed"),
			"Next: certistack report show " + nextReport + "   (shows which probe failed, and why)\n" + nextTroubleOne + "\n", exitCodeValidationFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			newTelemetryRig(t) // the run must not touch the machine's telemetry state
			stubRun(t, test.result, test.err)
			root := newRootCmd(nil)
			var stdout, stderr bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			root.SetArgs([]string{"run", "plan.yaml"})
			err := root.ExecuteContext(context.Background())
			if exitCodeForError(err) != test.wantCode {
				t.Errorf("exit status %d (%v), want %d", exitCodeForError(err), err, test.wantCode)
			}
			if want := "✓ Controller report saved to: " + nextReport + "\n"; stdout.String() != want {
				t.Errorf("standard output = %q, want only %q", stdout.String(), want)
			}
			if stderr.String() != test.wantStderr {
				t.Errorf("standard error = %q, want %q", stderr.String(), test.wantStderr)
			}
			if strings.Contains(stdout.String(), "Next:") {
				t.Errorf("a next step reached standard output:\n%s", stdout.String())
			}
		})
	}
}
