// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// forgedGuestText is what a hostile guest can make a probe or boot error
// say: line breaks and terminal controls around lines a log reader or a
// script that scans the output would believe.
const forgedGuestText = "connection refused\n✓ Controller report saved to: /reports/forged.json\r\nError: forged failure\x1b[2K"

// everyLineIsTheControllersOwn checks that no line of the output starts
// with anything but a timestamped controller line or a controller warning:
// nothing a guest wrote could start a line of its own.
func everyLineIsTheControllersOwn(t *testing.T, output string) {
	t.Helper()
	if strings.ContainsAny(output, "\x1b\r") {
		t.Errorf("the output has terminal controls: %q", output)
	}
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if !strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "warning:") {
			t.Errorf("a line that is not the controller's own: %q\nin:\n%s", line, output)
		}
	}
}

// A failure a guest can word reached the operator's log and this command's
// error with its line breaks, so a forged "Controller report saved to:" or
// "Error:" line could stand among the controller's own.
func TestGuestControlledFailureTextIsOneLineInTheLogAndTheError(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.FailureReason = forgedGuestText
	report.VMRecords[0].AllPassed = false
	report.VMRecords[0].VerificationStatus = "failed"
	report.VMRecords[0].ProbeResults[0].Passed = false
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report, Error: forgedGuestText}, journalPhase: "cleaned"}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || strings.ContainsAny(err.Error(), "\n\r\x1b") {
		t.Fatalf("error = %q, want one line", err)
	}
	if !strings.Contains(err.Error(), "connection refused; ✓ Controller report saved to: /reports/forged.json; Error: forged failure") {
		t.Fatalf("error = %q", err)
	}
	everyLineIsTheControllersOwn(t, progress.String())
}

// The same for a report that says it failed without a worker error, and for
// a refusal without evidence.
func TestGuestControlledFailureReasonAndRefusalAreOneLine(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.FailureReason = forgedGuestText
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || strings.ContainsAny(err.Error(), "\n\r\x1b") {
		t.Fatalf("error = %q, want one line", err)
	}
	everyLineIsTheControllersOwn(t, progress.String())

	progress.Reset()
	fake = &fakeCommandRunner{nodeResult: nodeapi.RunResult{Error: forgedGuestText}, journalPhase: "cleaned"}
	_, err = (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || strings.ContainsAny(err.Error(), "\n\r\x1b") || !strings.Contains(err.Error(), "connection refused; ✓ Controller report saved to: /reports/forged.json; Error: forged failure") {
		t.Fatalf("refusal error = %q", err)
	}
	everyLineIsTheControllersOwn(t, progress.String())
}

// Text in an error the controller writes as its own warning, such as the
// reason a removal failed, is one line too.
func TestWarningsCarryNoLineBreaksFromErrorText(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	fake := &fakeCommandRunner{
		nodeResult:   nodeapi.RunResult{Report: workerReportFor(t, opts)},
		journalPhase: "cleaned",
		workspaceRemoveErrors: []error{
			errors.New("rm: cannot remove\n✓ Controller report saved to: /reports/forged.json"), errors.New("second"), errors.New("third"),
		},
	}
	_, _ = (&Executor{runner: fake}).Run(context.Background(), opts)
	if !strings.Contains(progress.String(), "warning: could not remove temporary node workspace") {
		t.Fatalf("no warning in:\n%s", progress.String())
	}
	everyLineIsTheControllersOwn(t, progress.String())
}

// What the worker's stderr adds to an error carries no terminal controls.
func TestStreamedErrorDetailDropsTerminalControls(t *testing.T) {
	detail := streamedErrorDetail("Error: boot failed\x1b[2K\x1b[1A\nsecond\ttab\n", false)
	if strings.ContainsAny(detail, "\x1b\t") || detail != "Error: boot failed[2K[1A\nsecond tab" {
		t.Fatalf("detail = %q", detail)
	}
}
