// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/controller"
)

func TestFormatRunErrorPreservesCleanupFailure(t *testing.T) {
	cleanupErr := errors.New("temporary node workspace /var/lib/certistack/workers/run-123 could not be removed")
	got := formatRunError(errors.Join(context.Canceled, cleanupErr))
	if got == nil {
		t.Fatal("formatRunError returned nil for an interrupted run with cleanup failure")
	}
	if !errors.Is(got, cleanupErr) {
		t.Fatalf("formatted error lost cleanup failure: %v", got)
	}
	if !strings.Contains(got.Error(), "validation interrupted") || !strings.Contains(got.Error(), "/var/lib/certistack/workers/run-123") {
		t.Fatalf("formatted error lost interruption context or workspace path: %v", got)
	}
	if strings.Contains(got.Error(), "verified cleanup") {
		t.Fatalf("cleanup failure was falsely reported as verified: %v", got)
	}
}

func TestFormatRunErrorUsesVerifiedCleanupMessageForBareCancellation(t *testing.T) {
	got := formatRunError(context.Canceled)
	if got == nil || !strings.Contains(got.Error(), "verified cleanup") {
		t.Fatalf("bare cancellation message = %v", got)
	}
	if !errors.Is(got, context.Canceled) {
		t.Fatalf("bare cancellation lost its cancellation cause: %v", got)
	}
	if strings.HasSuffix(got.Error(), "context canceled") {
		t.Fatalf("bare cancellation message ends with the Go error: %v", got)
	}
}

// A run whose credential-bearing controller material (the node workspace
// with its environment, or the SSH staging directory) was not verified removed
// exits 2 in EVERY outcome. A failed validation with verified cleanup keeps
// exit 1, so a campaign that credits a fault or a capacity guard only on
// status 1 never credits a run that left its credentials on the node.
func TestRunOutcomeErrorExitStatuses(t *testing.T) {
	cleanupFailure := fmt.Errorf("%w: %w", controller.ErrControllerMaterialCleanupUnverified, errors.New("remove workspace: ssh: connection reset"))
	failedValidation := errors.New("DR validation failed: probe \"LDAP\" failed")
	report := func(passed, cleaned bool) *controller.Result {
		return &controller.Result{
			ReportPath: "/reports/plan/report.json",
			Report:     &attest.Report{AllPassed: passed, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: cleaned}},
		}
	}
	cases := []struct {
		name   string
		result *controller.Result
		err    error
		want   int
	}{
		{"a passed run", report(true, true), nil, 0},
		{"a failed validation with verified cleanup", report(false, true), failedValidation, exitCodeValidationFailed},
		{"a failed validation with no error text", report(false, true), nil, exitCodeValidationFailed},
		{"a failed validation whose node cleanup was not verified", report(false, false), failedValidation, exitCodeInfrastructure},
		{"a passed run whose controller material cleanup was not verified", report(true, true), cleanupFailure, exitCodeInfrastructure},
		{"a failed validation whose controller material cleanup was not verified", report(false, true), errors.Join(failedValidation, cleanupFailure), exitCodeInfrastructure},
		// The signed report of a failed validation could not be saved: the
		// evidence is not archived, which is not a failed validation with
		// verified cleanup.
		{"a failed validation whose report could not be saved", &controller.Result{Report: &attest.Report{AllPassed: false, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}}}, errors.New("save controller report /r/p/x.json: no space left on device"), exitCodeInfrastructure},
		{"a failed validation whose report could not be saved, with no error", &controller.Result{Report: &attest.Report{AllPassed: false, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}}}, nil, exitCodeInfrastructure},
		{"a passed run whose report could not be saved", &controller.Result{Report: &attest.Report{AllPassed: true, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}}}, errors.New("save controller report: full"), exitCodeInfrastructure},
		{"an interruption whose report could not be saved", &controller.Result{Report: &attest.Report{AllPassed: false}}, errors.Join(context.Canceled, errors.New("save controller report: full")), exitCodeInterrupted},
		{"a run with no report", nil, errors.New("could not start the worker"), exitCodeInfrastructure},
		{"an interruption", nil, context.Canceled, exitCodeInterrupted},
		{"an interruption that left controller material", nil, errors.Join(context.Canceled, cleanupFailure), exitCodeInterrupted},
	}
	for _, test := range cases {
		err := runOutcomeError(test.result, test.err)
		if got := exitCodeForError(err); got != test.want {
			t.Errorf("%s: exit status %d (err %v), want %d", test.name, got, err, test.want)
		}
		if test.want == 0 && err != nil {
			t.Errorf("%s: returned %v", test.name, err)
		}
	}
}

// runOutcomeError recognizes the controller's cleanup failure by the
// sentinel pkg/controller wraps (errors.Is), never by its wording. The wording
// operators read is still the controller's, and the sentinel's message is it:
// a run that left credentials on the node exits 2 and says so in words a
// scan of the output would find. The source must still build the error from
// the sentinel, with the wording unchanged.
func TestControllerCleanupUnverifiedSentinelCarriesTheWording(t *testing.T) {
	if got := controller.ErrControllerMaterialCleanupUnverified.Error(); got != controllerCleanupUnverified {
		t.Fatalf("the sentinel says %q, want %q", got, controllerCleanupUnverified)
	}
	source, err := os.ReadFile(filepath.Join("..", "..", "pkg", "controller", "ssh.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), `fmt.Errorf("%w: %w", ErrControllerMaterialCleanupUnverified,`) || !strings.Contains(string(source), `errors.New("`+controllerCleanupUnverified+`")`) {
		t.Fatalf("pkg/controller no longer builds its cleanup failure from ErrControllerMaterialCleanupUnverified with the wording %q", controllerCleanupUnverified)
	}
	// The wording alone, without the sentinel, is no cleanup failure.
	wordingOnly := errors.New(controllerCleanupUnverified + ": remove workspace: ssh: connection reset")
	if got := exitCodeForError(runOutcomeError(nil, wordingOnly)); got != exitCodeInfrastructure {
		t.Fatalf("a run with no report exits %d", got)
	}
	failed := &controller.Result{ReportPath: "/r.json", Report: &attest.Report{AllPassed: false, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}}}
	if got := exitCodeForError(runOutcomeError(failed, errors.Join(errors.New("DR validation failed: x"), wordingOnly))); got != exitCodeValidationFailed {
		t.Fatalf("wording without the sentinel changed the status to %d", got)
	}
}

// A signed report that could be neither saved nor written to the
// operator's progress output is written to standard output instead, and the
// error says which copy exists; a failing standard output is an error too.
func TestUnsavedReportFallbackWritesTheReportToStandardOutput(t *testing.T) {
	_, key, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := &attest.Report{ReportID: "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f", PlanID: "p", AllPassed: true}
	if err := attesttest.SignReport(report, key); err != nil {
		t.Fatal(err)
	}
	saveErr := errors.New("save controller report /reports/p/x.json: no space left on device")
	notWritten := errors.Join(saveErr, fmt.Errorf("%w (closed pipe)", controller.ErrEmergencyReportNotWritten))
	unsaved := &controller.Result{Report: report}

	var stdout bytes.Buffer
	got := unsavedReportFallback(&stdout, unsaved, notWritten)
	text := stdout.String()
	begin, end := strings.Index(text, "-----BEGIN CERTISTACK REPORT-----\n"), strings.Index(text, "\n-----END CERTISTACK REPORT-----")
	if !errors.Is(got, saveErr) || !strings.Contains(got.Error(), "written to standard output instead") || begin < 0 || end < begin {
		t.Fatalf("err = %v, stdout:\n%s", got, text)
	}
	if _, valid, err := attest.VerifyReportSignatureOnly([]byte(text[begin+len("-----BEGIN CERTISTACK REPORT-----\n") : end])); err != nil || !valid {
		t.Fatalf("the copy on standard output does not verify: %v", err)
	}

	got = unsavedReportFallback(failingWriter{}, unsaved, notWritten)
	if !strings.Contains(got.Error(), "on standard output failed as well") || !errors.Is(got, controller.ErrEmergencyReportNotWritten) {
		t.Fatalf("err = %v", got)
	}

	// Without the failed first copy, or with a saved report, nothing is written.
	for name, c := range map[string]struct {
		result *controller.Result
		err    error
	}{
		"the first copy was written": {unsaved, saveErr},
		"the report was saved":       {&controller.Result{Report: report, ReportPath: "/reports/p/x.json"}, notWritten},
		"there is no report":         {nil, notWritten},
	} {
		stdout.Reset()
		if got := unsavedReportFallback(&stdout, c.result, c.err); got != c.err || stdout.Len() != 0 {
			t.Errorf("%s: err = %v, stdout %q", name, got, stdout.String())
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write /dev/stdout: broken pipe")
}

func TestSignalContextsCancelCleanupOnlyAfterSecondSignal(t *testing.T) {
	signals := make(chan os.Signal, 2)
	var output bytes.Buffer
	ctx, cleanupCtx, stop := newSignalContexts(signals, &output)
	defer stop()

	signals <- os.Interrupt
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("first signal did not cancel the run context")
	}
	select {
	case <-cleanupCtx.Done():
		t.Fatal("first signal canceled the cleanup context")
	default:
	}

	signals <- os.Interrupt
	select {
	case <-cleanupCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("second signal did not cancel the cleanup context")
	}
	if !strings.Contains(output.String(), "Press Ctrl-C again to abandon cleanup") {
		t.Fatalf("signal guidance = %q", output.String())
	}
}

// On a node, the supervisor stops the worker with SIGTERM once the
// controller's lease expires; nobody is there to press Ctrl-C.
func TestSignalContextsDoNotOfferCtrlCForAStopSignal(t *testing.T) {
	signals := make(chan os.Signal, 2)
	var output bytes.Buffer
	ctx, _, stop := newSignalContexts(signals, &output)
	defer stop()
	signals <- syscall.SIGTERM
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("SIGTERM did not cancel the run context")
	}
	if got := output.String(); strings.Contains(got, "Ctrl-C") || !strings.Contains(got, "Stop signal received (terminated); cleaning up") {
		t.Fatalf("stop signal guidance = %q", got)
	}
}

func TestExitCodeForError(t *testing.T) {
	if got := exitCodeForError(withExitCode(errors.New("invalid plan"), exitCodeValidationFailed)); got != exitCodeValidationFailed {
		t.Fatalf("validation exit code = %d", got)
	}
	if got := exitCodeForError(errors.New("SSH unavailable")); got != exitCodeInfrastructure {
		t.Fatalf("infrastructure exit code = %d", got)
	}
	if got := exitCodeForError(context.Canceled); got != exitCodeInterrupted {
		t.Fatalf("interrupted exit code = %d", got)
	}
}
