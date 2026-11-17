// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// limitedWriter takes limit bytes in all, then fails: with err after a
// partial write, or, when short is set, with no error at all.
type limitedWriter struct {
	limit   int
	short   bool
	written bytes.Buffer
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	room := w.limit - w.written.Len()
	if room >= len(p) {
		return w.written.Write(p)
	}
	if room < 0 {
		room = 0
	}
	w.written.Write(p[:room])
	if w.short {
		return room, nil
	}
	return room, io.ErrClosedPipe
}

// unsavableRun runs a validation whose report directory becomes unusable
// after its preflight, as a full disk does, with the operator's output going
// to w.
func unsavableRun(t *testing.T, w io.Writer, mutate func(*fakeCommandRunner)) (*Result, error) {
	t.Helper()
	opts := preflightTestOptions(t)
	opts.Writer = w
	report := workerReportFor(t, opts)
	planDir := filepath.Join(opts.OutputDir, report.PlanID)
	fake := &fakeCommandRunner{
		nodeResult:   nodeapi.RunResult{Report: report},
		journalPhase: "cleaned",
		nodeRunHook: func() {
			if err := os.RemoveAll(planDir); err != nil {
				t.Error(err)
			}
			if err := os.WriteFile(planDir, nil, 0600); err != nil {
				t.Error(err)
			}
		},
	}
	if mutate != nil {
		mutate(fake)
	}
	return (&Executor{runner: fake}).Run(context.Background(), opts)
}

// When the report cannot be saved and the operator's output fails too, the
// failure of the emergency copy is an error of the run, next to the storage
// error, and the signed report is still returned: the report must not exist
// only in memory without a word of it.
func TestFailureOfTheEmergencyReportOutputIsAnErrorOfTheRun(t *testing.T) {
	for name, tc := range map[string]struct {
		writer     func() io.Writer
		wantDetail string
	}{
		"every write fails":       {func() io.Writer { return &limitedWriter{limit: 0} }, "wrote 0 of"},
		"fails partway through":   {func() io.Writer { return &limitedWriter{limit: 500} }, "closed pipe"},
		"a short write, no error": {func() io.Writer { return &limitedWriter{limit: 500, short: true} }, io.ErrShortWrite.Error()},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := unsavableRun(t, tc.writer(), nil)
			if err == nil || !strings.Contains(err.Error(), "save controller report") {
				t.Fatalf("err = %v, want the storage failure", err)
			}
			if !errors.Is(err, ErrEmergencyReportNotWritten) || !strings.Contains(err.Error(), tc.wantDetail) || !strings.Contains(err.Error(), "as Result.Report") {
				t.Fatalf("err = %v, want the failed emergency copy reported (%q)", err, tc.wantDetail)
			}
			if result == nil || result.Report == nil || result.Report.Signature == "" || result.ReportPath != "" {
				t.Fatalf("result = %+v, want the signed, unsaved report", result)
			}
		})
	}
}

// Control: when the emergency copy is written, the error is the
// storage failure alone and the copy verifies.
func TestEmergencyReportOutputThatWorksIsNotAnError(t *testing.T) {
	var out bytes.Buffer
	result, err := unsavableRun(t, &out, nil)
	if err == nil || errors.Is(err, ErrEmergencyReportNotWritten) {
		t.Fatalf("err = %v, want the storage failure alone", err)
	}
	text := out.String()
	begin := strings.Index(text, "-----BEGIN CERTISTACK REPORT-----\n")
	end := strings.Index(text, "\n-----END CERTISTACK REPORT-----")
	if begin < 0 || end < begin || result == nil {
		t.Fatalf("the output lacks the report between markers:\n%s", text)
	}
	if _, valid, verr := attest.VerifyReportSignatureOnly([]byte(text[begin+len("-----BEGIN CERTISTACK REPORT-----\n") : end])); verr != nil || !valid {
		t.Fatalf("the emergency copy does not verify: %v", verr)
	}
}

// A report that could not be saved, from a run whose cleanup could not be
// verified either, says both.
func TestUnsavedReportAndUnverifiedCleanupAreBothReported(t *testing.T) {
	var out bytes.Buffer
	_, err := unsavableRun(t, &out, func(f *fakeCommandRunner) { f.journalState = "absent" })
	if err == nil || !strings.Contains(err.Error(), "save controller report") || !strings.Contains(err.Error(), "cleanup could not be verified either") {
		t.Fatalf("err = %v", err)
	}
}

func TestWriteUnsavedReportSaysHowMuchWasWritten(t *testing.T) {
	report := &attest.Report{ReportID: "x"}
	w := &limitedWriter{limit: 20}
	err := WriteUnsavedReport(w, report)
	if err == nil || !errors.Is(err, io.ErrClosedPipe) || !strings.HasPrefix(err.Error(), "wrote 20 of ") {
		t.Fatalf("err = %v", err)
	}
	if err := WriteUnsavedReport(io.Discard, report); err != nil {
		t.Fatal(err)
	}
}
