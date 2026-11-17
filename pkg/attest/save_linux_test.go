//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestSaveShortWriteChild is the child of the short-write tests: it saves a
// report with the process's file size limit at 96 bytes, which makes the
// write fail with EFBIG after a partial write, as a full disk or a quota
// does, and prints what Save returned. It does nothing on its own.
func TestSaveShortWriteChild(t *testing.T) {
	dir := os.Getenv("CERTISTACK_SAVE_CHILD_DIR")
	if dir == "" {
		t.Skip("helper of the short-write tests")
	}
	signal.Ignore(syscall.SIGXFSZ)
	limit := syscall.Rlimit{Cur: 96, Max: 96}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		fmt.Println("CHILD-SETUP-FAILED:", err)
		return
	}
	err := saveTestReport().SaveWithForce(filepath.Join(dir, "report.json"), os.Getenv("CERTISTACK_SAVE_CHILD_FORCE") == "1")
	if err == nil {
		fmt.Println("CHILD-SAVED")
		return
	}
	fmt.Println("CHILD-ERROR:", err)
}

func saveWithShortWrite(t *testing.T, dir string, force bool) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSaveShortWriteChild$", "-test.v")
	cmd.Env = append(os.Environ(), "CERTISTACK_SAVE_CHILD_DIR="+dir)
	if force {
		cmd.Env = append(cmd.Env, "CERTISTACK_SAVE_CHILD_FORCE=1")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
	}
	text := string(out)
	if strings.Contains(text, "CHILD-SETUP-FAILED") || !strings.Contains(text, "CHILD-ERROR:") {
		t.Fatalf("the child did not fail its save with a short write:\n%s", text)
	}
	if !strings.Contains(text, "file too large") {
		t.Fatalf("the child failed for another reason:\n%s", text)
	}
	return text
}

// A save that fails partway leaves nothing at all, not a partial report at
// the final name (invalid JSON among the evidence, which a plain save would
// refuse to replace), and the same save, tried again, succeeds.
func TestFailedSaveLeavesNoPartialReportAndCanBeRetried(t *testing.T) {
	dir := t.TempDir()
	saveWithShortWrite(t, dir, false)
	if names := entries(t, dir); len(names) != 0 {
		t.Fatalf("a failed save left %v behind", names)
	}
	report := saveTestReport()
	if err := report.Save(filepath.Join(dir, "report.json")); err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	if mustBeValidReport(t, filepath.Join(dir, "report.json")).ReportID != report.ReportID {
		t.Fatal("the retry saved another report")
	}
}

// A forced save that fails leaves the report it would have replaced
// exactly as it was, where truncating it in place left a fragment.
func TestFailedForcedSaveLeavesTheExistingReportWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	existing := saveTestReport()
	if err := existing.Save(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	saveWithShortWrite(t, dir, true)
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("the existing report changed (%d bytes, was %d): %v", len(after), len(before), err)
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Fatalf("directory holds %v, want the report alone", names)
	}
}
