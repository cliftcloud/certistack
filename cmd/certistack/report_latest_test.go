// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// With no file named, report show reads the newest report run saved, names
// it on standard error, and shows exactly what naming that file would show.
func TestReportShowWithNoFileShowsTheNewestReport(t *testing.T) {
	reports := viewFixtureReports()
	dir := t.TempDir()
	older := filepath.Join(dir, "plan-a")
	newer := filepath.Join(dir, "plan-b")
	for _, d := range []string{older, newer} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldPath := writeFixtureReport(t, older, "run-1.json", reports["twin-fail"], nil)
	newPath := writeFixtureReport(t, newer, "run-2.json", reports["twin-pass"], nil)
	setModTime(t, oldPath, time.Now().Add(-time.Hour))
	setModTime(t, newPath, time.Now())

	stdout, stderr, err := runReportCommand(t, "report", "show", "--reports-dir", dir)
	if err != nil {
		t.Fatalf("report show: %v (stderr %q)", err, stderr)
	}
	if stderr != "Newest report: "+newPath+"\n" {
		t.Errorf("stderr = %q, want it to name %s", stderr, newPath)
	}
	named, _, err := runReportCommand(t, "report", "show", newPath)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != named {
		t.Error("the newest report is not shown as naming its file shows it")
	}

	// --json stays pure JSON on standard output.
	jsonOut, jsonErr, err := runReportCommand(t, "report", "show", "--reports-dir", dir, "--json")
	if err != nil || !strings.HasPrefix(jsonOut, "{") || !strings.Contains(jsonErr, newPath) {
		t.Errorf("--json: err %v, stdout starts %q, stderr %q", err, firstLine(jsonOut), jsonErr)
	}
}

// Only reports count: hidden files, files that are not JSON, symbolic links,
// refused results and files directly in the reports directory are skipped,
// and ties in time go to the name that sorts last.
func TestNewestReportSkipsWhatIsNotAReport(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan")
	refused := filepath.Join(dir, "refused")
	for _, d := range []string{plan, refused} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().Add(-time.Hour)
	write := func(path string, at time.Time) {
		t.Helper()
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		setModTime(t, path, at)
	}
	write(filepath.Join(plan, "a.json"), base)
	write(filepath.Join(plan, "b.json"), base)
	later := base.Add(time.Minute)
	write(filepath.Join(plan, ".certistack-write-check-1"), later)
	write(filepath.Join(plan, ".hidden.json"), later)
	write(filepath.Join(plan, "notes.txt"), later)
	write(filepath.Join(refused, "run-x.json"), later)
	write(filepath.Join(dir, "top.json"), later)
	if err := os.Symlink(filepath.Join(plan, "a.json"), filepath.Join(plan, "z.json")); err != nil {
		t.Fatal(err)
	}

	got, err := newestReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(plan, "b.json"); got != want {
		t.Errorf("newestReport = %s, want %s", got, want)
	}
}

// No reports directory, or one with no report in it, says to run a plan first.
func TestNewestReportSaysToRunAPlanFirst(t *testing.T) {
	for _, dir := range []string{filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		_, err := newestReport(dir)
		if err == nil || !strings.Contains(err.Error(), "no reports in "+dir) || !strings.Contains(err.Error(), "certistack run") {
			t.Errorf("newestReport(%s) = %v, want it to say there are no reports and to run a plan", dir, err)
		}
	}
}

func setModTime(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
