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
	if want := "Looking in " + dir + " (--reports-dir)\nNewest report: " + newPath + "\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
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

// Without --reports-dir, report show looks where run saves: the
// CERTISTACK_OUTPUT_DIR of the environment file setup recorded, so a controller
// installed without sudo, whose reports are not in /var/lib/certistack, finds
// its last report. The flag overrides it, and with nothing recorded the
// default directory is the one searched.
func TestReportShowWithNoFileLooksWhereTheEnvironmentFileSaysRunSaves(t *testing.T) {
	pointer := withUserConfigDir(t)
	reports := viewFixtureReports()
	saved, other := t.TempDir(), t.TempDir()
	for _, dir := range []string{saved, other} {
		if err := os.MkdirAll(filepath.Join(dir, "plan"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	savedPath := writeFixtureReport(t, filepath.Join(saved, "plan"), "run-1.json", reports["twin-pass"], nil)
	otherPath := writeFixtureReport(t, filepath.Join(other, "plan"), "run-2.json", reports["twin-fail"], nil)
	envFile := writeEnvFile(t, "CERTISTACK_OUTPUT_DIR="+saved+"\n")
	if err := recordEnvFile(pointer, envFile); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CERTISTACK_OUTPUT_DIR", "")

	stdout, stderr, err := runReportCommand(t, "report", "show")
	if err != nil {
		t.Fatalf("report show: %v (stderr %q)", err, stderr)
	}
	if want := "Looking in " + saved + " (CERTISTACK_OUTPUT_DIR in " + envFile + ")\nNewest report: " + savedPath + "\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if named, _, err := runReportCommand(t, "report", "show", savedPath); err != nil || stdout != named {
		t.Errorf("the report in the environment file's directory is not shown as naming it shows it (err %v)", err)
	}
	if os.Getenv("CERTISTACK_OUTPUT_DIR") != "" {
		t.Error("report show left the environment file's values in the process environment")
	}

	// An explicit --reports-dir wins over the environment file.
	_, stderr, err = runReportCommand(t, "report", "show", "--reports-dir", other)
	if err != nil {
		t.Fatalf("report show --reports-dir: %v (stderr %q)", err, stderr)
	}
	if want := "Looking in " + other + " (--reports-dir)\nNewest report: " + otherPath + "\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}

// With no environment file, the process environment's CERTISTACK_OUTPUT_DIR is
// run's too (PVE_URL set: the controller container, whose environment is the
// file); with neither, the default directory is searched and named.
func TestReportShowWithNoFileFallsBackToTheProcessEnvironmentThenTheDefault(t *testing.T) {
	withUserConfigDir(t)
	reports := viewFixtureReports()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "plan"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := writeFixtureReport(t, filepath.Join(dir, "plan"), "run-1.json", reports["twin-pass"], nil)

	t.Setenv("PVE_URL", "https://pve.example.invalid:8006")
	t.Setenv("CERTISTACK_OUTPUT_DIR", dir)
	_, stderr, err := runReportCommand(t, "report", "show")
	if err != nil {
		t.Fatalf("report show: %v (stderr %q)", err, stderr)
	}
	if want := "Looking in " + dir + " (CERTISTACK_OUTPUT_DIR in the environment)\nNewest report: " + path + "\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}

	t.Setenv("PVE_URL", "")
	t.Setenv("CERTISTACK_OUTPUT_DIR", "")
	_, stderr, _ = runReportCommand(t, "report", "show")
	if want := "Looking in " + defaultReportsDir + " (the default)\n"; !strings.HasPrefix(stderr, want) {
		t.Errorf("stderr = %q, want it to start with %q", stderr, want)
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
