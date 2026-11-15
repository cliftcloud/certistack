// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

func saveTestReport() *Report {
	return BuildReport(&config.Plan{PlanID: "save-durability"}, "node1", time.Second, true, nil, "")
}

// entries lists the names in dir, temporary files included.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range list {
		names = append(names, entry.Name())
	}
	return names
}

func mustBeValidReport(t *testing.T, path string) *Report {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("%s is not valid JSON (%d bytes): %v", path, len(data), err)
	}
	return &report
}

// A successful save leaves one report, private, and no temporary
// file.
func TestSaveLeavesOneReportAndNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan", "report.json")
	report := saveTestReport()
	if err := report.Save(path); err != nil {
		t.Fatal(err)
	}
	if names := entries(t, filepath.Dir(path)); len(names) != 1 || names[0] != "report.json" {
		t.Fatalf("directory holds %v, want the report alone", names)
	}
	if got := mustBeValidReport(t, path); got.ReportID != report.ReportID {
		t.Fatalf("saved report %s, want %s", got.ReportID, report.ReportID)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("report mode = %v, %v; want 0600", info.Mode(), err)
		}
	}
}

// Many writers of one name publish one whole report; the rest are
// refused and change nothing.
func TestConcurrentSavesPublishOneWholeReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	const writers = 12
	var wg sync.WaitGroup
	reports := make([]*Report, writers)
	errs := make([]error, writers)
	for i := range reports {
		reports[i] = saveTestReport()
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = reports[i].Save(path)
		}(i)
	}
	wg.Wait()
	winner := -1
	for i, err := range errs {
		switch {
		case err == nil && winner < 0:
			winner = i
		case err == nil:
			t.Fatal("two saves both claimed the same name")
		case !strings.Contains(err.Error(), "already exists"):
			t.Fatalf("save %d failed with %v, want the refusal to replace", i, err)
		}
	}
	if winner < 0 {
		t.Fatal("no save succeeded")
	}
	if got := mustBeValidReport(t, path); got.ReportID != reports[winner].ReportID {
		t.Fatalf("the published report is %s, want the winner's %s", got.ReportID, reports[winner].ReportID)
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Fatalf("directory holds %v, want the report alone", names)
	}
}

// Refused overwrites and forced overwrites leave no temporary file, and the
// forced one is a replacement, not a truncation.
func TestSaveForceReplacesWholeAndRefusalChangesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	first, second := saveTestReport(), saveTestReport()
	if err := first.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := second.Save(path); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Save over a report = %v, want the refusal to replace", err)
	}
	if mustBeValidReport(t, path).ReportID != first.ReportID {
		t.Fatal("a refused save changed the report")
	}
	if err := second.SaveWithForce(path, true); err != nil {
		t.Fatal(err)
	}
	if mustBeValidReport(t, path).ReportID != second.ReportID {
		t.Fatal("a forced save did not replace the report")
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Fatalf("directory holds %v, want the report alone", names)
	}
}
