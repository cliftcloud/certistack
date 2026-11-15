// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// caseInsensitiveFS reports whether dir's filesystem treats two names that
// differ only in case as one file.
func caseInsensitiveFS(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "case-probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(probe)
	_, err := os.Stat(filepath.Join(dir, "CASE-PROBE"))
	return err == nil
}

// linkDirectory makes link another name for the directory target: a symbolic
// link, or on Windows, where creating one needs a privilege an ordinary
// account lacks, a junction, which needs none and resolves the same way.
func linkDirectory(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err != nil && runtime.GOOS == "windows" {
		if out, junctionErr := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); junctionErr != nil {
			t.Skipf("neither a symbolic link (%v) nor a junction (%v: %s) can be made here", err, junctionErr, out)
		}
		return
	}
	if err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
}

// Filesystems with neither a no-replace rename nor hard links (FAT and exFAT,
// some FUSE and network mounts): the fallback creates the destination
// exclusively and writes it in place, and must not leave the staging file, a
// second copy of the report, behind, or refuse the next save because of it.
func TestFallbackPublicationLeavesNoStagingCopy(t *testing.T) {
	previous := noReplaceRename
	noReplaceRename = func(string, string) error { return errNoAtomicNoReplace }
	t.Cleanup(func() { noReplaceRename = previous })

	dir := t.TempDir()
	first := BuildReport(&config.Plan{PlanID: "p"}, "n", time.Second, true, nil, "")
	second := BuildReport(&config.Plan{PlanID: "p"}, "n", 2*time.Second, false, nil, "")
	path := filepath.Join(dir, "reports", "report.json")
	if err := first.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	assertAbsent(t, stagingPath(path))
	if got := mustBeValidReport(t, path); got.ReportID != first.ReportID {
		t.Fatalf("the report saved through the fallback is %s, want %s", got.ReportID, first.ReportID)
	}
	// The next save, forced, is not refused because of a leftover.
	if err := second.SaveWithForce(path, true); err != nil {
		t.Fatalf("the next forced save is refused: %v", err)
	}
	if got := mustBeValidReport(t, path); got.ReportID != second.ReportID {
		t.Fatalf("the forced replacement is %s, want %s", got.ReportID, second.ReportID)
	}
	assertAbsent(t, stagingPath(path))

	// An unforced save over an existing report is still refused, and cleans up.
	if err := first.Save(path); err == nil {
		t.Fatal("an unforced report save replaced a report")
	}
	assertAbsent(t, stagingPath(path))
	if got := mustBeValidReport(t, path); got.ReportID != second.ReportID {
		t.Fatalf("the refused save changed the report to %s", got.ReportID)
	}
}

// A staging file left by an earlier write, or held by one still running, stops
// the next write of that report with a message that says what it is and that it
// can be deleted when nothing is running; it hints at nothing else.
func TestALeftoverReportStagingFileIsNamedAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	report := BuildReport(&config.Plan{PlanID: "p"}, "n", time.Second, true, nil, "")
	reportPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(stagingPath(reportPath), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := report.Save(reportPath)
	var exists *stagingExistsError
	if !errors.As(err, &exists) || !strings.Contains(err.Error(), stagingPath(reportPath)+" already exists") || !strings.Contains(err.Error(), "delete it and retry") {
		t.Fatalf("a report's staging file: %v", err)
	}
	for _, unrelated := range []string{"keygen", "rotation", "rename"} {
		if strings.Contains(err.Error(), unrelated) {
			t.Errorf("the message mentions %q: %v", unrelated, err)
		}
	}
	assertAbsent(t, reportPath)
}
