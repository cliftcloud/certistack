//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
)

// A worker killed while a screendump exists leaves a diagnostic copy of a
// console in the scratch directory. The capture journals its exact file names
// before QEMU writes them, and recovery removes what is still recorded: those
// files, as plain files of that name in the run's scratch directory, and nothing
// else.
func TestRecoveryRemovesTheScreenshotFilesTheRunJournaled(t *testing.T) {
	scratch := t.TempDir()
	write := func(name string) string {
		path := filepath.Join(scratch, name)
		if err := os.WriteFile(path, []byte("console image"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	frame := write("certistack-failure-vm9100-1790000000-0123abcd.ppm")
	image := write("certistack-failure-vm9100-1790000000-0123abcd.png")
	neverMade := filepath.Join(scratch, "certistack-failure-vm9100-1790000001-89abcdef.png")
	bystander := write("certistack-failure-vm9100-1790000002-aaaaaaaa.png") // not in the journal: nothing is swept by name
	other := write("notes.txt")

	record := journal.Record{RunID: "run-shot", Phase: "running", UpdatedAt: time.Now().UTC(), Scratch: scratch}
	record.AddScreenshotFiles(frame, image, neverMade)
	stateDir := t.TempDir()
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery = %v", err)
	}
	for _, gone := range []string{frame, image} {
		if _, err := os.Stat(gone); err == nil {
			t.Errorf("%s was not removed", gone)
		}
	}
	for _, kept := range []string{bystander, other} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s, which the journal does not record, was removed: %v", kept, err)
		}
	}
	after := journalPhase(t, stateDir)
	if after.Phase != "cleaned" || len(after.ScreenshotFiles) != 0 {
		t.Fatalf("journal phase %q with screenshot files %v; want cleaned and none left", after.Phase, after.ScreenshotFiles)
	}
}

// What the journal names but is not a screenshot file of the scratch directory
// is refused and left, and the journal keeps it for an operator.
func TestRecoveryLeavesAScreenshotEntryThatIsNotOne(t *testing.T) {
	scratch := t.TempDir()
	outside := filepath.Join(t.TempDir(), "certistack-failure-vm9100-1790000000-0123abcd.png") // the right name, another directory
	if err := os.WriteFile(outside, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongName := filepath.Join(scratch, "report.json")
	if err := os.WriteFile(wrongName, []byte("a report"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("the link's target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(scratch, "certistack-failure-vm9100-1790000003-bbbbbbbb.png")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(scratch, "certistack-failure-vm9100-1790000004-cccccccc.png")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	record := journal.Record{RunID: "run-shot2", Phase: "running", UpdatedAt: time.Now().UTC(), Scratch: scratch}
	record.AddScreenshotFiles(outside, wrongName, link, dir, "relative/certistack-failure-vm9100-1790000005-dddddddd.png")
	stateDir := t.TempDir()
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	err := RecoverLocked(stateDir)
	if err == nil || strings.Count(err.Error(), "left ") < 4 {
		t.Fatalf("recovery = %v; want every entry that is not a screenshot file refused and reported", err)
	}
	for _, kept := range []string{outside, wrongName, target} {
		if _, statErr := os.Stat(kept); statErr != nil {
			t.Errorf("%s was removed: %v", kept, statErr)
		}
	}
	if _, statErr := os.Lstat(link); statErr != nil {
		t.Errorf("the symlink was removed: %v", statErr)
	}
	after := journalPhase(t, stateDir)
	if after.Phase == "cleaned" || len(after.ScreenshotFiles) != 5 {
		t.Fatalf("journal phase %q with %d screenshot entries; want it kept unclean with all five", after.Phase, len(after.ScreenshotFiles))
	}
}
