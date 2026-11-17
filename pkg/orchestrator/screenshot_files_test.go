// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// The screenshot files of a capture are in the journal before they exist, are
// removed at teardown if nobody removed them earlier, and leave the journal
// when they are gone.
func TestScreenshotFilesAreJournaledBeforeTheyExistAndRemovedAtTeardown(t *testing.T) {
	scratch, stateDir := t.TempDir(), t.TempDir()
	o := New(networkOnlyPlan(), Options{ScratchDir: scratch, StateDir: stateDir}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: "http://127.0.0.1:1"}))
	frame := filepath.Join(scratch, "certistack-failure-vm9100-1790000000-0123abcd.ppm")
	image := filepath.Join(scratch, "certistack-failure-vm9100-1790000000-0123abcd.png")

	if err := o.registerScreenshotFiles(frame, image); err != nil {
		t.Fatal(err)
	}
	recorded, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil || len(recorded.ScreenshotFiles) != 2 {
		t.Fatalf("journal after registering: %+v, %v; want both names recorded before either file exists", recorded.ScreenshotFiles, err)
	}
	// QEMU writes the frame, the capture writes the image; the run then stops.
	for _, path := range []string{frame, image} {
		if err := os.WriteFile(path, []byte("console"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if failures := o.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures: %v", failures)
	}
	for _, path := range []string{frame, image} {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s survived teardown", path)
		}
	}
	after, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil || len(after.ScreenshotFiles) != 0 {
		t.Fatalf("journal after teardown: %+v, %v; want no screenshot files", after.ScreenshotFiles, err)
	}
}

// A capture whose files cannot be journaled is not taken: the registration says
// so, and records and removes nothing.
func TestScreenshotFilesAreNotCapturedWhenTheJournalCannotRecordThem(t *testing.T) {
	scratch, stateDir := t.TempDir(), t.TempDir()
	o := New(networkOnlyPlan(), Options{ScratchDir: scratch, StateDir: stateDir}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: "http://127.0.0.1:1"}))
	if err := os.Mkdir(filepath.Join(stateDir, "active.json"), 0o700); err != nil { // the journal cannot be replaced
		t.Fatal(err)
	}
	frame := filepath.Join(scratch, "certistack-failure-vm9100-1790000000-0123abcd.ppm")
	if err := o.registerScreenshotFiles(frame); err == nil {
		t.Fatal("registration succeeded although the journal could not be written")
	}
	if len(o.record.ScreenshotFiles) != 0 {
		t.Fatalf("the failed registration left %v in the record", o.record.ScreenshotFiles)
	}
}
