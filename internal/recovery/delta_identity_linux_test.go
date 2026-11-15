//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

// Recovery removed every journaled overlay path, so a file another
// tool had put at one after the run's creator refused it was unlinked and
// counted as recovered. A path whose journal entry has an identity is removed
// only while it is still that file; a path without one (a journal from an
// earlier version, or a staging file named with the run's token) is removed by
// path as before.
func TestRecoveryRemovesAnOverlayOnlyWhileItIsTheFileTheRunCreated(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ours := write("ours.qcow2", "the run's overlay")
	replaced := write("replaced.qcow2", "the run's overlay")
	symlinked := filepath.Join(dir, "symlinked.qcow2")
	staging := write("certistack-delta-vm9100-scsi0-1-0.qcow2.part-0123456789abcdef0123456789abcdef", "partial")
	legacy := write("certistack-delta-vm9100-scsi1-1-0.qcow2", "an earlier version's journal's overlay")
	absent := filepath.Join(dir, "absent.qcow2")
	foreignTarget := filepath.Join(t.TempDir(), "foreign")
	if err := os.WriteFile(foreignTarget, []byte("foreign target"), 0o644); err != nil {
		t.Fatal(err)
	}

	record := journal.Record{RunID: "run-identity", Phase: "running", UpdatedAt: time.Now().UTC()}
	identify := func(path string) journal.FileIdentity {
		id, err := sysutil.FileIdentityOf(path)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	record.SetDeltaFile(ours, identify(ours))
	record.SetDeltaFile(replaced, identify(replaced))
	record.SetDeltaFile(symlinked, identify(replaced)) // the identity of another inode
	record.SetDeltaFile(absent, identify(ours))
	record.AddDeltaFile(staging)
	record.AddDeltaFile(legacy)

	// A file that is not the run's replaces one, and a symlink stands at another.
	// The replacement is written beside the path and renamed over it, so it
	// never gets the run's freed inode back: with that inode and a birth time
	// from the same coarse tick (ext4 on a 6.8 kernel) no identity of path,
	// inode and birth time could tell it from the run's file.
	replacement := write("replacement.tmp", "foreign replacement")
	if err := os.Chmod(replacement, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, replaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreignTarget, symlinked); err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	err := RecoverLocked(stateDir)
	if err == nil {
		t.Fatal("recovery reported clean although two paths hold files the run did not create")
	}
	for _, left := range []string{replaced, symlinked} {
		if !strings.Contains(err.Error(), "left "+left+" in place: it is not the file the interrupted run created there") {
			t.Errorf("recovery = %v, want it to report %s left in place", err, left)
		}
	}
	for path, want := range map[string]string{replaced: "foreign replacement", foreignTarget: "foreign target"} {
		if data, readErr := os.ReadFile(path); readErr != nil || string(data) != want {
			t.Errorf("%s = %q, %v; want it untouched", path, data, readErr)
		}
	}
	if _, statErr := os.Lstat(symlinked); statErr != nil {
		t.Errorf("the symlink was removed: %v", statErr)
	}
	for _, gone := range []string{ours, staging, legacy} {
		if _, statErr := os.Lstat(gone); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s survived recovery: %v", gone, statErr)
		}
	}
	after, loadErr := journal.Load(filepath.Join(stateDir, "active.json"))
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if after.Phase != "cleanup_failed" || len(after.DeltaIdentities) != 4 {
		t.Fatalf("journal after recovery = phase %q, identities %v; want cleanup_failed with every identity kept for the retry", after.Phase, after.DeltaIdentities)
	}
}

// The control: with nothing foreign at any path, recovery removes them all and
// cleans the journal.
func TestRecoveryCleansAJournalWhoseOverlaysAreAllTheRuns(t *testing.T) {
	dir := t.TempDir()
	ours := filepath.Join(dir, "ours.qcow2")
	legacy := filepath.Join(dir, "certistack-delta-vm9100-scsi1-1-0.qcow2")
	for _, path := range []string{ours, legacy} {
		if err := os.WriteFile(path, []byte("overlay"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	identity, err := sysutil.FileIdentityOf(ours)
	if err != nil {
		t.Fatal(err)
	}
	record := journal.Record{RunID: "run-identity", Phase: "running", UpdatedAt: time.Now().UTC()}
	record.SetDeltaFile(ours, identity)
	record.AddDeltaFile(legacy)
	stateDir := t.TempDir()
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ours, legacy} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s survived recovery: %v", path, statErr)
		}
	}
	if after, loadErr := journal.Load(filepath.Join(stateDir, "active.json")); loadErr != nil || after.Phase != "cleaned" {
		t.Fatalf("journal after recovery = %+v, %v; want cleaned", after, loadErr)
	}
}
