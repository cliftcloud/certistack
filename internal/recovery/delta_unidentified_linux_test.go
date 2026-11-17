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
)

// A delta_files entry without a recorded identity was unlinked by its path
// alone, whatever the path was: a corrupt or hand-edited journal naming a file
// outside the run (a configuration file, another tool's disk image, a
// directory) had it removed and the journal marked clean. Only a file named as
// CertiStack names its disposable disks, as a plain file, is removed by path;
// anything else is left and reported, and the journal is kept for the operator.
func TestRecoveryRemovesAnUnidentifiedOverlayOnlyWhenItIsNamedAsTheRunsDisks(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	foreign := write("vm-100-disk-0.qcow2")
	config := write("storage.cfg")
	emptyDir := filepath.Join(dir, "images")
	if err := os.Mkdir(emptyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkTarget := write("target.raw")
	link := filepath.Join(dir, "certistack-delta-vm9100-scsi0-1-0.qcow2")
	if err := os.Symlink(linkTarget, link); err != nil {
		t.Fatal(err)
	}
	unclean := dir + "/sub/../certistack-delta-vm9100-scsi1-1-0.qcow2"
	write("certistack-delta-vm9100-scsi1-1-0.qcow2")
	ours := []string{
		write("certistack-delta-vm9100-scsi2-1-0.qcow2"),
		write("certistack-copy-vm9100-scsi3-1-0.raw"),
		write("certistack-delta-vm9100-efidisk0-1-0.raw.part-0123456789abcdef0123456789abcdef"),
	}

	record := journal.Record{RunID: "run-unidentified", Phase: "running", UpdatedAt: time.Now().UTC()}
	for _, path := range append([]string{foreign, config, emptyDir, link, unclean, "relative/certistack-delta-vm1-a-1-0.qcow2"}, ours...) {
		record.AddDeltaFile(path)
	}
	stateDir := t.TempDir()
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}

	err := RecoverLocked(stateDir)
	if err == nil {
		t.Fatal("recovery reported clean although the journal names files that are not the run's")
	}
	for _, path := range []string{foreign, config, emptyDir, link, linkTarget, filepath.Clean(unclean)} {
		if _, statErr := os.Lstat(path); statErr != nil {
			t.Errorf("%s was removed: %v", path, statErr)
		}
	}
	for _, path := range []string{foreign, config, emptyDir, link, unclean} {
		if !strings.Contains(err.Error(), "left "+path+" in place") {
			t.Errorf("recovery = %v; want it to say %s was left in place", err, path)
		}
	}
	for _, path := range ours {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s survived recovery: %v", path, statErr)
		}
	}
	after, loadErr := journal.Load(filepath.Join(stateDir, "active.json"))
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if after.Phase != "cleanup_failed" || len(after.DeltaFiles) != len(record.DeltaFiles) {
		t.Fatalf("journal after recovery = phase %q, delta files %v; want cleanup_failed with every entry kept", after.Phase, after.DeltaFiles)
	}
}
