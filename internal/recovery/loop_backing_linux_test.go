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

// A run journals a loop device only right after proxmox-backup-client map
// attached it, on the map's FUSE file in /run/pbs-loopdev. A journal entry whose
// backing is any other file (an administrator's disk image, a snap) cannot be a
// loop the run made, yet recovery detached it whenever the device still backed
// that file, and stopped what the host assembled on its partitions first. A
// corrupt or hand-edited journal thereby detached another tool's loop. Such a
// loop is now left attached and reported, and the journal is kept.
func TestRecoveryDetachesNoLoopOutsideTheMapRunDirectory(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	h := newLabHost(t, root)
	outside := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(outside, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	h.maps.add("loop2", filepath.Dir(outside), "disk.img", time.Time{})
	log := installLabTools(t, h.maps.sysBlock, false)
	path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: killedLoop, Backing: outside}})

	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "left "+killedLoop+" attached") || !strings.Contains(err.Error(), "delete its entry in loops of the journal") {
		t.Errorf("recovery = %v; want the loop left attached, with the next step", err)
	}
	if calls := callsIn(log); calls != "" {
		t.Fatalf("calls %q; want the loop on a file outside the map run directory left attached", calls)
	}
	if err == nil || phaseOf(t, path) == "cleaned" {
		t.Fatalf("recovery = %v, phase %q; want the loop reported and the journal kept", err, phaseOf(t, path))
	}
}
