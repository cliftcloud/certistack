//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/cliftcloud/certistack/internal/process"
)

// A QEMU process's PID and start time name it only within the boot they were
// read in. A journal of a run that was cut off by a reboot names a process by
// both, and another process of the later boot can have both: recovery must not
// signal it.
func TestRecoveryDoesNotSignalAProcessOfALaterBootThatHasTheRecordedPIDAndStartTime(t *testing.T) {
	vmRecoveryPVE(t, "")
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	identity, err := process.ProcessIdentity(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	// The record is of the run's QEMU in a boot that has since ended.
	identity.BootID = "00000000-0000-0000-0000-00000000dead"
	stateDir, overlay, consumer := depsJournal(t, identity, false)
	_ = consumer.Close()

	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery = %v, want the earlier boot's process taken as gone", err)
	}
	if !runs(child.Process.Pid) {
		t.Fatal("recovery signaled a process of the later boot that has the recorded PID and start time")
	}
	if _, statErr := os.Stat(overlay); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("overlay kept for a process that is gone: %v", statErr)
	}
}

// The control: the same record made in this boot is the run's QEMU, and is
// stopped.
func TestRecoveryStopsARecordedQEMUOfThisBoot(t *testing.T) {
	vmRecoveryPVE(t, "")
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	identity, err := process.ProcessIdentity(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if identity.BootID, err = process.CurrentBootID(); err != nil {
		t.Skipf("no boot identity on this host: %v", err)
	}
	stateDir, overlay, consumer := depsJournal(t, identity, false)
	_ = consumer.Close()

	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery = %v", err)
	}
	if runs(child.Process.Pid) {
		t.Fatal("recovery left the recorded QEMU of this boot running")
	}
	if _, statErr := os.Stat(overlay); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("overlay kept after its QEMU was stopped: %v", statErr)
	}
}
