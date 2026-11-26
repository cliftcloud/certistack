// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package process

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
)

// thisBoot is the boot the test runs in, as StopRecorded reads it.
func thisBoot(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Skipf("no boot identity on this host: %v", err)
	}
	return strings.TrimSpace(string(data))
}

// stillRunning reports whether child has not been killed: a child that was
// killed and not yet reaped is a zombie, which a signal 0 still reaches, so
// its state is read.
func stillRunning(child *exec.Cmd) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child.Process.Pid))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(stat[strings.LastIndex(string(stat), ")")+1:]))
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

// A PID and its start ticks name a process only within one boot: after a
// reboot another process can have both. A record made in another boot is of a
// process that is gone, and the process now at that PID is not signaled.
func TestStopRecordedLeavesAProcessThatCarriesAnotherBootsIdentity(t *testing.T) {
	child, identity := startDisposable(t)
	identity.BootID = "00000000-0000-0000-0000-00000000dead"
	if err := StopRecorded(identity); err != nil {
		t.Fatalf("StopRecorded of a process of an earlier boot = %v, want it taken as gone", err)
	}
	if !stillRunning(child) {
		t.Fatal("a process with the recorded PID and start ticks was signaled although the record is of another boot")
	}
}

// The control: a process recorded in this boot, with its PID and start ticks,
// is the recorded one, and is stopped.
func TestStopRecordedStopsAProcessOfThisBoot(t *testing.T) {
	child, identity := startDisposable(t)
	identity.BootID = thisBoot(t)
	if err := StopRecorded(identity); err != nil {
		t.Fatalf("StopRecorded = %v", err)
	}
	err := child.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("wait = %v, want the process killed", err)
	}
}

// A record without a boot identity is judged by PID and start ticks alone:
// it is stopped while they match, and refused when they do not.
func TestStopRecordedStillHandlesARecordWithoutABootIdentity(t *testing.T) {
	child, identity := startDisposable(t)
	if identity.BootID != "" {
		t.Fatalf("ProcessIdentity carries a boot identity %q: a legacy record would differ from a read identity", identity.BootID)
	}
	mismatched := journal.Process{PID: identity.PID, StartTicks: identity.StartTicks + "1"}
	if err := StopRecorded(mismatched); !errors.Is(err, ErrPIDReused) {
		t.Fatalf("mismatched start ticks = %v, want ErrPIDReused", err)
	}
	if !stillRunning(child) {
		t.Fatal("a process with other start ticks was signaled")
	}
	if err := StopRecorded(identity); err != nil {
		t.Fatalf("StopRecorded = %v", err)
	}
}

// A record of a boot that cannot be compared with this one, because this
// boot's identity cannot be read, is neither known gone nor known to be the
// recorded process: it is not signaled, and the error says why.
func TestStopRecordedDoesNotSignalWhenThisBootCannotBeRead(t *testing.T) {
	for name, read := range map[string]func() (string, error){
		"unreadable": func() (string, error) { return "", errors.New("permission denied") },
		"empty":      func() (string, error) { return "", errors.New("the kernel's boot identity is empty") },
	} {
		t.Run(name, func(t *testing.T) {
			child, identity := startDisposable(t)
			identity.BootID = thisBoot(t)
			real := readBootID
			readBootID = read
			t.Cleanup(func() { readBootID = real })
			err := StopRecorded(identity)
			if !errors.Is(err, ErrBootUnreadable) || errors.Is(err, ErrPIDReused) {
				t.Fatalf("StopRecorded = %v, want ErrBootUnreadable", err)
			}
			if !stillRunning(child) {
				t.Fatal("a process whose boot could not be compared was signaled")
			}
		})
	}
	t.Run("a legacy record needs no boot identity", func(t *testing.T) {
		child, identity := startDisposable(t)
		real := readBootID
		readBootID = func() (string, error) { return "", errors.New("unreadable") }
		t.Cleanup(func() { readBootID = real })
		if err := StopRecorded(identity); err != nil {
			t.Fatalf("StopRecorded of a record without a boot identity = %v, want it judged by PID and start ticks", err)
		}
		_ = child.Wait()
	})
}

func TestCurrentBootIDIsTheKernelsBootID(t *testing.T) {
	boot, err := CurrentBootID()
	if err != nil || boot != thisBoot(t) {
		t.Fatalf("CurrentBootID = %q, %v; want %q", boot, err, thisBoot(t))
	}
}
