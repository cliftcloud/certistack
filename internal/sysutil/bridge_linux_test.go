//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeIfupdownLock is a lock file and a /proc/locks naming it when held.
func fakeIfupdownLock(t *testing.T) (hold func(bool)) {
	t.Helper()
	dir := t.TempDir()
	lockFile := filepath.Join(dir, ".lock")
	if err := os.WriteFile(lockFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	locks := filepath.Join(dir, "locks")
	var st syscall.Stat_t
	if err := syscall.Stat(lockFile, &st); err != nil {
		t.Fatal(err)
	}
	dev := uint64(st.Dev)
	major := (dev >> 8 & 0xfff) | (dev >> 32 & ^uint64(0xfff))
	minor := (dev & 0xff) | (dev >> 12 & ^uint64(0xff))
	held := fmt.Sprintf("1: FLOCK  ADVISORY  WRITE 2425792 %02x:%02x:%d 0 EOF\n", major, minor, st.Ino)
	other := "2: POSIX  ADVISORY  WRITE 900 00:1a:77 0 EOF\n"
	origFile, origLocks := ifupdownLockFile, procLocks
	ifupdownLockFile, procLocks = lockFile, locks
	t.Cleanup(func() { ifupdownLockFile, procLocks = origFile, origLocks })
	return func(on bool) {
		contents := other
		if on {
			contents += held
		}
		if err := os.WriteFile(locks, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// On -02: ifreload runs as "python3" (a Python script through env),
// so its lock tells when ifupdown2 is done, not its process name. The
// bridge was up 452 ms before ifreload let go of it.
func TestSettleBridgeWaitsForIfupdown2sLock(t *testing.T) {
	sys, _, _ := fakeNodeRoots(t)
	hold := fakeIfupdownLock(t)
	hold(true)
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.MkdirAll(filepath.Join(sys, "csVnet1"), 0o755)
		time.Sleep(30 * time.Millisecond)
		hold(false)
	}()
	start := time.Now()
	if err := SettleBridge(context.Background(), "csVnet1", true, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatalf("settled after %s, while ifupdown2 still held its lock", time.Since(start))
	}
	hold(true)
	err := SettleBridge(context.Background(), "csVnet1", true, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "bridge csVnet1 is present, and ifupdown2 is still running") {
		t.Fatalf("SettleBridge with the lock held = %v", err)
	}
}

// Without ifupdown2's lock file, an ifreload is found by its command line,
// also when an interpreter runs it.
func TestIfupdownRunningFindsTheScriptByCommandLine(t *testing.T) {
	_, proc, _ := fakeNodeRoots(t)
	origFile := ifupdownLockFile
	ifupdownLockFile = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { ifupdownLockFile = origFile })
	write := func(pid, cmdline string) {
		dir := filepath.Join(proc, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("1", "/sbin/init\x00")
	write("400", "python3\x00/usr/bin/other-tool\x00ifreload\x00")
	if ifupdownRunning() {
		t.Fatal("found ifupdown2 in an unrelated command line")
	}
	write("812", "python3\x00/usr/sbin/ifreload\x00-a\x00")
	if !ifupdownRunning() {
		t.Fatal("did not find python3 /usr/sbin/ifreload")
	}
}

// A lookup that fails is not an observation. A bridge path that cannot be
// stat-ed for another reason than "not there", a process list that cannot be
// read and a command line that cannot be read each leave the answer unknown: the
// settle does not succeed on them, and says so when it gives up.
func TestSettleBridgeNeverSettlesOnWhatItCouldNotRead(t *testing.T) {
	sys, proc, _ := fakeNodeRoots(t)
	origFile := ifupdownLockFile
	ifupdownLockFile = filepath.Join(t.TempDir(), "absent") // no lock file: the process list decides
	t.Cleanup(func() { ifupdownLockFile = origFile })

	t.Run("definitely absent settles", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(proc, "1-placeholder"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := SettleBridge(context.Background(), "csVnet1", false, time.Second); err != nil {
			t.Fatalf("a bridge that is not there, with the process list readable: %v", err)
		}
	})

	t.Run("a path that cannot be inspected is not absent", func(t *testing.T) {
		// A regular file where the interface directory's parent should be: stat
		// of csVnet1 beneath it fails with ENOTDIR, not ENOENT.
		blocker := filepath.Join(t.TempDir(), "net")
		if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		orig := sysClassNet
		sysClassNet = blocker
		t.Cleanup(func() { sysClassNet = orig })
		err := SettleBridge(context.Background(), "csVnet1", false, 30*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "could not be established") {
			t.Fatalf("SettleBridge = %v, want it to give up and say the bridge's state could not be read", err)
		}
	})

	t.Run("a process list that cannot be read is not idle", func(t *testing.T) {
		orig := procDir
		procDir = filepath.Join(t.TempDir(), "no-proc") // ReadDir fails
		t.Cleanup(func() { procDir = orig })
		err := SettleBridge(context.Background(), "csVnet1", false, 30*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "process list cannot be read") {
			t.Fatalf("SettleBridge = %v, want it to give up and say the process list could not be read", err)
		}
	})

	t.Run("a command line that cannot be read is not idle", func(t *testing.T) {
		dir := filepath.Join(proc, "812")
		if err := os.MkdirAll(filepath.Join(dir, "cmdline"), 0o755); err != nil { // a directory cannot be read as a file
			t.Fatal(err)
		}
		busy, unknown := ifupdownState()
		if busy || unknown == "" || !strings.Contains(unknown, "command lines cannot be read") {
			t.Fatalf("ifupdownState = %v, %q; want unknown", busy, unknown)
		}
	})
	_ = sys
}
