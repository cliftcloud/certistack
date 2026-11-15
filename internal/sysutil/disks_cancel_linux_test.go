//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hangingZpool installs a zpool that starts and then hangs, as one does on a
// suspended pool, and the mount table of two ZFS datasets (/scratch and the
// cluster state directory), on two devices unless sameDevice. It returns the
// file the fake writes when it has started.
func hangingZpool(t *testing.T, sameDevice bool) string {
	t.Helper()
	work := t.TempDir()
	bin := filepath.Join(work, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(work, "zpool.started")
	script := fmt.Sprintf("#!/bin/sh\nprintf 'started\\n' > %q\nexec /bin/sleep 60\n", started)
	if err := os.WriteFile(filepath.Join(bin, "zpool"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	mountInfo := filepath.Join(work, "mountinfo")
	if err := os.WriteFile(mountInfo, []byte(strings.Join([]string{
		"25 1 0:24 / /scratch rw,relatime - zfs rpool/scratch rw,xattr",
		"26 1 0:45 / /var/lib/pve-cluster rw,relatime - zfs rpool/cluster rw,xattr",
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origDeviceOf, origMountInfoPath := deviceOf, mountInfoPath
	t.Cleanup(func() { deviceOf, mountInfoPath = origDeviceOf, origMountInfoPath })
	deviceOf = func(path string) (string, error) {
		switch path {
		case "/scratch":
			return "0:24", nil
		case ClusterStateDir:
			if sameDevice {
				return "0:24", nil
			}
			return "0:45", nil
		}
		return "", fmt.Errorf("unexpected path %q", path)
	}
	mountInfoPath = mountInfo
	return started
}

func waitStarted(t *testing.T, started string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the synthetic zpool did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type sharedResult struct {
	shared []string
	err    error
}

// The topology check ran `zpool status` under context.Background
// with its own 15-second timeout, so a caller that was cancelled waited for the
// subprocess, and a run that was interrupted at its first check could not begin
// its teardown. The reported case: a zpool that hangs, and the caller's
// context cancelled while it does.
func TestSharedDisksStopsWhenTheCallerIsCancelled(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sameDevice bool
	}{
		{"two datasets, two devices (the reporter's fixture)", false},
		// One file system: the old code turned any failure into "they share
		// it", which is an answer, not a cancellation.
		{"one dataset", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := hangingZpool(t, tc.sameDevice)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan sharedResult, 1)
			go func() {
				shared, err := SharedDisks(ctx, "/scratch", ClusterStateDir)
				done <- sharedResult{shared, err}
			}()
			waitStarted(t, started)
			cancel()
			select {
			case got := <-done:
				if !errors.Is(got.err, context.Canceled) || errors.Is(got.err, ErrDisksUnknown) || got.shared != nil {
					t.Fatalf("SharedDisks = %v, %v; want the context's error alone: a cancelled caller is not told the topology is unknown or shared", got.shared, got.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("SharedDisks was still waiting for zpool 3 s after the caller was cancelled (it returns only when the check's own 15 s timeout kills it)")
			}
		})
	}
}

func TestSharedDisksStopsAtTheCallersDeadline(t *testing.T) {
	started := hangingZpool(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan sharedResult, 1)
	go func() {
		shared, err := SharedDisks(ctx, "/scratch", ClusterStateDir)
		done <- sharedResult{shared, err}
	}()
	select {
	case got := <-done:
		if !errors.Is(got.err, context.DeadlineExceeded) || errors.Is(got.err, ErrDisksUnknown) {
			t.Fatalf("SharedDisks = %v, %v; want the caller's deadline", got.shared, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SharedDisks outlived its caller's deadline")
	}
	waitStarted(t, started)
}

// A context that has ended already starts nothing.
func TestSharedDisksWithAnEndedContextStartsNothing(t *testing.T) {
	started := hangingZpool(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if shared, err := SharedDisks(ctx, "/scratch", ClusterStateDir); !errors.Is(err, context.Canceled) || shared != nil {
		t.Fatalf("SharedDisks = %v, %v; want the context's error", shared, err)
	}
	if _, err := os.Stat(started); err == nil {
		t.Fatal("zpool was started for a caller that had already been cancelled")
	}
}

// The check's own timeout is not the caller's: a pool that does not answer in
// time is unknown, as it always was, and never a cancellation the caller did
// not ask for.
func TestSharedDisksOwnTimeoutIsStillUnknown(t *testing.T) {
	hangingZpool(t, false)
	orig := zpoolStatusTimeout
	zpoolStatusTimeout = 300 * time.Millisecond
	t.Cleanup(func() { zpoolStatusTimeout = orig })
	shared, err := SharedDisks(context.Background(), "/scratch", ClusterStateDir)
	if !errors.Is(err, ErrDisksUnknown) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || shared != nil {
		t.Fatalf("SharedDisks = %v, %v; want ErrDisksUnknown alone", shared, err)
	}
}
