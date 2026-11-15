//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO named like a plan beside the output held init for good: it
// was opened for reading, which waits for a writer, before anything looked at
// what it was. It is now opened without waiting and skipped, and the plans
// beside it are still read (a symbolic link to one included).
func TestSiblingFIFOAndDevicesDoNotHoldInit(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "00-block.yaml"), 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(dir, "01-zero.yml")); err != nil {
		t.Fatal(err)
	}
	const plan = "network:\n  zone_id: csZone1\ntiers:\n  - vms:\n      - vmid: 9100\n"
	if err := os.WriteFile(filepath.Join(dir, "10-real.yaml"), []byte(plan), 0o644); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "elsewhere.yaml"), []byte("tiers:\n  - vms:\n      - vmid: 9300\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "elsewhere.yaml"), filepath.Join(dir, "20-link.yaml")); err != nil {
		t.Fatal(err)
	}

	type answer struct {
		vmids []int
		err   error
	}
	done := make(chan answer, 1)
	go func() {
		vmids, _, _, err := siblingPlanIDs(context.Background(), filepath.Join(dir, "new.yaml"))
		done <- answer{vmids, err}
	}()
	select {
	case got := <-done:
		if got.err != nil || fmt.Sprint(got.vmids) != "[9100 9300]" {
			t.Fatalf("reserved %v (%v), want the plan and the linked plan, neither the FIFO nor the device", got.vmids, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the scan is waiting for a writer to a FIFO")
	}
}
