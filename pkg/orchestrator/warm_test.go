// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Test mode reads what udev probes first: the head, the GPT backup at the
// tail, and the start of each partition, and nothing else of the disk.
func TestWarmDiskLabelsReadsTheHeadTailAndPartitionStarts(t *testing.T) {
	dir := t.TempDir()
	device := filepath.Join(dir, "loop7")
	const size = 64 << 20
	if err := os.WriteFile(device, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	sys := filepath.Join(dir, "sys")
	for name, start := range map[string]string{"loop7p1": "2048\n", "loop7p2": "81920\n"} { // 1 MiB and 40 MiB
		if err := os.MkdirAll(filepath.Join(sys, "loop7", name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sys, "loop7", name, "start"), []byte(start), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read, err := warmDiskLabels(context.Background(), sys, device)
	if err != nil {
		t.Fatal(err)
	}
	// 16 MiB head, 1 MiB tail, 1 MiB at each partition start (the first
	// inside the head, read again from the cache).
	if want := int64(16<<20 + 1<<20 + 2<<20); read != want {
		t.Fatalf("read %d bytes, want %d", read, want)
	}
	if read >= size/2 {
		t.Fatalf("read %d of %d bytes: that is a scan, not a warm-up", read, size)
	}
}

// A disk smaller than the head is read once, whole.
func TestWarmDiskLabelsOfASmallDisk(t *testing.T) {
	device := filepath.Join(t.TempDir(), "loop8")
	if err := os.WriteFile(device, make([]byte, 3<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := warmDiskLabels(context.Background(), t.TempDir(), device)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(3<<20 + 1<<20); read != want { // whole disk, then its last MiB
		t.Fatalf("read %d, want %d", read, want)
	}
}
