//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// residentPages counts f's pages in the page cache.
func residentPages(t *testing.T, f *os.File, size int) int {
	t.Helper()
	data, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(data)
	vec := make([]byte, (size+os.Getpagesize()-1)/os.Getpagesize())
	if _, _, errno := unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&data[0])), uintptr(size), uintptr(unsafe.Pointer(&vec[0]))); errno != 0 {
		t.Fatal(errno)
	}
	resident := 0
	for _, v := range vec {
		resident += int(v & 1)
	}
	return resident
}

// The scan leaves none of what it read in the page cache of the file it
// read, where a plain read leaves it all.
func TestScanLeavesNoPagesCached(t *testing.T) {
	const size = 16 << 20
	path := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xa5}, size), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil { // dirty pages can't be dropped
		t.Fatal(err)
	}

	if _, err := f.ReadAt(make([]byte, size), 0); err != nil {
		t.Fatal(err)
	}
	dropDevicePages(f, 0, size)
	if residentPages(t, f, size) > 0 {
		t.Skip("this file system keeps its pages (tmpfs?); nothing to measure")
	}

	if _, _, err := hashMappedImage(context.Background(), f, nil); err != nil {
		t.Fatal(err)
	}
	if n := residentPages(t, f, size); n > 0 {
		t.Fatalf("%d of %d pages still cached after the scan", n, size/os.Getpagesize())
	}
}
