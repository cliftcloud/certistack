//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The copy leaves the image's zero ranges as holes, and neither the copy's
// nor the source's pages stay cached.
func TestCopyImageIsSparseAndLeavesNothingCached(t *testing.T) {
	dir := t.TempDir()
	path, image := writeImage(t, dir)
	src, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if err := src.Sync(); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(dir, "copy.raw")
	if _, _, _, err := copyImage(context.Background(), src, path, copyPath, DiskSize{}, nil); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(copyPath, &st); err != nil {
		t.Fatal(err)
	}
	if allocated := st.Blocks * 512; allocated >= int64(len(image))-(4<<20) {
		t.Errorf("copy allocates %d bytes of %d: the 8 MiB hole was written", allocated, len(image))
	}
	dst, err := os.Open(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if n := residentPages(t, dst, len(image)); n > 16 {
		t.Errorf("%d pages of the copy still cached", n)
	}
	if n := residentPages(t, src, len(image)); n > 16 {
		t.Errorf("%d pages of the source still cached", n)
	}
}
