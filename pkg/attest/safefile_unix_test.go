//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"os"
	"path/filepath"
	"testing"
)

// A filesystem that cannot flush a directory (procfs answers EINVAL) does not
// make a save fail after the file was renamed into place.
func TestSyncDirectoryToleratesFilesystemsThatCannotSyncDirectories(t *testing.T) {
	d, err := os.Open("/proc/self")
	if err != nil {
		t.Skip("no /proc")
	}
	defer d.Close()
	if err := d.Sync(); err == nil {
		t.Skip("this kernel can sync /proc directories")
	}
	if err := syncDirectory("/proc/self"); err != nil {
		t.Fatalf("syncDirectory on a filesystem that cannot sync directories = %v, want nil", err)
	}
	if err := syncDirectory(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("syncDirectory of a missing directory succeeded")
	}
}
