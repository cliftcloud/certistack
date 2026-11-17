//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"os"

	"golang.org/x/sys/unix"
)

// dropDevicePages asks the kernel to drop [off, off+n) of f from the page
// cache. It is advice: a failure leaves the pages to normal reclaim.
func dropDevicePages(f *os.File, off, n int64) {
	_ = unix.Fadvise(int(f.Fd()), off, n, unix.FADV_DONTNEED)
}

// flushCopyRange writes [off, off+n) of f to disk, waits for it, and drops
// it from the page cache.
func flushCopyRange(f *os.File, off, n int64) error {
	flags := unix.SYNC_FILE_RANGE_WAIT_BEFORE | unix.SYNC_FILE_RANGE_WRITE | unix.SYNC_FILE_RANGE_WAIT_AFTER
	if err := unix.SyncFileRange(int(f.Fd()), off, n, flags); err != nil {
		return err
	}
	dropDevicePages(f, off, n)
	return nil
}
