//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"os"

	"golang.org/x/sys/unix"
)

func openKeyfileSource(source string) (*os.File, error) {
	// Refuse a leaf symlink and avoid blocking if a regular file was replaced
	// by a FIFO between Lstat and open. The caller checks the opened inode.
	fd, err := unix.Open(source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), source), nil
}
