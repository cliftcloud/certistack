//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openInput opens path for reading without blocking if a FIFO was put in
// place of a regular file, and without making a terminal device the process's
// controlling terminal. Unless follow is set it also refuses to follow a final
// symbolic link. The caller checks the opened file.
func openInput(path string, follow bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOCTTY
	if !follow {
		flags |= unix.O_NOFOLLOW
	}
	var fd int
	var err error
	for {
		if fd, err = unix.Open(path, flags, 0); err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// createExclusive creates path for writing with perm. O_EXCL fails on any
// existing entry, a symbolic link included, so nothing is followed or reused.
// perm alone makes a file owner-only on Unix (a report is written mode 0600).
func createExclusive(path string, perm os.FileMode, _ bool) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
}

// replaceFile atomically renames from over to.
func replaceFile(from, to string) error {
	return os.Rename(from, to)
}

// syncDirectory makes a rename in dir durable across a crash or power loss.
// A filesystem that cannot flush a directory at all (some FUSE, network and
// pseudo filesystems answer EINVAL or ENOTSUP) makes the rename as durable as
// it can be, so that answer is not an error: failing there would fail every
// save on such a filesystem after the file was already in place.
func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory %s to sync it: %w", dir, err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTTY) {
			return nil
		}
		return fmt.Errorf("sync directory %s: %w", dir, err)
	}
	return d.Close()
}

// linkUnsupported reports a hard-link failure that means the filesystem
// cannot link at all (FAT, some network and FUSE mounts), not that this
// link was refused.
func linkUnsupported(err error) bool {
	return errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOSYS)
}
