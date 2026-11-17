// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build linux || darwin || freebsd || netbsd || openbsd

package telemetry

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// stateLockSerializes is true where tryLock really excludes another holder.
const stateLockSerializes = true

// tryLock takes f's exclusive lock if nobody else holds it: held says whether
// it did, and an error that is not contention means the file system has no
// such lock.
func tryLock(f *os.File) (held bool, err error) {
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EINTR):
		return false, nil
	}
	return false, err
}

func releaseLock(f *os.File) { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }
