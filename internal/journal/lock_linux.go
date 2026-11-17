//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

import (
	"fmt"
	"os"
	"syscall"
)

// Lock acquires a host-wide lock via /run/certistack.lock to prevent concurrent executions.
func Lock() (*os.File, error) {
	return openLock("/run/certistack.lock")
}

func openLock(lockPath string) (*os.File, error) {
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("open host lock %s: %w", lockPath, err)
	}

	f := os.NewFile(uintptr(fd), lockPath)
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", LockHeldMessage, err)
	}
	return f, nil
}
