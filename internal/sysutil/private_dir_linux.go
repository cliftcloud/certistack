//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"fmt"
	"os"
	"syscall"
)

// writableDirectory reports whether this process can create entries in dir.
func writableDirectory(dir string) error {
	if err := syscall.Access(dir, 0x3); err != nil { // W_OK|X_OK
		return fmt.Errorf("%s is not writable by this user: %w", dir, err)
	}
	return nil
}

func validatePrivateDirectoryOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not inspect private directory ownership")
	}
	if uint32(stat.Uid) != uint32(os.Geteuid()) {
		return fmt.Errorf("private directory must be owned by the current user")
	}
	return nil
}
