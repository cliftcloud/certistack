//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"syscall"
)

// openWithoutBlocking opens path for reading without waiting: opening a FIFO
// for reading blocks until a writer appears, which a plain os.Open does before
// the caller can look at what it opened.
func openWithoutBlocking(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
