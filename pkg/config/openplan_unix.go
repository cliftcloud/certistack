//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"os"
	"syscall"
)

// openPlanFile opens path for reading without waiting: opening a FIFO for
// reading blocks until a writer appears, before the caller can see that it
// is not a plan file.
func openPlanFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
