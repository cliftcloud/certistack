//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import "errors"

// FilesystemFreeBytes is not measured off Linux, where sandboxes never run.
func FilesystemFreeBytes(string) (int64, error) {
	return 0, errors.New("free space is measured only on Linux nodes")
}
