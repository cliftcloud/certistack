//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import "errors"

// IsMountPoint cannot read a mount table off Linux, where no PVE node runs.
func IsMountPoint(path string) (bool, error) {
	return false, errors.New("mount points can be read only on Linux")
}
