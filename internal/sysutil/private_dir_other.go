//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import "os"

func validatePrivateDirectoryOwner(_ os.FileInfo) error {
	return nil
}

func writableDirectory(string) error { return nil }
