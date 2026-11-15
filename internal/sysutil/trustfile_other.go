//go:build !unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import "os"

// UnsafeToTrust is nil where files carry no Unix owner and mode: Windows keeps
// a file's access in its ACL, which the user's profile directory restricts.
func UnsafeToTrust(path string, info os.FileInfo, what, risk string) error {
	return nil
}
