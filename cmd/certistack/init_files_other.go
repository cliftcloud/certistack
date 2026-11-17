//go:build !unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import "os"

// openWithoutBlocking opens path for reading. Off Unix there are no FIFOs in
// a plan directory to wait for.
func openWithoutBlocking(path string) (*os.File, error) {
	return os.Open(path)
}
