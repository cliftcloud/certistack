//go:build !unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import "os"

// openPlanFile opens path for reading. Off Unix there are no FIFOs to wait
// for.
func openPlanFile(path string) (*os.File, error) {
	return os.Open(path)
}
