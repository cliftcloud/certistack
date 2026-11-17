//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import "os"

func openKeyfileSource(source string) (*os.File, error) {
	return os.Open(source)
}
