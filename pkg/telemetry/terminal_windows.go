// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build windows

package telemetry

import (
	"os"

	"golang.org/x/sys/windows"
)

// IsTerminal reports whether f is a console. A pipe, a file and NUL are not.
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}
