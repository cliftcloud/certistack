// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build darwin || freebsd || netbsd || openbsd

package telemetry

import (
	"os"

	"golang.org/x/sys/unix"
)

// IsTerminal reports whether f is a terminal. A pipe, a file and /dev/null
// are not, so a script, a cron job or a service never reaches the question.
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	return err == nil
}
