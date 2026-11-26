// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !windows

package telemetry

import "os"

// IsTerminal is false on a platform this build cannot ask: the first-run
// question is never shown, and `certistack telemetry enable` or
// CERTISTACK_TELEMETRY=1 is the way in.
func IsTerminal(*os.File) bool { return false }
