// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"os"
	"testing"
)

// TestMain keeps tests that run a supervisor script from starting a real
// transient service: a lease watch they do not replace fails to start.
func TestMain(m *testing.M) {
	leaseWatchLauncher = "/nonexistent/certistack-test/systemd-run"
	os.Exit(m.Run())
}
