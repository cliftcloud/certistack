//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"path/filepath"
	"strings"
	"testing"
)

// Whatever else happens to a script on its way to the shell, one that
// reaches it altered does not start a worker. The supervisor and the lease
// watch each open with a comparison of a text systemd would change with the
// same text spelled so that it cannot: here they are run as the launcher
// would hand them over had it not escaped them, had it escaped them and not
// undone it, and had it expanded the
// specifiers "%h" and "%%".
func TestSupervisorAndWatchRefuseToStartWhenTheirLauncherAlteredThem(t *testing.T) {
	alterations := map[string]func(string) string{
		"systemd deletes the ${...} forms": func(s string) string { return systemdExpandCommand([]string{s}, systemdEnvironment)[0] },
		"every $ doubled and not undone":   systemdWord,
		"specifiers expanded":              func(s string) string { return strings.NewReplacer("%h", "pve1", "%%", "%").Replace(s) },
	}
	for name, alter := range alterations {
		t.Run("supervisor, "+name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "worker-ran")
			h := newSupervisorHarness(t, ": > "+shellQuote(marker)+"\nprintf '{\"report\":{}}'", 0)
			status, stdout, stderr := h.start(t, alter(h.supervisor(t)))()
			if status != 126 || stdout != "" || !strings.Contains(stderr, "altered by the program that started it") {
				t.Fatalf("status %d, stdout %q, stderr %q; want a refusal with status 126", status, stdout, stderr)
			}
			if exists(marker) || exists(h.pidFile) {
				t.Fatal("the worker was started by a script its launcher had altered")
			}
		})
		t.Run("lease watch, "+name, func(t *testing.T) {
			h := newSupervisorHarness(t, "", 0)
			watch := alter(h.adapt(t, leaseWatchScript(workspaceShellVariables(h.lease, h.worker, h.stateDir, h.env, h.progress, h.workspace))))
			h.setUptime(t, 1000)
			status, _, stderr := h.start(t, watch, "1000", "", "", "")()
			if status != 126 || !strings.Contains(stderr, "altered by the program that started it") {
				t.Fatalf("status %d, stderr %q; want a refusal with status 126", status, stderr)
			}
		})
	}
}
