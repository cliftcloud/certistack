// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// standInWorkerName is the name under which a copy of this test binary stands
// in for the node worker (standInWorker).
const standInWorkerName = "certistack-node"

// TestMain keeps tests that run a supervisor script from starting a real
// transient service: a lease watch they do not replace fails to start.
//
// Run as a copy named certistack-node with one argument, the test binary is the
// stand-in worker of the stop-script tests: it sleeps that many seconds and
// exits.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == standInWorkerName && len(os.Args) == 2 {
		if seconds, err := strconv.Atoi(os.Args[1]); err == nil {
			time.Sleep(time.Duration(seconds) * time.Second)
			os.Exit(0)
		}
	}
	leaseWatchLauncher = "/nonexistent/certistack-test/systemd-run"
	os.Exit(m.Run())
}

// standInWorker copies this test binary into dir as the worker's executable,
// which runs as `certistack-node SECONDS` and sleeps (TestMain). The stop script
// tells the worker by its binary, so the stand-in must be a real executable
// that keeps running under that name. A copy of /bin/sleep did that until
// Ubuntu 26.04: its sleep is uutils' multicall binary, which picks what to do
// from the name it is run under, and as certistack-node it exits at once.
func standInWorker(t *testing.T, dir string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, standInWorkerName)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
