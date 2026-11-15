//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The environment file is opened once, without waiting, and checked
// on the open descriptor: a FIFO is refused at once.
func TestEnvironmentFileFIFOIsRefusedWithoutWaiting(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo.env")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := parseEnvironmentFile(fifo, controllerEnvironmentNames, "controller")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("a FIFO: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the loader is waiting for a writer to a FIFO")
	}
}
