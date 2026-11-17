// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build linux

package telemetry

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Opening a named pipe waits for a writer; a state file that is one must be
// read as corrupt at once, not hang the command that looked at it.
func TestAStateFileThatIsANamedPipeIsCorruptAndDoesNotBlock(t *testing.T) {
	path := statePath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("no named pipes here: %v", err)
	}
	done := make(chan StateStatus, 1)
	go func() {
		_, status := ReadState(path)
		done <- status
	}()
	select {
	case status := <-done:
		if status != StateCorrupt {
			t.Fatalf("status = %v, want StateCorrupt", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadState blocked on a named pipe")
	}
}
