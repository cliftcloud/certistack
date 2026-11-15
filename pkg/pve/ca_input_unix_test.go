//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"crypto/tls"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A named pipe given as the CA file is refused at once. The loader
// opened it and waited for a writer to end the stream.
func TestLoadCustomCARefusesANamedPipeWithoutWaiting(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pve-ca.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- loadCustomCA(&tls.Config{}, fifo) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "named pipe") {
			t.Fatalf("a named pipe as the CA file: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the loader is waiting on a named pipe for a writer")
	}
}
