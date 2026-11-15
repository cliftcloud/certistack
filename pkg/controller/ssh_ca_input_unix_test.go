//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Staging a named pipe used to wait for a writer and then copy every
// byte it supplied. It now returns before a writer exists and creates no file.
func TestStagePVECARefusesANamedPipeWithoutWaiting(t *testing.T) {
	dir := t.TempDir()
	fifo, destination := filepath.Join(dir, "pve-ca.fifo"), filepath.Join(dir, "pve-ca.pem")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- stagePVECA(fifo, destination) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "named pipe") {
			t.Fatalf("stage a named pipe: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("PVE CA staging waited for a named-pipe writer")
	}
	if err := syscall.Stat(destination, &syscall.Stat_t{}); err == nil {
		t.Fatal("named-pipe CA left a staging file")
	}
}
