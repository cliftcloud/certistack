// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The test-mode label warm-up read a map with no way to stop, so a read waiting
// on PBS held a cancelled run too. A FIFO with no writer stands in for that
// read.
func TestWarmDiskLabelsStopsWhenCancelled(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "loop9")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := warmDiskLabels(ctx, t.TempDir(), fifo)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("warm-up = %v after %v, want the deadline at once", err, time.Since(start))
	}
	// Release the warm-up still waiting to open the FIFO (without waiting
	// for it, should it not be there).
	if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
		_ = f.Close()
	}
}
