//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

// A real SIGTERM cancels the run and is named.
func TestInterruptContextNamesTheSignal(t *testing.T) {
	ctx, stop, interrupted := interruptContext(context.Background())
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not cancel the run")
	}
	got := interrupted()
	if got == nil || got.Signal != "SIGTERM" {
		t.Fatalf("interrupted = %+v", got)
	}
}
