//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"strings"
	"testing"
)

// A worker's result is bounded at maxWorkerJSON, and that holds a failed fleet:
// a test cluster's failure reports reach 5 MB for 8 failing VMs (about 0.5 MB
// of screenshot each), so 60 failing VMs are 30 MB. A result past the bound is
// an error that says so. limitedBuffer must not embed a bytes.Buffer: its
// ReadFrom is what os/exec's copy uses, and it would skip the limit.
func TestWorkerResultBoundHoldsAFailedFleetAndStillBounds(t *testing.T) {
	if maxWorkerJSON < 64<<20 {
		t.Fatalf("maxWorkerJSON = %d, want at least 64 MiB", maxWorkerJSON)
	}
	out, err := runCommand(context.Background(), "/usr/bin/head", []string{"-c", "40000000", "/dev/zero"}, nil)
	if err != nil || len(out) != 40000000 {
		t.Fatalf("a 40 MB result: %d bytes, %v", len(out), err)
	}
	out, err = runCommand(context.Background(), "/usr/bin/head", []string{"-c", "70000000", "/dev/zero"}, nil)
	if err == nil || !strings.Contains(err.Error(), "output exceeded 67108864 bytes") {
		t.Logf("got %d bytes", len(out))
		t.Fatalf("a 70 MB result: %v", err)
	}
}
