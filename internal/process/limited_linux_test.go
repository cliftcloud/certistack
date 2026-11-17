//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package process

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The PBS client's output was buffered whole, so a client that wrote
// a lot, or kept writing for its whole time limit, cost memory in proportion.
// CombinedOutputLimited keeps the first limit bytes and stops the command the
// moment it writes one more.
func TestCombinedOutputLimitedStopsACommandThatWritesPastTheLimit(t *testing.T) {
	run := func(script string, limit int) ([]byte, error, time.Duration) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := CommandContext(ctx, "sh", []string{"-c", script}, false)
		start := time.Now()
		out, err := CombinedOutputLimited(cmd, limit)
		return out, err, time.Since(start)
	}

	// Exactly the limit is accepted, in the order written, stdout and stderr together.
	out, err, _ := run(`printf 12345; printf 67890 >&2`, 10)
	if err != nil || string(out) != "1234567890" {
		t.Fatalf("output at the limit = %q, %v; want it whole and no error", out, err)
	}
	// One byte over is refused, and only the limit is kept.
	out, err, _ = run(`printf 12345; printf 678901 >&2`, 10)
	if !errors.Is(err, ErrOutputLimit) || string(out) != "1234567890" || !strings.Contains(err.Error(), "it wrote 11 bytes, over the 10") {
		t.Fatalf("output one byte over = %q, %v; want the first 10 bytes and ErrOutputLimit naming the sizes", out, err)
	}
	// Sustained output is stopped at once, not read until the command's own end:
	// this one would write for a minute.
	out, err, took := run(`while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done`, 1<<20)
	if !errors.Is(err, ErrOutputLimit) || len(out) != 1<<20 {
		t.Fatalf("sustained output = %d bytes, %v; want the first 1 MiB and ErrOutputLimit", len(out), err)
	}
	if took > 10*time.Second {
		t.Fatalf("the command ran %v after it passed the limit", took)
	}
	// A command that exits with an error keeps its output and its error.
	out, err, _ = run(`printf failed >&2; exit 3`, 100)
	if err == nil || errors.Is(err, ErrOutputLimit) || string(out) != "failed" {
		t.Fatalf("failing command = %q, %v", out, err)
	}
	// The limit must be positive.
	if _, err := CombinedOutputLimited(Command("true", nil, false), 0); err == nil {
		t.Fatal("a zero limit was accepted")
	}
}

// The child is reaped: nothing is left running once the call returns.
func TestCombinedOutputLimitedReapsTheCommandItStopped(t *testing.T) {
	cmd := CommandContext(context.Background(), "sh", []string{"-c", `while :; do printf 'yyyyyyyyyyyyyyyyyyyyyyyy'; done`}, false)
	if _, err := CombinedOutputLimited(cmd, 4096); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("err = %v", err)
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() && cmd.ProcessState.String() == "" {
		t.Fatalf("the command was not waited for: %v", cmd.ProcessState)
	}
}
