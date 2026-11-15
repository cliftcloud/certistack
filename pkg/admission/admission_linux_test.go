//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeCPUSamples makes readCPUSample return lines in turn, the last one
// from then on.
func fakeCPUSamples(t *testing.T, lines ...string) {
	t.Helper()
	read, interval := readCPUSample, ioWaitSampleInterval
	t.Cleanup(func() { readCPUSample, ioWaitSampleInterval = read, interval })
	ioWaitSampleInterval = time.Millisecond
	next := 0
	readCPUSample = func() (cpuSample, error) {
		line := lines[min(next, len(lines)-1)]
		next++
		return parseCPULine(line)
	}
}

// Through the real controller: a 20% interval on a host whose user time is
// guest time is denied at a 15% limit, and counters that keep going backwards
// defer admission as unknown load, never admit it.
func TestAdmissionDeniesWhatItCannotMeasureAsLow(t *testing.T) {
	c := New(Config{MaxHostRAMPercent: 100, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 1, MaxDeferRetries: 1})

	fakeCPUSamples(t, "cpu 100 0 0 100 0 0 0 0 100 0", "cpu 800 0 0 200 200 0 0 0 800 0")
	if err := c.Check(context.Background()); !errors.Is(err, ErrAdmissionDenied) {
		t.Fatalf("20%% I/O wait with guest time at a 15%% limit: %v, want denied", err)
	}

	fakeCPUSamples(t, "cpu 100 0 0 100 100 0 0 0 0 0", "cpu 200 0 0 200 50 0 0 0 0 0", "cpu 300 0 0 300 40 0 0 0 0 0", "cpu 400 0 0 400 30 0 0 0 0 0")
	err := c.Check(context.Background())
	if !errors.Is(err, ErrAdmissionDenied) || !errors.Is(err, ErrIOWaitUnknown) {
		t.Fatalf("iowait going backwards: %v, want a deferral for unknown I/O wait", err)
	}

	// One unusable interval is sampled again, and the next one counts.
	fakeCPUSamples(t, "cpu 100 0 0 100 100 0 0 0 0 0", "cpu 200 0 0 200 50 0 0 0 0 0", "cpu 300 0 0 300 50 0 0 0 0 0")
	if err := c.Check(context.Background()); err != nil {
		t.Fatalf("a usable second interval (0%% I/O wait): %v, want admitted", err)
	}
}
