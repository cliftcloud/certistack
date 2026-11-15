// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
)

func mustCPULine(t *testing.T, line string) cpuSample {
	t.Helper()
	sample, err := parseCPULine(line)
	if err != nil {
		t.Fatal(err)
	}
	return sample
}

// Guest time is already in user (and niced guest time in nice), so
// an interval of 700 user (all of it guest), 100 idle and 200 iowait ticks is
// 20% I/O wait, not 200/1700.
func TestIOWaitCountsGuestTimeOnce(t *testing.T) {
	for name, lines := range map[string][2]string{
		"no guest (control)": {"cpu 100 0 0 100 0 0 0 0 0 0", "cpu 800 0 0 200 200 0 0 0 0 0"},
		"guest":              {"cpu 100 0 0 100 0 0 0 0 100 0", "cpu 800 0 0 200 200 0 0 0 800 0"},
		"niced guest":        {"cpu 0 100 0 100 0 0 0 0 0 100", "cpu 0 800 0 200 200 0 0 0 0 800"},
		"mixed":              {"cpu 100 100 0 100 0 0 0 0 50 50", "cpu 450 450 0 200 200 0 0 0 400 400"},
	} {
		got, err := ioWaitPercent(mustCPULine(t, lines[0]), mustCPULine(t, lines[1]))
		if err != nil || math.Abs(got-20) > 1e-9 {
			t.Errorf("%s: I/O wait %v, %v; want 20%%", name, got, err)
		}
	}
}

// An interval in which a counter went backwards, or no time passed,
// is not a measurement; it is never a negative or zero percentage.
func TestIOWaitRefusesAnUnusableInterval(t *testing.T) {
	for name, lines := range map[string][2]string{
		"iowait went backwards": {"cpu 100 0 0 100 100 0 0 0 0 0", "cpu 200 0 0 200 50 0 0 0 0 0"},
		"idle went backwards":   {"cpu 100 0 0 300 100 0 0 0 0 0", "cpu 400 0 0 200 150 0 0 0 0 0"},
		"no time passed":        {"cpu 100 0 0 100 100 0 0 0 0 0", "cpu 100 0 0 100 100 0 0 0 0 0"},
	} {
		if got, err := ioWaitPercent(mustCPULine(t, lines[0]), mustCPULine(t, lines[1])); err == nil {
			t.Errorf("%s: measured %v%%, want no measurement", name, got)
		}
	}
	for _, bad := range []string{"cpu 1 2 3", "cpu a 0 0 0 0 0 0 0", "cpu0 1 1 1 1 1 1 1 1", "cpu -1 0 0 0 0 0 0 0"} {
		if _, err := parseCPULine(bad); err == nil {
			t.Errorf("parsed %q", bad)
		}
	}
}

// A Config built without plan validation cannot switch a limit off
// with NaN, or overflow its retry interval.
func TestCheckRefusesLimitsNoPlanAccepts(t *testing.T) {
	valid := Config{MaxHostRAMPercent: 100, MaxHostIOWaitPercent: 100, DeferRetryIntervalSec: 1, MaxDeferRetries: 1}
	for name, mutate := range map[string]func(*Config){
		"NaN I/O wait limit":  func(c *Config) { c.MaxHostIOWaitPercent = math.NaN() },
		"NaN RAM limit":       func(c *Config) { c.MaxHostRAMPercent = math.NaN() },
		"infinite RAM limit":  func(c *Config) { c.MaxHostRAMPercent = math.Inf(1) },
		"overflowing retries": func(c *Config) { c.DeferRetryIntervalSec = 9223372037 },
		"no retry interval":   func(c *Config) { c.DeferRetryIntervalSec = 0 },
	} {
		cfg := valid
		mutate(&cfg)
		err := New(cfg).Check(context.Background())
		if err == nil || errors.Is(err, ErrAdmissionDenied) || !strings.Contains(err.Error(), "admission") {
			t.Errorf("%s: check = %v, want a refusal of the limit itself", name, err)
		}
	}
}
