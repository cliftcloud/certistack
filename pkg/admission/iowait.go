// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrIOWaitUnknown means no usable I/O wait sample could be taken. Admission
// defers on it as on a limit exceeded: unknown load is not idle load.
var ErrIOWaitUnknown = errors.New("host I/O wait could not be measured")

// cpuStates are the /proc/stat cpu columns that make up the CPUs' time, in
// order: user nice system idle iowait irq softirq steal. The guest and
// guest_nice columns that follow are left out: the kernel already counts
// guest time in user and niced guest time in nice, so adding them again
// would inflate the total and understate I/O wait on a host that runs VMs.
const cpuStates = 8

// iowaitColumn is iowait's index among cpuStates.
const iowaitColumn = 4

// cpuSample is one reading of the aggregate cpu line of /proc/stat, in
// clock ticks.
type cpuSample struct {
	states [cpuStates]uint64
}

// parseCPULine parses "cpu  user nice system idle iowait irq softirq steal
// guest guest_nice".
func parseCPULine(line string) (cpuSample, error) {
	fields := strings.Fields(line)
	if len(fields) < 1+cpuStates || fields[0] != "cpu" {
		return cpuSample{}, fmt.Errorf("unexpected cpu line format in /proc/stat")
	}
	var sample cpuSample
	for i := range sample.states {
		value, err := strconv.ParseUint(fields[1+i], 10, 64)
		if err != nil {
			return cpuSample{}, fmt.Errorf("unexpected cpu line format in /proc/stat: %w", err)
		}
		sample.states[i] = value
	}
	return sample, nil
}

// ioWaitPercent is the share of the CPUs' time between two samples spent
// waiting for I/O. An interval in which no time passed, or in which any
// counter went backwards (the kernel documents that iowait can), is not a
// measurement and is an error, never a low or negative percentage.
func ioWaitPercent(before, after cpuSample) (float64, error) {
	var total uint64
	for i := range after.states {
		if after.states[i] < before.states[i] {
			return 0, fmt.Errorf("CPU time counter %d went backwards", i+1)
		}
		delta := after.states[i] - before.states[i]
		if total+delta < total {
			return 0, errors.New("CPU time counters overflowed")
		}
		total += delta
	}
	if total == 0 {
		return 0, errors.New("no CPU time passed between the samples")
	}
	iowait := after.states[iowaitColumn] - before.states[iowaitColumn]
	return float64(iowait) / float64(total) * 100, nil
}
