//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func readRAMUsagePercent() (float64, error) {
	memTotal, memAvailable, err := readRAMCapacityMB()
	if err != nil {
		return 0, err
	}
	return ((memTotal - memAvailable) / memTotal) * 100.0, nil
}

// readRAMCapacityMB returns host memory totals in MiB. Keeping this separate
// from the utilization percentage lets admission reserve future recovery VM
// memory before it starts allocating sandbox processes.
func readRAMCapacityMB() (totalMB, availableMB float64, err error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	var memTotal, memAvailable float64
	var foundTotal, foundAvail bool

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, err := strconv.ParseFloat(parts[1], 64)
				if err == nil {
					memTotal = val
					foundTotal = true
				}
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, err := strconv.ParseFloat(parts[1], 64)
				if err == nil {
					memAvailable = val
					foundAvail = true
				}
			}
		}

		if foundTotal && foundAvail {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}

	if !foundTotal || !foundAvail || memTotal == 0 {
		return 0, 0, fmt.Errorf("could not parse MemTotal and MemAvailable from /proc/meminfo")
	}

	return memTotal / 1024, memAvailable / 1024, nil
}

// readCPUSample reads the aggregate cpu line of /proc/stat; tests replace it.
var readCPUSample = readProcStatCPU

// ioWaitSampleInterval is the interval each I/O wait sample spans.
var ioWaitSampleInterval = 500 * time.Millisecond

// ioWaitAttempts bounds how many intervals admission samples before it
// reports the I/O wait as unknown.
const ioWaitAttempts = 3

func readProcStatCPU() (cpuSample, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "cpu ") {
			return parseCPULine(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return cpuSample{}, err
	}
	return cpuSample{}, fmt.Errorf("cpu line not found in /proc/stat")
}

// readIOWaitPercent measures the host's I/O wait over one interval. An
// interval whose counters are not usable (no CPU time passed, or a counter
// went backwards, which the kernel documents for iowait) is not a
// measurement: it is sampled again, and after ioWaitAttempts intervals the
// I/O wait is reported as unknown, never as a low value.
func readIOWaitPercent(ctx context.Context) (float64, error) {
	before, err := readCPUSample()
	if err != nil {
		return 0, err
	}
	var lastErr error
	for attempt := 0; attempt < ioWaitAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(ioWaitSampleInterval):
		}
		after, err := readCPUSample()
		if err != nil {
			return 0, err
		}
		percent, err := ioWaitPercent(before, after)
		if err == nil {
			return percent, nil
		}
		lastErr = err
		before = after
	}
	return 0, fmt.Errorf("%w: %d intervals gave no usable sample (%v)", ErrIOWaitUnknown, ioWaitAttempts, lastErr)
}
