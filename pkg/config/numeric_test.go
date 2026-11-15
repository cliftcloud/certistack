// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// loadBoth loads p's YAML through the controller and the worker loaders.
func loadBoth(t *testing.T, p *Plan) (controllerErr, workerErr error) {
	t.Helper()
	data, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	_, controllerErr = LoadFromReader(bytes.NewReader(data))
	_, workerErr = LoadFromReaderForWorker(bytes.NewReader(data))
	return controllerErr, workerErr
}

// YAML's .nan, .inf and -.inf compare false with every bound, so
// they passed validation; a NaN I/O wait limit then admitted any load. Both
// loaders now refuse them, aliases included, naming the field.
func TestLoadersRefuseNonFiniteNumbers(t *testing.T) {
	nan, inf := math.NaN(), math.Inf(1)
	for _, tc := range []struct {
		field  string
		mutate func(*Plan)
	}{
		{"admission_control.max_host_iowait_percent", func(p *Plan) { p.AdmissionControl.MaxHostIOWaitPercent = nan }},
		{"admission_control.max_host_iowait_percent", func(p *Plan) { p.AdmissionControl.MaxHostIOWaitPercent = inf }},
		{"admission_control.max_host_iowait_percent", func(p *Plan) { p.AdmissionControl.MaxHostIOWaitPercent = -inf }},
		{"admission_control.max_host_ram_percent", func(p *Plan) { p.AdmissionControl.MaxHostRAMPercent = nan }},
		{"compliance.rto_target_seconds", func(p *Plan) { p.Compliance.RTOTargetSeconds = nan }},
		{"compliance.rto_target_seconds", func(p *Plan) { p.Compliance.RTOTargetSeconds = inf }},
		{"compliance.rto_target_seconds", func(p *Plan) { p.Compliance.RTOTargetSeconds = -inf }},
		{"admission_control.max_host_io_wait_percent", func(p *Plan) { p.AdmissionControl.MaxHostIOWaitPercentAlt = nan }},
		{"admission.max_host_io_wait_percent", func(p *Plan) { p.Admission.MaxHostIOWaitPercentAlt = nan }},
		{"admission.max_host_ram_percent", func(p *Plan) { p.Admission.MaxHostRAMPercent = nan }},
	} {
		p := validPlan()
		tc.mutate(p)
		controllerErr, workerErr := loadBoth(t, p)
		for loader, err := range map[string]error{"controller": controllerErr, "worker": workerErr} {
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Errorf("%s loader, %s: err %v, want a %s error", loader, tc.field, err, tc.field)
			}
		}
	}
	// Finite values still load.
	p := validPlan()
	p.Compliance.RTOTargetSeconds = 900
	if controllerErr, workerErr := loadBoth(t, p); controllerErr != nil || workerErr != nil {
		t.Fatalf("finite plan: %v / %v", controllerErr, workerErr)
	}
}

// A count of seconds above about 292 years overflows time.Duration
// into a negative wait that ends at once. Every duration is bounded at seven
// days in both loaders.
func TestLoadersBoundEveryDuration(t *testing.T) {
	const overflowing = 9223372037
	for _, tc := range []struct {
		field  string
		mutate func(*Plan, int)
	}{
		{"admission_control.defer_retry_interval_sec", func(p *Plan, n int) { p.AdmissionControl.DeferRetryIntervalSec = n }},
		{"tiers[0].startup_grace_period_sec", func(p *Plan, n int) { p.Tiers[0].StartupGracePeriodSec = n }},
		{"tiers[0].boot_timeout_sec", func(p *Plan, n int) { p.Tiers[0].BootTimeoutSec = n }},
		{"tiers[0].soak_time_sec", func(p *Plan, n int) { p.Tiers[0].SoakTimeSec = n }},
		{"tiers[0].vms[0].probes[0].timeout_sec", func(p *Plan, n int) { p.Tiers[0].VMs[0].Probes[0].TimeoutSec = n }},
	} {
		for _, n := range []int{overflowing, MaxDurationSec + 1} {
			p := validPlan()
			tc.mutate(p, n)
			controllerErr, workerErr := loadBoth(t, p)
			for loader, err := range map[string]error{"controller": controllerErr, "worker": workerErr} {
				if err == nil || !strings.Contains(err.Error(), tc.field) {
					t.Errorf("%s loader, %s = %d: err %v", loader, tc.field, n, err)
				}
			}
		}
		p := validPlan()
		tc.mutate(p, MaxDurationSec)
		if controllerErr, workerErr := loadBoth(t, p); controllerErr != nil || workerErr != nil {
			t.Errorf("%s = %d (7 days): %v / %v", tc.field, MaxDurationSec, controllerErr, workerErr)
		}
	}
	p := validPlan()
	p.AdmissionControl.MaxDeferRetries = MaxDeferRetries + 1
	if !hasFieldError(Validate(p), "admission_control.max_defer_retries") {
		t.Error("max_defer_retries above its bound was accepted")
	}
}

// Loading a plan file reads no more than the size limit; the old
// loader read the whole file first. A 64 MiB file is refused after about
// the limit's worth of allocation, not the file's.
func TestLoadFromFileReadsNoMoreThanTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.yaml")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	file.Close()
	for name, load := range map[string]func(string) (*Plan, error){"controller": LoadFromFile, "worker": LoadFromFileForWorker} {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := load(path)
		runtime.ReadMemStats(&after)
		if err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
			t.Fatalf("%s: err %v, want the size limit", name, err)
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 48<<20 {
			t.Errorf("%s: allocated %d MiB to refuse a 64 MiB file", name, allocated>>20)
		}
	}
}
