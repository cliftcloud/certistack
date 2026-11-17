// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestController_Check_Pass(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping admission host metric tests on non-linux")
	}
	// Generous thresholds that should always pass on a running system
	cfg := Config{
		MaxHostRAMPercent:     100.0,
		MaxHostIOWaitPercent:  100.0,
		DeferRetryIntervalSec: 1,
		MaxDeferRetries:       1,
	}

	c := New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.Check(ctx); err != nil {
		t.Fatalf("expected admission check to pass, got: %v", err)
	}
}

func TestController_Check_DeniedRAM(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping admission host metric tests on non-linux")
	}
	// 0.00001% threshold should always trigger denial if any RAM is used
	cfg := Config{
		MaxHostRAMPercent:     0.00001,
		MaxHostIOWaitPercent:  100.0,
		DeferRetryIntervalSec: 1,
		MaxDeferRetries:       1,
	}

	c := New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := c.Check(ctx)
	if err == nil {
		t.Fatal("expected admission denial, got nil")
	}
	if !errors.Is(err, ErrAdmissionDenied) {
		t.Fatalf("expected ErrAdmissionDenied, got: %v", err)
	}
}

func TestController_WaitForAdmission_Timeout(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping admission host metric tests on non-linux")
	}
	cfg := Config{
		MaxHostRAMPercent:     0.00001,
		MaxHostIOWaitPercent:  100.0,
		DeferRetryIntervalSec: 1,
		MaxDeferRetries:       1,
	}

	c := New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := c.WaitForAdmission(ctx)
	if !errors.Is(err, ErrMaxRetriesExceeded) {
		t.Fatalf("expected ErrMaxRetriesExceeded, got: %v", err)
	}
}

func TestProjectedRAMPercent(t *testing.T) {
	percent, err := projectedRAMPercent(10000, 7000, 2500)
	if err != nil {
		t.Fatal(err)
	}
	if percent < 54.999 || percent > 55.001 {
		t.Fatalf("projected RAM = %.2f%%, want 55%%", percent)
	}
	for _, values := range [][3]float64{{0, 0, 0}, {100, 101, 0}, {100, -1, 0}} {
		if _, err := projectedRAMPercent(values[0], values[1], int(values[2])); err == nil {
			t.Fatalf("projectedRAMPercent(%v) unexpectedly succeeded", values)
		}
	}
	if _, err := projectedRAMPercent(100, 50, -1); err == nil {
		t.Fatal("negative reservation unexpectedly succeeded")
	}
}

// On a 126 GiB node, 84 VMs reserve 249 GiB, 198% of the node: never
// admissible, not "not admitted now; the run would wait and retry", which
// would defer a run ten times before it fails.
func TestReservationFitsTellsNeverFromNotNow(t *testing.T) {
	err := reservationFits(128838, 254976, 80)
	if !errors.Is(err, ErrNeverAdmissible) || errors.Is(err, ErrAdmissionDenied) {
		t.Fatalf("249 GiB on a 126 GiB node = %v, want ErrNeverAdmissible and no deferral", err)
	}
	for _, want := range []string{"reserve 249 GiB", "max_host_ram_percent 80% of its 126 GiB (101 GiB)", "split the plan"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if err := reservationFits(370000, 254976, 80); err != nil {
		t.Fatalf("249 GiB on a 361 GiB node = %v, want it to fit", err)
	}
	if err := reservationFits(0, 254976, 80); err != nil {
		t.Fatalf("unknown node memory = %v, want no judgement", err)
	}
}
