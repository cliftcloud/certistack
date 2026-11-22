// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeHost replaces what a check reads: the node's memory (total and
// available, MiB), the share of memory in use, and the I/O wait (or an error).
func fakeHost(t *testing.T, totalMB, availableMB, ramPercent, ioWait float64, ioWaitErr error) {
	t.Helper()
	capacity, usage, wait := readRAMCapacity, readRAMUsage, readIOWait
	t.Cleanup(func() { readRAMCapacity, readRAMUsage, readIOWait = capacity, usage, wait })
	readRAMCapacity = func() (float64, float64, error) { return totalMB, availableMB, nil }
	readRAMUsage = func() (float64, error) { return ramPercent, nil }
	readIOWait = func(context.Context) (float64, error) { return ioWait, ioWaitErr }
}

// Every way a check ends leaves what it measured and decided, so the
// report can say why the run was admitted or refused.
func TestACheckRecordsWhatItMeasuredAndDecided(t *testing.T) {
	cfg := Config{MaxHostRAMPercent: 70, MaxHostIOWaitPercent: 10, DeferRetryIntervalSec: 1, MaxDeferRetries: 2}
	const total = 100_000.0
	for _, tc := range []struct {
		name      string
		available float64 // MiB free
		ram       float64 // share in use at the first reading
		ioWait    float64
		ioErr     error
		reserved  int
		decision  string
		denied    bool
		want      Evaluation // the measurements the decision leaves (Checks and Decision are checked apart)
	}{
		{name: "granted", available: 60_000, ram: 40, ioWait: 2, reserved: 20_000, decision: DecisionGranted,
			want: Evaluation{HostTotalMiB: total, HostAvailableMiB: 60_000, HostRAMPercent: 40, HostIOWaitPercent: 2, ProjectedRAMPercent: 60}},
		{name: "memory already over the limit", available: 20_000, ram: 80, ioWait: 2, reserved: 1_000, decision: DecisionDeniedRAM, denied: true,
			want: Evaluation{HostRAMPercent: 80, HostIOWaitPercent: 2, ProjectedRAMPercent: 80}},
		{name: "I/O wait over the limit", available: 60_000, ram: 40, ioWait: 25, reserved: 1_000, decision: DecisionDeniedIOWait, denied: true,
			want: Evaluation{HostRAMPercent: 40, HostIOWaitPercent: 25, ProjectedRAMPercent: 40}},
		{name: "the reservation would pass the limit", available: 60_000, ram: 40, ioWait: 2, reserved: 35_000, decision: DecisionDeniedProjectedRAM, denied: true,
			want: Evaluation{HostTotalMiB: total, HostAvailableMiB: 60_000, HostRAMPercent: 40, HostIOWaitPercent: 2, ProjectedRAMPercent: 75}},
		{name: "I/O wait that cannot be measured", available: 60_000, ram: 40, ioErr: ErrIOWaitUnknown, reserved: 1_000, decision: DecisionDeniedIOWaitUnmeasured, denied: true,
			want: Evaluation{HostRAMPercent: 40}},
		{name: "a reservation no wait can admit", available: 60_000, ram: 40, ioWait: 2, reserved: 90_000, decision: DecisionNeverAdmissible,
			want: Evaluation{HostTotalMiB: total, HostAvailableMiB: 60_000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeHost(t, total, tc.available, tc.ram, tc.ioWait, tc.ioErr)
			c := New(cfg)
			if got := c.Evaluation(); got.Checks != 0 || got.Decision != "" {
				t.Fatalf("a controller that has checked nothing reports %+v", got)
			}
			err := c.CheckWithReservedMemory(context.Background(), tc.reserved)
			switch {
			case tc.decision == DecisionGranted && err != nil:
				t.Fatalf("check = %v, want a grant", err)
			case tc.denied && !errors.Is(err, ErrAdmissionDenied):
				t.Fatalf("check = %v, want a deferrable denial", err)
			case tc.decision == DecisionNeverAdmissible && !errors.Is(err, ErrNeverAdmissible):
				t.Fatalf("check = %v, want ErrNeverAdmissible", err)
			}
			got := c.Evaluation()
			tc.want.Checks, tc.want.Decision = 1, tc.decision
			if got != tc.want {
				t.Errorf("evaluation = %+v, want %+v", got, tc.want)
			}
			if !KnownDecision(got.Decision) {
				t.Errorf("decision %q is not in the vocabulary a report is held to", got.Decision)
			}
		})
	}
}

// A negative reservation is a caller's error, not "no reservation": it was
// run as a plain check and granted on the host's current load alone, although
// projectedRAMPercent refuses it. The host here would grant a check with no
// reservation, so only the sign of the argument decides.
func TestANegativeRAMReservationIsRefusedNotTreatedAsNone(t *testing.T) {
	cfg := Config{MaxHostRAMPercent: 70, MaxHostIOWaitPercent: 10, DeferRetryIntervalSec: 1, MaxDeferRetries: 2}
	fakeHost(t, 100_000, 60_000, 40, 2, nil)
	c := New(cfg)
	if err := c.Check(context.Background()); err != nil {
		t.Fatalf("a plain check on this host = %v, want a grant", err)
	}
	if err := c.CheckWithReservedMemory(context.Background(), 0); err != nil {
		t.Fatalf("a zero reservation = %v, want a grant", err)
	}
	for _, reserved := range []int{-1, -1_000, -1 << 30} {
		err := c.CheckWithReservedMemory(context.Background(), reserved)
		if err == nil || !strings.Contains(err.Error(), "must not be negative") {
			t.Errorf("CheckWithReservedMemory(%d) = %v, want a refusal of the negative reservation", reserved, err)
		}
		if errors.Is(err, ErrAdmissionDenied) {
			t.Errorf("CheckWithReservedMemory(%d) = %v, a caller's error is not a denial that a wait would retry", reserved, err)
		}
		if err := c.WaitForAdmissionWithReservedMemory(context.Background(), reserved); err == nil || errors.Is(err, ErrMaxRetriesExceeded) || !strings.Contains(err.Error(), "must not be negative") {
			t.Errorf("WaitForAdmissionWithReservedMemory(%d) = %v, want the negative reservation refused at once", reserved, err)
		}
	}
}

// A run that is deferred is checked again: the evidence counts the checks and
// keeps the last one's measurements, the one that finally granted the run or
// the one that refused it last.
func TestAnEvaluationCountsEveryCheckAndKeepsTheLast(t *testing.T) {
	cfg := Config{MaxHostRAMPercent: 70, MaxHostIOWaitPercent: 10, DeferRetryIntervalSec: 1, MaxDeferRetries: 2}
	const total = 100_000.0

	// Refused on every check: max_defer_retries + 1 checks, the last one's numbers.
	fakeHost(t, total, 10_000, 90, 2, nil)
	refused := New(cfg)
	if err := refused.WaitForAdmissionWithReservedMemory(context.Background(), 1_000); !errors.Is(err, ErrMaxRetriesExceeded) {
		t.Fatalf("wait = %v, want the retries exhausted", err)
	}
	if got := refused.Evaluation(); got.Checks != 3 || got.Decision != DecisionDeniedRAM || got.HostRAMPercent != 90 {
		t.Errorf("after three refusals the evaluation is %+v, want 3 checks of denied_ram at 90%%", got)
	}

	// Refused once, then granted: two checks, the grant's numbers.
	readings := []float64{90, 40}
	capacity, usage, wait := readRAMCapacity, readRAMUsage, readIOWait
	t.Cleanup(func() { readRAMCapacity, readRAMUsage, readIOWait = capacity, usage, wait })
	next := 0
	readRAMUsage = func() (float64, error) {
		reading := readings[min(next, len(readings)-1)]
		next++
		return reading, nil
	}
	readRAMCapacity = func() (float64, float64, error) { return total, 60_000, nil }
	readIOWait = func(context.Context) (float64, error) { return 1, nil }
	later := New(cfg)
	if err := later.WaitForAdmissionWithReservedMemory(context.Background(), 1_000); err != nil {
		t.Fatalf("wait = %v, want the second check to grant", err)
	}
	if got := later.Evaluation(); got.Checks != 2 || got.Decision != DecisionGranted || got.HostRAMPercent != 40 {
		t.Errorf("after a refusal and a grant the evaluation is %+v, want 2 checks, granted at 40%%", got)
	}
}

// A plan with no reservation (not a plan the product runs) is held to the use
// now, and says so: the projection is the use.
func TestWithoutAReservationTheProjectionIsTheUseNow(t *testing.T) {
	fakeHost(t, 100_000, 60_000, 40, 2, nil)
	c := New(Config{MaxHostRAMPercent: 70, MaxHostIOWaitPercent: 10, DeferRetryIntervalSec: 1, MaxDeferRetries: 1})
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := c.Evaluation(); got.Decision != DecisionGranted || got.ProjectedRAMPercent != 40 || got.HostTotalMiB != 0 {
		t.Errorf("evaluation = %+v, want a grant projecting the 40%% in use, with no capacity read", got)
	}
}

// The deferral line names the memory in use, not the memory available: the two
// numbers it adds are the ones the percentage is made of.
func TestTheDeferralLineAddsTheMemoryInUseToTheReservation(t *testing.T) {
	const total, available, reserved = 15992.0, 13596.0, 12544
	projected, err := projectedRAMPercent(total, available, reserved)
	if err != nil {
		t.Fatal(err)
	}
	got := projectedRAMDeferral(total, available, reserved, projected, 85)
	if want := "Host admission deferred: 2396 MiB in use plus the recovery reservation of 12544 MiB would reach 93.4% of 15992 MiB (max 85.0%)."; got != want {
		t.Errorf("line = %q\nwant   %q", got, want)
	}
	if strings.Contains(got, "available") {
		t.Errorf("the line calls a number available: %q", got)
	}
}
