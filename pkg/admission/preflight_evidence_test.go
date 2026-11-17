// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import "testing"

func TestPreflightMemoryRecordsTheSampleThatRefusesTheRun(t *testing.T) {
	previous := readRAMCapacity
	t.Cleanup(func() { readRAMCapacity = previous })
	readRAMCapacity = func() (float64, float64, error) { return 10_000, 1_000, nil }
	got, err := PreflightMemory(2_000, 90)
	if err == nil || got.Decision != DecisionPreflightDeniedMemory || got.HostTotalMiB != 10_000 || got.HostAvailableMiB != 1_000 || got.RequiredAvailableMiB != 2_000 || got.Checks != 1 {
		t.Fatalf("preflight evaluation=%+v error=%v", got, err)
	}
	got, err = PreflightMemory(9_500, 90)
	if err == nil || got.Decision != DecisionNeverAdmissible {
		t.Fatalf("never-admissible evaluation=%+v error=%v", got, err)
	}
	got, err = PreflightMemory(500, 90)
	if err != nil || got.Checks != 0 {
		t.Fatalf("preflight claimed an admission grant: %+v %v", got, err)
	}
}
