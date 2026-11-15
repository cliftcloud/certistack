// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import (
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

func TestRecoveryMemoryReservationCountsEveryResidentTier(t *testing.T) {
	plan := &config.Plan{Tiers: []config.Tier{
		{Level: 1, VMs: []config.VM{
			{HardwareOverrides: config.HardwareOverrides{MemoryMB: 4096}},
			{},
		}},
		{Level: 2, VMs: []config.VM{{HardwareOverrides: config.HardwareOverrides{MemoryMB: 4096}}}},
	}}
	memoryMB, count, tier, err := RecoveryMemoryReservation(plan)
	if err != nil {
		t.Fatal(err)
	}
	// Tier 1 stays running while tier 2 boots:
	// (4096 + default 2048 + 2x256) + (4096 + 256) = 11008 MiB.
	if memoryMB != 11008 || count != 3 || tier != 2 {
		t.Fatalf("reservation = %d MiB / %d VM(s) / tier %d, want 11008 / 3 / 2", memoryMB, count, tier)
	}
}

func TestRecoveryMemoryReservationRejectsNilPlan(t *testing.T) {
	if _, _, _, err := RecoveryMemoryReservation(nil); err == nil {
		t.Fatal("nil plan unexpectedly produced a memory reservation")
	}
}
