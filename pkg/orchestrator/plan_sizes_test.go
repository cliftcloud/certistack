// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"testing"
)

// plan said "reads all 0 GiB" for a 64 MiB disk (lab chaos L5), and rounded a
// disk of 1.5 GiB down to "all 1 GiB". A size below 1 GiB is in MiB, and a size
// that is not a whole number of GiB shows its fraction.
func TestPlanSaysHowMuchOfASmallOrOddDiskItReads(t *testing.T) {
	plan := planTestPlan()
	plan.Tiers[0].VMs[0].SourceDiskBytes = map[string]int64{"scsi0": 64 << 20, "scsi1": 3 << 29}
	p, err := planOrchestrator(t, plan, planPVE(t, "")).Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reads := map[string]string{}
	for _, step := range p.Steps {
		if step.Kind == "integrity-scan" {
			reads[step.Target] = step.Detail
		}
	}
	want := map[string]string{
		"scsi0": "reads all 64 MiB once (SHA-256), filling the page cache the boot reads",
		"scsi1": "reads all 1.5 GiB once (SHA-256), filling the page cache the boot reads",
	}
	for slot, detail := range want {
		if reads[slot] != detail {
			t.Errorf("%s: %q, want %q", slot, reads[slot], detail)
		}
	}
}
