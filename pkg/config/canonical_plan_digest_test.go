// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"bytes"
	"testing"
)

func TestCanonicalDigestSurvivesWorkerPlanTransfer(t *testing.T) {
	encoded, err := MarshalWorkerPlan(validPlan())
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFromReaderForWorker(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	first, err := CanonicalWorkerPlanSHA256(loaded)
	if err != nil {
		t.Fatal(err)
	}
	transfer, err := MarshalWorkerPlan(loaded)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := LoadFromReaderForWorker(bytes.NewReader(transfer))
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalWorkerPlanSHA256(worker)
	if err != nil || first != second {
		t.Fatalf("worker transfer changed the canonical digest: %s %s %v", first, second, err)
	}
}

func TestCanonicalWorkerPlanDigestCoversPoliciesAndResolvedHardware(t *testing.T) {
	plan := &Plan{PlanID: "complete-policy", Compliance: Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90},
		Tiers: []Tier{{Level: 1, VMs: []VM{{VMID: 100}}}}}
	base, err := CanonicalWorkerPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Plan){
		"startup grace":   func(p *Plan) { p.Tiers[0].StartupGracePeriodSec = 30 },
		"resolved memory": func(p *Plan) { p.Tiers[0].VMs[0].HardwareOverrides.MemoryMB = 8192 },
		"quiesced backup": func(p *Plan) { p.Tiers[0].VMs[0].RequireQuiescedBackup = true },
	} {
		copy := plan.canonicalCopy()
		change(&copy)
		got, err := CanonicalWorkerPlanSHA256(&copy)
		if err != nil || got == base {
			t.Errorf("%s was not included in the digest: %v", name, err)
		}
	}
	plan.Compliance.SignKeyPath = "/controller-only/key"
	if got, err := CanonicalWorkerPlanSHA256(plan); err != nil || got != base {
		t.Fatal("controller-only key path affected the worker digest")
	}
}
