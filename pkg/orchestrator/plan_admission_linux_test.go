//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/admission"
)

// On a 126 GiB blade: plan said "not admitted now; the run would wait and
// retry" for a plan that node can never hold. A plan no wait can admit is a
// refusal, and the run refuses it before anything is made.
func TestPlanRefusesAPlanTheNodeCanNeverAdmit(t *testing.T) {
	plan := planTestPlan()
	plan.Tiers[0].VMs[0].HardwareOverrides.MemoryMB = 64 << 20 // 64 TiB: no host holds it
	o := planOrchestrator(t, plan, planPVE(t, ""))
	o.admission = admission.New(admission.Config{MaxHostRAMPercent: 80, MaxHostIOWaitPercent: 100, DeferRetryIntervalSec: 1, MaxDeferRetries: 1})
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	refused := strings.Join(p.Refusals, "\n")
	if !strings.Contains(refused, "can never be admitted on this node") || !strings.Contains(refused, "split the plan") {
		t.Fatalf("refusals = %q, want the never-admissible refusal", refused)
	}
	for _, step := range p.Steps {
		if step.Kind == "admission" && step.Status != StatusFailed {
			t.Fatalf("admission step = %s %q, want it failed", step.Status, step.Detail)
		}
		if strings.Contains(step.Detail, "would wait and retry") {
			t.Fatalf("plan still promises a retry: %q", step.Detail)
		}
	}
}
