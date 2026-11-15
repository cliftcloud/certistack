// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// fakeClockGate is a bootGate on a clock that sleeping advances.
func fakeClockGate(limit int, settle time.Duration) (*bootGate, *time.Time, *[]time.Duration) {
	now := time.Date(2026, 9, 27, 20, 0, 0, 0, time.UTC)
	var slept []time.Duration
	g := newBootGate(config.AdmissionControl{MaxConcurrentBoots: limit, BootSettleSec: int(settle / time.Second)})
	g.now = func() time.Time { return now }
	g.sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		now = now.Add(d)
		return nil
	}
	return g, &now, &slept
}

// With two VMs still in their first 180 s, a third start waits until the
// older of them settles, and no longer.
func TestBootGateHoldsAStartUntilASlotFrees(t *testing.T) {
	g, now, slept := fakeClockGate(2, 180*time.Second)
	t0 := *now
	g.started(t0)
	g.started(t0.Add(10 * time.Second))
	*now = t0.Add(20 * time.Second)
	waited, err := g.wait(context.Background(), 9103)
	if err != nil {
		t.Fatal(err)
	}
	if waited != 160*time.Second || len(*slept) != 1 {
		t.Fatalf("waited %s in %v, want 160s at once", waited, *slept)
	}
	// Three booting with a limit of two: the start waits for two to settle.
	g.started(*now)
	*now = now.Add(5 * time.Second) // t0+185: t0+10 and t0+180 boot
	g.started(*now)                 // t0+185: now three
	*slept = nil
	waited, err = g.wait(context.Background(), 9105)
	if err != nil {
		t.Fatal(err)
	}
	if want := 175 * time.Second; waited != want { // until t0+180 settles at t0+360
		t.Fatalf("waited %s (%v), want %s", waited, *slept, want)
	}
}

func TestBootGateWithoutALimitNeverWaits(t *testing.T) {
	g, now, slept := fakeClockGate(0, 0)
	for i := 0; i < 5; i++ {
		g.started(*now)
	}
	if waited, err := g.wait(context.Background(), 1); waited != 0 || err != nil || len(*slept) != 0 {
		t.Fatalf("unlimited gate waited %s (%v)", waited, err)
	}
	var nilGate *bootGate
	if waited, err := nilGate.wait(context.Background(), 1); waited != 0 || err != nil {
		t.Fatal("a nil gate waited")
	}
	nilGate.started(*now)
}

func TestBootGateWaitEndsWithTheRun(t *testing.T) {
	g, now, _ := fakeClockGate(1, time.Minute)
	g.started(*now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g.sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	if _, err := g.wait(ctx, 2); err == nil {
		t.Fatal("wait outlived its context")
	}
}

// plan shows where a start may be held: from the (limit+1)th VM on.
func TestPlanShowsTheBootSlotWaits(t *testing.T) {
	plan := planTestPlan()
	vm := plan.Tiers[0].VMs[0]
	for i, id := range []int{9002, 9003} {
		next := withOwnTarget(vm, 11+i)
		next.VMID, next.Name = id, "web0"+string(rune('2'+i))
		plan.Tiers[0].VMs = append(plan.Tiers[0].VMs, next)
	}
	plan.AdmissionControl.MaxConcurrentBoots = 2
	o := planOrchestrator(t, plan, planPVE(t, ""))
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, step := range p.Steps {
		if step.Kind == "wait" && step.Target == "boot slot" {
			order = append(order, "wait")
			if !strings.Contains(step.Detail, "fewer than 2 sandbox VMs started in the last 3m0s") {
				t.Errorf("wait detail = %q", step.Detail)
			}
		}
		if step.Action == PlanStart {
			order = append(order, step.Target)
		}
	}
	if got := strings.Join(order, ", "); got != "VM 9001, VM 9002, wait, VM 9003" {
		t.Fatalf("starts and waits = %s", got)
	}
}
