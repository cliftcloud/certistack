// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"sort"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/progress"
)

// bootGate holds a sandbox VM's start while admission_control's
// max_concurrent_boots VMs are still booting on the node. A tier starts its
// VMs one after another, so without it their first minutes overlap, when
// each guest writes to its fresh overlays at once: on a node whose cluster
// database shares the disk, that can delay corosync. A VM counts as
// booting for the plan's boot settle time after it was started, across
// tiers.
type bootGate struct {
	limit  int
	settle time.Duration
	starts []time.Time
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error
}

func newBootGate(a config.AdmissionControl) *bootGate {
	return &bootGate{
		limit:  a.MaxConcurrentBoots,
		settle: a.BootSettle(),
		now:    time.Now,
		sleep: func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		},
	}
}

// wait returns once fewer than the limit of sandbox VMs are booting, and
// how long it waited. Without a limit it returns at once.
func (g *bootGate) wait(ctx context.Context, vmid int) (time.Duration, error) {
	if g == nil || g.limit <= 0 {
		return 0, nil
	}
	began := g.now()
	announced := false
	for {
		now := g.now()
		booting := g.booting(now)
		if len(booting) < g.limit {
			return now.Sub(began), nil
		}
		// The slot frees when the oldest of the last limit starts settles.
		free := booting[len(booting)-g.limit].Add(g.settle)
		if !announced {
			progress.Info("Sandbox", "Holding VM %d's start for up to %s: %d sandbox VM(s) are in their first %s of boot (admission_control.max_concurrent_boots: %d).",
				vmid, free.Sub(now).Round(time.Second), len(booting), g.settle, g.limit)
			announced = true
		}
		if err := g.sleep(ctx, free.Sub(now)); err != nil {
			return g.now().Sub(began), err
		}
	}
}

// started records a sandbox VM's start at t.
func (g *bootGate) started(t time.Time) {
	if g != nil && g.limit > 0 {
		g.starts = append(g.starts, t)
	}
}

// booting is the starts within the settle time before now, oldest first.
func (g *bootGate) booting(now time.Time) []time.Time {
	var booting []time.Time
	for _, t := range g.starts {
		if now.Sub(t) < g.settle {
			booting = append(booting, t)
		}
	}
	sort.Slice(booting, func(i, j int) bool { return booting[i].Before(booting[j]) })
	return booting
}
