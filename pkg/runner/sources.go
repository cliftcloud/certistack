// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"sync"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// maxConcurrentSourceLoads bounds the PBS reads a run makes at once while
// reading its VMs' source configurations.
const maxConcurrentSourceLoads = 8

// sourceCache reads each snapshot's source configuration once. prefetch
// reads them several at a time before the sequential steps apply them, so
// a large plan does not wait for one PBS round trip per VM, and a VM whose
// configuration two steps need is read once.
type sourceCache struct {
	inner backupProfileResolver

	mu       sync.Mutex
	profiles map[string]profileResult
	layouts  map[string]layoutResult
}

type profileResult struct {
	profile pbs.VMProfile
	err     error
}

type layoutResult struct {
	layout pbs.VMLayout
	err    error
}

func newSourceCache(inner backupProfileResolver) *sourceCache {
	return &sourceCache{inner: inner, profiles: make(map[string]profileResult), layouts: make(map[string]layoutResult)}
}

// LoadVMProfile returns the snapshot's full profile, reading it once.
func (c *sourceCache) LoadVMProfile(ctx context.Context, snapshot, scratchDir string) (pbs.VMProfile, error) {
	c.mu.Lock()
	cached, ok := c.profiles[snapshot]
	c.mu.Unlock()
	if ok {
		return cached.profile, cached.err
	}
	profile, err := c.inner.LoadVMProfile(ctx, snapshot, scratchDir)
	c.mu.Lock()
	c.profiles[snapshot] = profileResult{profile, err}
	c.mu.Unlock()
	return profile, err
}

// LoadVMLayout returns the snapshot's layout, reading it once.
func (c *sourceCache) LoadVMLayout(ctx context.Context, snapshot, scratchDir string) (pbs.VMLayout, error) {
	c.mu.Lock()
	cached, ok := c.layouts[snapshot]
	c.mu.Unlock()
	if ok {
		return cached.layout, cached.err
	}
	layout, err := c.inner.LoadVMLayout(ctx, snapshot, scratchDir)
	c.mu.Lock()
	c.layouts[snapshot] = layoutResult{layout, err}
	c.mu.Unlock()
	return layout, err
}

// prefetch reads, several at a time, what the apply steps will ask for:
// every snapshot's profile for a use_backup_config plan, its layout
// otherwise. Errors are kept and returned, with the VM they belong to, by
// the step that asks.
func (c *sourceCache) prefetch(ctx context.Context, plan *config.Plan, scratchDir string) {
	seen := make(map[string]bool)
	var snapshots []string
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			if snapshot := vm.SourcePBS.Snapshot; snapshot != "" && !seen[snapshot] {
				seen[snapshot] = true
				snapshots = append(snapshots, snapshot)
			}
		}
	}
	slots := make(chan struct{}, maxConcurrentSourceLoads)
	var wg sync.WaitGroup
	for _, snapshot := range snapshots {
		wg.Add(1)
		slots <- struct{}{}
		go func(snapshot string) {
			defer wg.Done()
			defer func() { <-slots }()
			if plan.UseBackupConfig {
				_, _ = c.LoadVMProfile(ctx, snapshot, scratchDir)
			} else {
				_, _ = c.LoadVMLayout(ctx, snapshot, scratchDir)
			}
		}(snapshot)
	}
	wg.Wait()
}
