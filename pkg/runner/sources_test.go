// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// countingResolver counts reads per snapshot and the most reads at once.
type countingResolver struct {
	mu        sync.Mutex
	reads     map[string]int
	running   atomic.Int32
	maxAtOnce atomic.Int32
	fail      string
}

func (r *countingResolver) read(snapshot string) error {
	now := r.running.Add(1)
	defer r.running.Add(-1)
	for {
		seen := r.maxAtOnce.Load()
		if now <= seen || r.maxAtOnce.CompareAndSwap(seen, now) {
			break
		}
	}
	time.Sleep(5 * time.Millisecond)
	r.mu.Lock()
	r.reads[snapshot]++
	r.mu.Unlock()
	if snapshot == r.fail {
		return errors.New("PBS unavailable")
	}
	return nil
}

func (r *countingResolver) LoadVMProfile(_ context.Context, snapshot, _ string) (pbs.VMProfile, error) {
	return pbs.VMProfile{}, r.read(snapshot)
}

func (r *countingResolver) LoadVMLayout(_ context.Context, snapshot, _ string) (pbs.VMLayout, error) {
	return pbs.VMLayout{}, r.read(snapshot)
}

func TestSourceCacheReadsEachSnapshotOnceAndInParallel(t *testing.T) {
	plan := &config.Plan{}
	var vms []config.VM
	for i := 0; i < 40; i++ {
		// 20 distinct snapshots, each used by two VMs.
		vms = append(vms, config.VM{VMID: 10000 + i, SourcePBS: config.SourcePBS{Snapshot: fmt.Sprintf("vm/%d/2026-09-27T03:00:00Z", 7000+i%20)}})
	}
	plan.Tiers = []config.Tier{{VMs: vms}}
	inner := &countingResolver{reads: make(map[string]int), fail: "vm/7003/2026-09-27T03:00:00Z"}
	cache := newSourceCache(inner)

	cache.prefetch(context.Background(), plan, "/tmp")
	for _, vm := range vms {
		_, err := cache.LoadVMLayout(context.Background(), vm.SourcePBS.Snapshot, "/tmp")
		if (err != nil) != (vm.SourcePBS.Snapshot == inner.fail) {
			t.Fatalf("%s: err %v", vm.SourcePBS.Snapshot, err)
		}
	}
	if len(inner.reads) != 20 {
		t.Fatalf("read %d snapshots, want 20", len(inner.reads))
	}
	for snapshot, n := range inner.reads {
		if n != 1 {
			t.Errorf("%s read %d times", snapshot, n)
		}
	}
	if got := inner.maxAtOnce.Load(); got < 2 || got > maxConcurrentSourceLoads {
		t.Fatalf("%d reads at once, want between 2 and %d", got, maxConcurrentSourceLoads)
	}
}
