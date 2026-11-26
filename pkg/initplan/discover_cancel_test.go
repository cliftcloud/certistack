// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package initplan

import (
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/pbs"
)

// gateBackups holds every LoadVMProfile call until the test lets it go, and
// records how many were made and the directory each was given.
type gateBackups struct {
	mu      sync.Mutex
	dirs    []string
	entered chan struct{}
	release chan struct{}
}

func (g *gateBackups) ListVMBackups(context.Context) ([]pbs.VMBackups, error) { return nil, nil }

func (g *gateBackups) LoadVMProfile(ctx context.Context, _, dir string) (pbs.VMProfile, error) {
	g.mu.Lock()
	g.dirs = append(g.dirs, dir)
	g.mu.Unlock()
	g.entered <- struct{}{}
	<-g.release
	return pbs.VMProfile{}, ctx.Err()
}

func (g *gateBackups) loads() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.dirs)
}

// readVMs runs a fixed pool of readers and looks at the context before it
// makes anything for a backup, so once the run is canceled no queued backup
// gets a private scratch directory or a question to the repository.
func TestReadVMsMakesNothingMoreOnceTheRunIsCanceled(t *testing.T) {
	const backups = 40
	chosen := make([]pbs.VMBackups, backups)
	for i := range chosen {
		chosen[i] = pbs.VMBackups{VMID: 1000 + i, Latest: "vm/snapshot"}
	}
	scratch := t.TempDir()
	gate := &gateBackups{entered: make(chan struct{}, backups), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	baseline := runtime.NumGoroutine()
	done := make(chan []VM, 1)
	go func() { done <- readVMs(ctx, gate, chosen, scratch) }()
	for i := 0; i < profileReaders; i++ {
		select {
		case <-gate.entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d readers started", i, profileReaders)
		}
	}
	// Every reader slot is taken and held. The pool is its size, not one
	// goroutine for each selected backup (the goroutine running readVMs and a
	// little slack besides).
	if extra := runtime.NumGoroutine() - baseline; extra > profileReaders+3 {
		t.Errorf("%d goroutines more than before for %d selected backups with %d readers", extra, backups, profileReaders)
	}

	cancel()
	close(gate.release)
	var vms []VM
	select {
	case vms = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("readVMs did not return after the cancellation")
	}
	if got := gate.loads(); got != profileReaders {
		t.Errorf("%d backups were opened, of which only the %d that held a reader before the cancellation may be", got, profileReaders)
	}
	if entries, err := os.ReadDir(scratch); err != nil || len(entries) != 0 {
		t.Errorf("scratch directory holds %v (%v) after readVMs returned", entries, err)
	}
	if len(vms) != backups {
		t.Fatalf("%d VMs, want %d", len(vms), backups)
	}
	for _, vm := range vms {
		if vm.Error == "" {
			t.Errorf("VM %d has no error after the run was canceled", vm.SourceVMID)
		}
		if vm.SourceVMID == 0 || vm.Snapshot != "vm/snapshot" {
			t.Errorf("a VM lost what was known of its backup: %+v", vm)
		}
	}
	for _, vm := range vms[profileReaders:] {
		if !strings.Contains(vm.Error, "not read") {
			t.Errorf("VM %d, which was never started, says %q", vm.SourceVMID, vm.Error)
		}
	}
}
