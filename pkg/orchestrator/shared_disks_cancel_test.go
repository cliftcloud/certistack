// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/pbs"
)

// The topology checks (a ZFS pool is listed by a subprocess) take the
// caller's context, so cancelling a plan, or interrupting a run at its first
// check, does not wait for the subprocess, and the failure the cancellation
// causes is not turned into an "unknown topology" warning. The fakes below
// behave as the production check does: they block until the caller's context
// ends, and then fail with its error.

// blockingDiskCheck is a sharedDisksFn that signals when it is called and
// then waits for the context it was given. dirs records the directories asked about.
type blockingDiskCheck struct {
	started chan struct{}
	dirs    chan string
}

func newBlockingDiskCheck() *blockingDiskCheck {
	return &blockingDiskCheck{started: make(chan struct{}, 1), dirs: make(chan string, 8)}
}

func (b *blockingDiskCheck) fn(ctx context.Context, dir, _ string) ([]string, error) {
	b.dirs <- dir
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (b *blockingDiskCheck) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the run never reached its shared-disk check")
	}
}

// Plan is cancelled while the check runs. It must
// return the context's error at once, not a plan whose copy decision rests on
// an "unknown" answer the cancellation made.
func TestPlanReturnsTheContextErrorWhenCancelledDuringTheCopyDecision(t *testing.T) {
	o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
	check := newBlockingDiskCheck()
	o.sharedDisksFn = check.fn
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		plan *RunPlan
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		plan, err := o.Plan(ctx)
		done <- outcome{plan, err}
	}()
	check.waitStarted(t)
	cancel()
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) || got.plan != nil {
			t.Fatalf("Plan = %+v, %v; want no plan and the context's error: a cancelled plan is not a plan", got.plan, got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Plan was still waiting for the shared-disk check 3 s after it was cancelled")
	}
}

// The overlay storage check of Plan reads the same topology.
func TestPlanReturnsTheContextErrorWhenCancelledDuringTheOverlayStorageCheck(t *testing.T) {
	o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
	o.opts.OverlayStorage = "certistack-scratch"
	o.validateOverlayStorageFn = func(context.Context) error { return nil }
	o.overlayVolumePathFn = func(_ context.Context, volume string) (string, error) {
		_, rest, _ := strings.Cut(volume, ":")
		return "/var/lib/vz/images/" + rest, nil
	}
	check := newBlockingDiskCheck()
	o.sharedDisksFn = check.fn
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		plan, err := o.Plan(ctx)
		if plan != nil {
			t.Errorf("Plan returned a plan: %+v", plan)
		}
		done <- err
	}()
	check.waitStarted(t)
	if dir := filepath.ToSlash(<-check.dirs); dir != "/var/lib/vz" {
		t.Fatalf("the first check was of %q, want the overlay storage's directory: the test must stop in the storage check", dir)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Plan = %v, want the context's error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Plan was still waiting for the shared-disk check 3 s after it was cancelled")
	}
}

// Over-correction guard: a topology that really cannot be determined is still
// a warning and an "unknown", and the plan is still made.
func TestPlanStillWarnsWhenTheTopologyIsUnknownAndNobodyCancelled(t *testing.T) {
	o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
	o.sharedDisksFn = func(context.Context, string, string) ([]string, error) {
		return nil, errors.New("cannot resolve cluster disk")
	}
	p, err := o.Plan(context.Background())
	if err != nil || p == nil {
		t.Fatalf("Plan = %v, %v; want a plan", p, err)
	}
	for _, step := range p.Steps {
		if step.Kind == "copy-before-boot" {
			return
		}
	}
	t.Fatal("the plan has no copy decision, although the topology was only unknown")
}

// The run's own checks answer a cancellation with the context's error too.
func TestRunSideDiskChecksReturnTheContextErrorWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	check := newBlockingDiskCheck()
	o := &Orchestrator{sharedDisksFn: check.fn}
	errs := make(chan error, 2)
	go func() { errs <- o.warnOverlaySharesClusterDisk(ctx, "/var/lib/vz/images/9001") }()
	check.waitStarted(t)
	cancel()
	select {
	case err := <-errs:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("warnOverlaySharesClusterDisk = %v, want the context's error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("warnOverlaySharesClusterDisk did not end with its context")
	}

	// copy-before-boot's decision in the same state.
	ctx, cancel = context.WithCancel(context.Background())
	check = newBlockingDiskCheck()
	o = &Orchestrator{
		sharedDisksFn: check.fn,
		deviceBytesFn: func(string) (int64, error) { return 48 << 30, nil },
		freeBytesFn:   func(string) (int64, error) { return 500 << 30, nil },
		tierCache:     tierCache{budgetKnown: true, budgetBytes: 35 << 30},
	}
	type decision struct {
		copied bool
		err    error
	}
	got := make(chan decision, 1)
	go func() {
		copied, err := o.chooseCopyBeforeBoot(ctx, mapTestVM(), []string{"/dev/loop0"}, "/scratch")
		got <- decision{copied, err}
	}()
	check.waitStarted(t)
	cancel()
	select {
	case d := <-got:
		if !errors.Is(d.err, context.Canceled) || d.copied || o.copiedBytes != 0 {
			t.Fatalf("chooseCopyBeforeBoot = %v, %v (copied bytes %d); want the context's error and no copy", d.copied, d.err, o.copiedBytes)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("chooseCopyBeforeBoot did not end with its context")
	}
}

// Run-side case: a run interrupted at its first topology check, after
// its PBS map was made and journaled. The check ends with the interruption, so
// teardown starts at once, and it releases the loop and proves it gone.
func TestRunInterruptedAtTheOverlayDiskCheckStillTearsDownItsMappedLoop(t *testing.T) {
	f := newLoopFixture(t, "exit 19")
	// The fixture's losetup only logs; this one detaches, as the real one does.
	losetup := "#!/bin/sh\nprintf 'losetup %s\\n' \"$*\" >> '" + f.log + "'\n/bin/rm -f '" + f.state + "'\n"
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.log), "losetup"), []byte(losetup), 0o755); err != nil {
		t.Fatal(err)
	}
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	o.opts.OverlayStorage = "certistack-scratch"
	images := filepath.Join(t.TempDir(), "images")
	if err := os.Mkdir(images, 0o700); err != nil {
		t.Fatal(err)
	}
	o.overlayVolumePathFn = func(_ context.Context, volume string) (string, error) {
		_, rest, _ := strings.Cut(volume, ":")
		return filepath.Join(images, rest), nil
	}
	check := newBlockingDiskCheck()
	o.sharedDisksFn = check.fn

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := o.bootAndVerifyVM(ctx, mapTestVM(), 60, nil)
		done <- err
	}()
	check.waitStarted(t)
	if len(o.record.Loops) != 1 {
		t.Fatalf("journaled loops = %+v; the check must come after the map is journaled", o.record.Loops)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("bootAndVerifyVM = %v, want the context's error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the run was still in its shared-disk check 3 s after the interruption, so its teardown could not begin")
	}

	if failures := o.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures = %v", failures)
	}
	if calls := f.calls(); calls != "losetup -d /dev/loop7" {
		t.Fatalf("teardown ran:\n%s\nwant the map released by the verified detach", calls)
	}
	if all, unmapped, errs := o.verifyTrackedLoopsUnmapped(); !all || len(unmapped) != 1 || len(errs) != 0 {
		t.Fatalf("verification = all %v, unmapped %v, errs %v; want the loop proven gone", all, unmapped, errs)
	}
}
