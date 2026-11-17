// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
)

// serialRunner serializes a fake command runner, which the lease renewals
// and the run's own commands use at the same time, and counts the renewals.
type serialRunner struct {
	mu       sync.Mutex
	inner    *fakeCommandRunner
	touches  atomic.Int64
	cancelAt atomic.Int64 // touches when the run's context was cancelled
}

func (r *serialRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	if strings.Contains(strings.Join(args, " "), "'/usr/bin/touch'") {
		r.touches.Add(1)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.Run(ctx, name, args)
}

func (r *serialRunner) RunWithStderr(ctx context.Context, name string, args []string, progress io.Writer) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.RunWithStderr(ctx, name, args, progress)
}

// The first Ctrl-C cancels the run's context, while the controller goes on
// verifying the worker's journal under its cleanup context. The lease is
// renewed until the controller's own work is done: renewals that stopped with
// the run's context would let the node's lease watch act on a journal the
// controller is verifying, and remove the credentials its recovery needs,
// whenever that verification waits longer than the lease for the host lock.
func TestLeaseIsRenewedWhileTheControllerVerifiesAfterACtrlC(t *testing.T) {
	fastHostLockRetry(t)
	interval, warnAfter := workerLeaseRenewInterval, leaseWarnAfter
	workerLeaseRenewInterval, leaseWarnAfter = 2*time.Millisecond, time.Hour
	defer func() { workerLeaseRenewInterval, leaseWarnAfter = interval, warnAfter }()

	opts := completedWorkerTeardownOptions(t)
	lockHeld := errors.New("ssh failed: exit status 1: cannot acquire host lock for recovery: " + journal.LockHeldMessage)
	// The worker returned, and the operator pressed Ctrl-C at once; the
	// node's host lock stays held for a while, then goes.
	recoverErrors := make([]error, 0, 61)
	for i := 0; i < 60; i++ {
		recoverErrors = append(recoverErrors, lockHeld)
	}
	recoverErrors = append(recoverErrors, nil)
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := &serialRunner{inner: &fakeCommandRunner{
		nodeRunError:  errors.New("ssh session ended"),
		journalPhase:  "cleanup_failed",
		recoverErrors: recoverErrors,
	}}
	runner.inner.nodeRunHook = func() {
		time.Sleep(20 * time.Millisecond) // renewals, so far
		runner.cancelAt.Store(runner.touches.Load())
		cancel()
	}
	_, err := (&Executor{runner: runner}).Run(runCtx, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the interruption", err)
	}
	before, after := runner.cancelAt.Load(), runner.touches.Load()
	if before == 0 {
		t.Fatal("no renewal ran before the interruption; the test does not measure anything")
	}
	if after-before < 5 {
		t.Fatalf("%d renewals after the interruption (%d before): the lease lapsed while the controller was still verifying the journal", after-before, before)
	}
	if runner.inner.recoverCalls < 61 {
		t.Fatalf("recover ran %d times: the verification did not wait for the lock", runner.inner.recoverCalls)
	}
}
