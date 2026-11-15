// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// A setup step retried after a lost connection returned the connection failure
// when the run was interrupted in the wait before the retry, so Ctrl-C there
// ended with exit status 2, as if the connection had failed, and not 130. The
// error is now the connection failure that made it retry, and the interruption.

// The verifier's probe: a step that fails with a lost connection, interrupted
// 200 ms into the wait before its retry.
func TestRetrySetupInterruptedDuringTheWaitIsTheInterruption(t *testing.T) {
	waits := setupRetries
	setupRetries = []time.Duration{time.Minute}
	t.Cleanup(func() { setupRetries = waits })
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	calls := 0
	start := time.Now()
	err := retrySetup(ctx, func() error {
		calls++
		return lostConnection("Connection reset by peer")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want the interruption (errors.Is context.Canceled), which exit status 130 is chosen by", err)
	}
	if !strings.Contains(err.Error(), "Connection reset by peer") || !connectionFailed(err) {
		t.Errorf("err = %v; want the connection failure that made it retry to stay in it", err)
	}
	if calls != 1 || time.Since(start) > 5*time.Second {
		t.Errorf("calls = %d after %s; want one try, and the wait cut short", calls, time.Since(start))
	}
}

// The same when the context has already ended by the time a retry is due, and
// not when the step failed for its own reasons.
func TestRetrySetupReportsTheInterruptionOnlyForAConnectionItWouldHaveRetried(t *testing.T) {
	waits := setupRetries
	setupRetries = []time.Duration{time.Minute}
	t.Cleanup(func() { setupRetries = waits })

	ctx, cancel := context.WithCancel(context.Background())
	err := retrySetup(ctx, func() error {
		cancel() // the run is interrupted while the step runs
		return lostConnection("Connection reset by peer")
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("a connection that failed as the run was interrupted: err = %v; want the interruption", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	realFailure := errors.New("ssh failed: exit status 1: install: cannot create directory: Permission denied")
	if err := retrySetup(ctx, func() error { cancel(); return realFailure }); err != realFailure {
		t.Errorf("a step that failed for its own reasons: err = %v; want it unchanged", err)
	}

	// An error that already is the interruption is not wrapped again.
	ctx, cancel = context.WithCancel(context.Background())
	already := lostConnection("Connection reset by peer: " + context.Canceled.Error())
	err = retrySetup(ctx, func() error { cancel(); return already })
	if strings.Count(err.Error(), "stopped retrying") > 1 {
		t.Errorf("err = %v", err)
	}

	// With no interruption nothing changes: the connection failure is retried,
	// and a failure that outlasts the retries is the failure.
	setupRetries = []time.Duration{time.Millisecond, time.Millisecond}
	tries := 0
	err = retrySetup(context.Background(), func() error { tries++; return lostConnection("Connection reset by peer") })
	if tries != 3 || err == nil || errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "stopped retrying") {
		t.Errorf("tries = %d, err = %v", tries, err)
	}
}

// Through the run: Ctrl-C while the controller waits to retry its first setup
// step on the node ends the run with the interruption, so the command exits
// with 130, and nothing was started on the node.
func TestRunInterruptedWhileRetryingASetupStepIsTheInterruption(t *testing.T) {
	waits := setupRetries
	setupRetries = []time.Duration{time.Minute}
	t.Cleanup(func() { setupRetries = waits })
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		if strings.Contains(joined, "'/usr/bin/uname'") {
			go func() {
				time.Sleep(200 * time.Millisecond)
				cancel()
			}()
			return nil, lostConnection("Connection reset by peer"), true
		}
		return nil, nil, false
	}
	start := time.Now()
	_, err := (&Executor{runner: fake}).Run(ctx, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v; want the interruption", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("the run took %s to end after the interrupt", time.Since(start))
	}
	if command, started := startedAnything(fake); started {
		t.Errorf("the controller started something on the node: %s", command)
	}
}
