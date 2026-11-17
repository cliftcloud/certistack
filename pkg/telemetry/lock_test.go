// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// concurrentTo is a second process: a manager over the same state file, with
// the same environment and clock.
func concurrentTo(h *harness) *Manager {
	return &Manager{Version: h.Version, StatePath: h.StatePath, Getenv: h.Getenv, Now: h.Now, Timeout: h.Timeout}
}

// between runs act once, at the moment AfterRun has decided from the state it
// read and has not yet written anything: the endpoint is the next thing it
// asks the environment for.
func between(h *harness, act func()) {
	inner := h.Manager.Getenv
	var once sync.Once
	h.Manager.Getenv = func(name string) string {
		if name == VarURL {
			once.Do(act)
		}
		return inner(name)
	}
}

// A run that read the state before the user opted out must not write the
// enabled state back when it finishes: that would undo the opt-out the user
// was told had worked, and the next runs would report again.
func TestARunThatReadItsStateBeforeAnOptOutDoesNotUndoTheOptOut(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	forgotten := mustEnable(t, h, false).InstallID
	other := concurrentTo(h)
	var disableErr error
	var got string
	between(h, func() { got, disableErr = other.Disable() })

	out := h.AfterRun(context.Background(), completed("cluster-a", h.now))

	if disableErr != nil || got != forgotten {
		t.Fatalf("Disable = %q, %v; want it to forget %q", got, disableErr, forgotten)
	}
	st, status := ReadState(h.StatePath)
	if status != StateOK || st.Enabled || st.InstallID != "" || st.Salt != "" || len(st.Clusters) != 0 {
		t.Fatalf("state after the opt-out and the run = %+v (%v); want the opt-out, with nothing of the old install", st, status)
	}
	if out.Sent || srv.count() != 0 {
		t.Fatalf("the run sent (%+v, %d requests) after the user opted out", out, srv.count())
	}
	if !strings.Contains(out.Why, "disabled") {
		t.Errorf("Why = %q; want it to say telemetry was turned off meanwhile", out.Why)
	}
}

// The same for reset, which forgets the install and the answer: the run does
// not bring the file back.
func TestARunThatReadItsStateBeforeAResetDoesNotBringTheStateBack(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)
	other := concurrentTo(h)
	between(h, func() {
		if _, err := other.Reset(); err != nil {
			t.Error(err)
		}
	})

	out := h.AfterRun(context.Background(), completed("cluster-a", h.now))

	if _, status := ReadState(h.StatePath); status != StateMissing {
		t.Fatalf("state status after the reset and the run = %v; want the file still gone", status)
	}
	if out.Sent || srv.count() != 0 {
		t.Fatalf("the run sent (%+v, %d requests) after the user reset telemetry", out, srv.count())
	}
}

// Two runs that finish together each read a due state. They must not send the
// day's report twice or lose each other's cluster: the second reads what the
// first wrote, keeps its cluster, and finds the day's attempt taken.
func TestRunsThatFinishTogetherMergeTheirHistoryAndReserveOneAttempt(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)
	other := concurrentTo(h)
	var first Outcome
	between(h, func() { first = other.AfterRun(context.Background(), completed("cluster-b", h.now)) })

	second := h.AfterRun(context.Background(), completed("cluster-a", h.now))

	if !first.Sent || second.Sent || srv.count() != 1 {
		t.Fatalf("first %+v, second %+v, %d requests; want exactly one report", first, second, srv.count())
	}
	if st := h.state(t); len(st.Clusters) != 2 {
		t.Fatalf("clusters = %d, want both runs' clusters kept", len(st.Clusters))
	}
}

// Many controllers finishing at once: every cluster is kept, one report goes,
// and the file is one the reader believes.
func TestManyRunsAtOnceKeepEveryClusterAndSendOnce(t *testing.T) {
	if !stateLockSerializes {
		t.Skip("this platform has no state-file lock: changes to the state are not serialized here")
	}
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)
	const runs = 12
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out := concurrentTo(h).AfterRun(context.Background(), completed(fmt.Sprintf("cluster-%d", i), h.now))
			if out.Err != nil {
				t.Errorf("run %d: %+v", i, out)
			}
		}(i)
	}
	wg.Wait()
	if st := h.state(t); len(st.Clusters) != runs {
		t.Fatalf("clusters = %d, want %d", len(st.Clusters), runs)
	}
	if srv.count() != 1 {
		t.Fatalf("%d reports went; want the one the day allows", srv.count())
	}
}

// A state that is being changed holds the others back for a bounded time and
// then they say so: a run does not write over it, an opt-out is not reported
// as done when it was not.
func TestABusyStateFileIsWaitedForAndThenReported(t *testing.T) {
	if !stateLockSerializes {
		t.Skip("this platform has no state-file lock: changes to the state are not serialized here")
	}
	previous := lockWait
	lockWait = 50 * time.Millisecond
	t.Cleanup(func() { lockWait = previous })
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)
	before, _ := os.ReadFile(h.StatePath)

	unlock, err := lockState(h.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := h.Disable(); err == nil || !strings.Contains(err.Error(), "another CertiStack process") {
		t.Errorf("Disable while the state is being changed = %v; want it to say so", err)
	}
	if out := h.AfterRun(context.Background(), completed("cluster-a", h.now)); out.Sent || out.Err == nil || srv.count() != 0 {
		t.Errorf("AfterRun while the state is being changed = %+v, %d requests; want nothing recorded or sent, and the reason", out, srv.count())
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("waited %v for a lock that was never released", elapsed)
	}
	if after, _ := os.ReadFile(h.StatePath); string(after) != string(before) {
		t.Error("the state changed without the lock")
	}

	unlock()
	if _, err := h.Disable(); err != nil {
		t.Fatalf("Disable once the lock is free: %v", err)
	}
	if st := h.state(t); st.Enabled {
		t.Fatal("telemetry is still enabled after a successful disable")
	}
}

// AfterRun does not wait out the whole lock wait (five seconds) for a state
// file another process holds when its context ends sooner: the command a report
// rides on must not wait past the two seconds the documentation promises. The
// wait for the lock ends with the context too.
func TestAfterRunWaitsForTheStateLockNoLongerThanItsContext(t *testing.T) {
	if !stateLockSerializes {
		t.Skip("this platform has no state-file lock")
	}
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)
	unlock, err := lockState(h.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unlock)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	out := h.AfterRun(ctx, completed("cluster-a", h.now))
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("AfterRun took %v with a context of 200ms; want it to stop waiting for the lock when the context ends", elapsed)
	}
	if out.Sent || srv.count() != 0 {
		t.Fatalf("AfterRun = %+v with %d requests; want nothing sent", out, srv.count())
	}
}
