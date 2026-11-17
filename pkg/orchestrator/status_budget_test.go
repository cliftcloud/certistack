// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// The status reads of a wait are bounded per read and, for a VM that
// has been read, as a whole. Three edits of that left every test green
// (observeVM unbounded, watchVMs's per-read bound unbounded, the shared final
// budget removed), and a healthy but slow PVE failed the later VMs of a big
// tier without ever asking about them. These tests drive the real PVE client
// against a PVE that is slow, hung, or both.

// pacedStatusPVE answers each VM's status reads by answer(vmid, nth), the nth read
// of that VM: a delay before an answer that says "running" (negative: no answer
// at all, until the read is abandoned), and release ends every request that is
// still held when the test ends.
func pacedStatusPVE(t *testing.T, answer func(vmid, nth int) time.Duration) *pve.Client {
	t.Helper()
	release := make(chan struct{})
	var mu sync.Mutex
	reads := map[int]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var vmid int
		if _, err := fmt.Sscanf(r.URL.Path[strings.Index(r.URL.Path, "/qemu/"):], "/qemu/%d/status/current", &vmid); err != nil {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		reads[vmid]++
		nth := reads[vmid]
		mu.Unlock()
		delay := answer(vmid, nth)
		if delay < 0 {
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		select {
		case <-time.After(delay):
			_, _ = w.Write([]byte(`{"data":{"status":"running","qmpstatus":"running"}}`))
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) }) // runs before server.Close
	return pve.NewClient(pve.Config{BaseURL: server.URL})
}

func setStatusReadTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := vmStatusReadTimeout
	vmStatusReadTimeout = d
	t.Cleanup(func() { vmStatusReadTimeout = old })
}

// within runs f and fails the test if it has not returned by limit: a read
// with no bound holds its caller, and the test must say so and not wait for it.
func within(t *testing.T, limit time.Duration, what string, f func()) time.Duration {
	t.Helper()
	started := time.Now()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s: not back after %s; a status read the PVE never answers has no bound", what, limit)
	}
	return time.Since(started)
}

// observeVM is what a probe stage's halt watch reads a VM with. Its read is
// bounded by vmStatusReadTimeout, not by the PVE client's minute.
func TestObserveVMBoundsItsReadByTheStatusReadTimeout(t *testing.T) {
	setStatusReadTimeout(t, 150*time.Millisecond)
	o := New(&config.Plan{}, Options{NodeName: "pve1"}, nil, pacedStatusPVE(t, func(int, int) time.Duration { return -1 }))
	obs := &vmObservation{started: time.Now()}
	elapsed := within(t, 5*time.Second, "observeVM", func() { _ = o.observeVM(context.Background(), 100, obs) })
	if elapsed < 100*time.Millisecond {
		t.Errorf("the read of a PVE that never answers ended after %s, before its budget", elapsed)
	}
	if obs.reads != 1 || obs.failed != 1 || obs.ok() {
		t.Fatalf("a read that timed out was taken for evidence: %+v", obs)
	}
}

// watchVMs bounds every read of a wait by the status read timeout, for a VM
// that was never read as for any other. With a PVE that never answers, a
// wait of 60 ms over three VMs ends when each has had its budget, and fails
// each as unobservable.
func TestWatchVMsBoundsEachReadAndFailsTheVMsItCouldNotRead(t *testing.T) {
	fastHaltPolls(t)
	setStatusReadTimeout(t, 120*time.Millisecond)
	o := New(&config.Plan{}, Options{NodeName: "pve1"}, nil, pacedStatusPVE(t, func(int, int) time.Duration { return -1 }))
	var halted map[int]error
	var observed map[int]*vmObservation
	var err error
	elapsed := within(t, 10*time.Second, "watchVMs", func() {
		halted, observed, err = o.watchVMs(context.Background(), 60*time.Millisecond, []int{101, 102, 103}, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, vmid := range []int{101, 102, 103} {
		if got := halted[vmid]; got == nil || !strings.Contains(got.Error(), "could not be read from PVE") {
			t.Errorf("VM %d: %v, want it failed as unobservable", vmid, got)
		}
		if observed[vmid].ok() || observed[vmid].failed == 0 {
			t.Errorf("VM %d: %+v", vmid, observed[vmid])
		}
	}
	// Three VMs, each with a budget of its own: not instantly (the budget of a
	// VM that was never read is its own), and not a minute.
	if elapsed < 300*time.Millisecond || elapsed > 4*time.Second {
		t.Errorf("the wait took %s; three reads of 120 ms each were to be waited out", elapsed)
	}
}

// A PVE that answers every read correctly, but slowly, and a tier of VMs
// whose reads, one after another, outlast one budget. Each VM's only read of a
// wait shorter than the poll interval is the final round's, and the later VMs
// must not get only what is left of one shared budget (nothing) and fail as
// "none of the 1 status read(s) in this 0s wait succeeded". Eight VMs at
// 200 ms against one second: every read is a fifth of the budget, and the
// eight together outlast it.
func TestAFinalRoundOfSlowButHealthyReadsFailsNoVM(t *testing.T) {
	fastHaltPolls(t)
	setStatusReadTimeout(t, time.Second)
	vmids := []int{201, 202, 203, 204, 205, 206, 207, 208}
	o := New(&config.Plan{}, Options{NodeName: "pve1"}, nil, pacedStatusPVE(t, func(int, int) time.Duration { return 200 * time.Millisecond }))
	var halted map[int]error
	var observed map[int]*vmObservation
	var err error
	elapsed := within(t, 30*time.Second, "watchVMs", func() {
		halted, observed, err = o.watchVMs(context.Background(), 0, vmids, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, vmid := range vmids {
		if halted[vmid] != nil {
			t.Errorf("VM %d, healthy and answered in full, was failed: %v", vmid, halted[vmid])
		}
		if obs := observed[vmid]; obs.reads != 1 || obs.failed != 0 || !obs.ok() {
			t.Errorf("VM %d: %+v, want the one read to have succeeded", vmid, obs)
		}
	}
	// The reads must have run one after another for longer than one budget,
	// or the case was not built.
	if elapsed < 8*180*time.Millisecond && !t.Failed() {
		t.Errorf("the wait took %s: the eight slow reads did not run one after another, and this test builds nothing", elapsed)
	}
}

// For a VM that has been read, the final rounds are bounded as one: a PVE that
// stops answering after its first answer holds a wait of 150 ms over three
// VMs for the wait and one status read timeout, not for one timeout per VM.
func TestTheFinalRoundIsBoundedAsAWholeForVMsAlreadyRead(t *testing.T) {
	setStatusReadTimeout(t, 400*time.Millisecond)
	old := haltPollInterval
	haltPollInterval = 50 * time.Millisecond
	t.Cleanup(func() { haltPollInterval = old })
	o := New(&config.Plan{}, Options{NodeName: "pve1"}, nil, pacedStatusPVE(t, func(_, nth int) time.Duration {
		if nth == 1 {
			return 0
		}
		return -1
	}))
	var halted map[int]error
	var err error
	const wait = 150 * time.Millisecond
	elapsed := within(t, 30*time.Second, "watchVMs", func() {
		halted, _, err = o.watchVMs(context.Background(), wait, []int{301, 302, 303}, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(halted) != 0 {
		t.Errorf("VMs that were read were failed: %v", halted)
	}
	// The wait and one budget, and slack for a loaded machine; three budgets in
	// turn would be at least 1.35 s.
	if limit := wait + 400*time.Millisecond + 450*time.Millisecond; elapsed > limit {
		t.Errorf("the wait took %s, more than the %s of the wait and one status read timeout: each hung read had a budget of its own", elapsed, limit)
	}
}
