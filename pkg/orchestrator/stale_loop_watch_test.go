// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

type staleSweep struct {
	called   int
	before   []string
	maps     int
	released []string
	problems []error
}

func newStaleWatchOrchestrator(t *testing.T, baseline []string, sweep *staleSweep) *Orchestrator {
	t.Helper()
	o := New(networkOnlyPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: "http://127.0.0.1:1"}))
	o.staleLoopDevicesFn = func() []string { return baseline }
	o.releaseStaleLoopsFn = func(_ context.Context, before []string, maps int) ([]string, []error) {
		sweep.called++
		sweep.before, sweep.maps = before, maps
		return sweep.released, sweep.problems
	}
	return o
}

// A map is begun with the stale FUSE loops the host already has on record; at
// the end of teardown, with a map that never reported a loop, the loops that
// appeared since are detached, and the loops that were there are not named as
// the baseline's to touch.
func TestAnInterruptedMapsStaleLoopIsReleasedAtTheEndOfTeardown(t *testing.T) {
	sweep := &staleSweep{released: []string{"/dev/loop2"}}
	o := newStaleWatchOrchestrator(t, []string{"/dev/loop9"}, sweep)
	intent := o.record.AddMapIntent("vm/7031/2026-10-05T03:01:20Z", "drive-scsi0.img", `\x3avm-7031-x.img`, time.Now())
	o.beginStaleLoopWatch(intent)

	recorded := o.record.MapIntents[intent]
	if !recorded.StaleLoopsChecked || len(recorded.StaleLoopsBefore) != 1 || recorded.StaleLoopsBefore[0] != "/dev/loop9" {
		t.Fatalf("the journaled baseline is %+v", recorded)
	}
	if failures := o.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures: %v", failures)
	}
	if sweep.called != 1 || len(sweep.before) != 1 || sweep.before[0] != "/dev/loop9" || sweep.maps != 1 {
		t.Fatalf("sweep called %d times with baseline %v and %d unresolved maps; want once, with loop9 and one", sweep.called, sweep.before, sweep.maps)
	}
}

// A map that reported its loop leaves nothing to look for; the sweep does not
// run, and a second map does not register a second sweep.
func TestTheStaleLoopSweepNeedsAMapThatNeverReportedAndRunsOnce(t *testing.T) {
	sweep := &staleSweep{}
	o := newStaleWatchOrchestrator(t, nil, sweep)
	first := o.record.AddMapIntent("vm/1/a", "drive-scsi0.img", `\x3avm-1-a.img`, time.Now())
	o.beginStaleLoopWatch(first)
	second := o.record.AddMapIntent("vm/2/b", "drive-scsi0.img", `\x3avm-2-b.img`, time.Now())
	o.beginStaleLoopWatch(second)
	o.record.ResolveMapIntent(first, "/dev/loop0")
	o.record.ResolveMapIntent(second, "/dev/loop1")
	if failures := o.cleanup.Unwind(); len(failures) != 0 || sweep.called != 0 {
		t.Fatalf("failures %v, sweep called %d times; want a quiet teardown that looked for nothing", failures, sweep.called)
	}

	sweep = &staleSweep{}
	o = newStaleWatchOrchestrator(t, nil, sweep)
	a := o.record.AddMapIntent("vm/1/a", "drive-scsi0.img", `\x3avm-1-a.img`, time.Now())
	o.beginStaleLoopWatch(a)
	b := o.record.AddMapIntent("vm/2/b", "drive-scsi0.img", `\x3avm-2-b.img`, time.Now())
	o.beginStaleLoopWatch(b)
	o.cleanup.Unwind()
	if sweep.called != 1 || sweep.maps != 2 {
		t.Fatalf("two unresolved maps: sweep called %d times with maps=%d; want once and 2", sweep.called, sweep.maps)
	}
}

// A stale loop the run cannot release is a teardown failure, so the run is not
// reported clean.
func TestAStaleLoopThatCannotBeReleasedFailsTheTeardown(t *testing.T) {
	sweep := &staleSweep{problems: []error{errors.New("/dev/loop2 is stuck")}}
	o := newStaleWatchOrchestrator(t, nil, sweep)
	o.beginStaleLoopWatch(o.record.AddMapIntent("vm/1/a", "drive-scsi0.img", `\x3avm-1-a.img`, time.Now()))
	failures := o.cleanup.Unwind()
	if len(failures) != 1 || !strings.Contains(failures[0].Err.Error(), "/dev/loop2 is stuck") {
		t.Fatalf("teardown failures = %v, want the stale loop reported", failures)
	}
	_ = journal.Record{}
	_ = filepath.Join
}
