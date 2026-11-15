//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
)

type staleCalls struct {
	n        int
	baseline []string
	maps     int
	released []string
	problems []error
}

func stubStaleLoops(t *testing.T, c *staleCalls) {
	t.Helper()
	old := releaseStaleLoops
	releaseStaleLoops = func(_ context.Context, before []string, maps int) ([]string, []error) {
		c.n++
		c.baseline, c.maps = before, maps
		return c.released, c.problems
	}
	t.Cleanup(func() { releaseStaleLoops = old })
}

func staleJournal(t *testing.T, mutate func(*journal.Record)) string {
	t.Helper()
	at := time.Now().UTC()
	record := journal.Record{RunID: "run-stale", Phase: "running", UpdatedAt: at}
	idx := record.AddMapIntent("vm/7031/2026-10-05T03:01:20Z", "drive-scsi0.img", `\x3avm-7031-2026\x2d10\x2d05T03\x3a01\x3a20Z-drive\x2dscsi0.img`, at)
	record.SetMapIntentStaleLoops(idx, []string{"/dev/loop9"})
	if mutate != nil {
		mutate(&record)
	}
	stateDir := t.TempDir()
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	return stateDir
}

// A run killed while its first map started leaves a map intent that never saw a
// loop. Recovery looks for the stale FUSE loop that map's daemon attached and
// left, with the baseline the run journaled, and for no more of them than the
// run has such maps.
func TestRecoveryReleasesTheStaleLoopAnInterruptedMapLeft(t *testing.T) {
	calls := &staleCalls{released: []string{"/dev/loop2"}}
	stubStaleLoops(t, calls)
	stateDir := staleJournal(t, nil)
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery = %v", err)
	}
	if calls.n != 1 || len(calls.baseline) != 1 || calls.baseline[0] != "/dev/loop9" || calls.maps != 1 {
		t.Fatalf("release called %d times with baseline %v and %d maps; want once with loop9 and 1", calls.n, calls.baseline, calls.maps)
	}
	if after := journalPhase(t, stateDir); after.Phase != "cleaned" {
		t.Fatalf("journal phase %q after the loop was released, want cleaned", after.Phase)
	}
}

func TestRecoveryLooksForNoStaleLoopWithoutABaselineOrAnUnreportedMap(t *testing.T) {
	for name, mutate := range map[string]func(*journal.Record){
		"a journal with no baseline (an earlier version)": func(r *journal.Record) {
			r.MapIntents[0].StaleLoopsChecked, r.MapIntents[0].StaleLoopsBefore = false, nil
		},
		"every map reported its loop": func(r *journal.Record) {
			r.ResolveMapIntent(0, "/dev/loop0")
			r.AddLoop("/dev/loop0", "/run/pbs-loopdev/x")
		},
	} {
		t.Run(name, func(t *testing.T) {
			calls := &staleCalls{}
			stubStaleLoops(t, calls)
			// A recorded loop that no longer backs anything is released or absent;
			// the point is only that the stale-loop sweep is not asked.
			_ = RecoverLocked(staleJournal(t, mutate))
			if calls.n != 0 {
				t.Fatalf("the sweep ran %d times; want it asked about nothing", calls.n)
			}
		})
	}
}

// A stale loop recovery cannot release leaves the journal unclean, with the
// reason, so the next recovery tries again.
func TestRecoveryKeepsTheJournalWhenAStaleLoopCannotBeReleased(t *testing.T) {
	calls := &staleCalls{problems: []error{errors.New("/dev/loop2 is held by md126")}}
	stubStaleLoops(t, calls)
	stateDir := staleJournal(t, nil)
	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "md126") {
		t.Fatalf("recovery = %v, want the held loop reported", err)
	}
	if after := journalPhase(t, stateDir); after.Phase == "cleaned" {
		t.Fatal("the journal was cleaned with a stale loop left")
	}
}
