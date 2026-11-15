//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

// Linux-only for the reason soak_run_linux_test.go gives: Run starts with the
// host's admission check, which reads the node's /proc counters.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// phaseRecorder collects the phase lines of a run.
func phaseRecorder(o *Orchestrator) *[]string {
	var lines []string
	o.phaseFn = func(stage, message string) { lines = append(lines, stage+" | "+message) }
	return &lines
}

func sameLines(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("phase lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A run that passes announces the phases of its tier as it reaches them (the
// restore and the boot are the VM's own and are announced inside the restore:
// this run's VM comes up as a test double, and those phases are passed over
// without taking another's number), and the teardown last but one.
func TestRunAnnouncesTheTiersPhasesAndTheTeardown(t *testing.T) {
	soakFast(t, 100*time.Millisecond)
	plan, client := soakRunPlan(t, 1)
	plan.Tiers[0].StartupGracePeriodSec = 1
	dir := shortSocketDir(t)
	guestAgent(t, dir, -1)
	orch := soakRunOrchestrator(t, plan, client, dir)
	lines := phaseRecorder(orch)

	res, err := orch.Run(context.Background())
	if err != nil || res == nil || !res.AllPassed {
		t.Fatalf("run: res=%+v err=%v", res, err)
	}
	// admission, network, restore, integrity, boot, grace, probes, soak, teardown, signing.
	sameLines(t, *lines,
		"Phase 1 of 10 | Admission checks: node support and host capacity",
		"Phase 2 of 10 | Isolated sandbox network",
		"Phase 6 of 10 | Start-up grace period for tier 1: 1 s",
		"Phase 7 of 10 | Service probes for VM 9101 (app)",
		"Phase 8 of 10 | Soak for tier 1: 1 s",
		"Phase 9 of 10 | Teardown, then a check that nothing of the run is left",
	)
}

// A run that fails goes on to its teardown with the number that phase has in the
// plan, and says nothing of the phases it never reached.
func TestRunThatFailsAnnouncesItsTeardownWithItsPlace(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, `{"data":null,"message":"synthetic SDN refusal"}`, http.StatusBadRequest)
	}))
	defer server.Close()
	plan := networkOnlyPlan()
	plan.PlanID = "failed-sdn-phases"
	o := New(plan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
	o.hostAddresses = &fakeHostAddressManager{}
	lines := phaseRecorder(o)

	if _, err := o.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "SDN sandbox setup failed") {
		t.Fatalf("run = %v, want the SDN setup refused", err)
	}
	if requests.Load() == 0 {
		t.Fatal("the SDN setup never reached PVE")
	}
	// The plan has no tier: admission, network, teardown, signing.
	sameLines(t, *lines,
		"Phase 1 of 4 | Admission checks: node support and host capacity",
		"Phase 2 of 4 | Isolated sandbox network",
		"Phase 3 of 4 | Teardown, then a check that nothing of the run is left",
	)
}

// A run cancelled during a tier's start-up grace wait ends the wait at once
// (not after the 600 s it was given), records the tier's VM as incomplete with
// the reason, tears the sandbox down and verifies the cleanup. The wait itself
// was tested on its own (waitWatchingVMs); this is the whole run.
func TestRunCancelledDuringTheStartupGraceEndsTheWaitAndCleansUp(t *testing.T) {
	plan, client := soakRunPlan(t, 0)
	plan.Tiers[0].StartupGracePeriodSec = 600
	dir := shortSocketDir(t)
	guestAgent(t, dir, -1)
	orch := soakRunOrchestrator(t, plan, client, dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lines []string
	orch.phaseFn = func(stage, message string) {
		lines = append(lines, stage+" | "+message)
		if strings.HasPrefix(message, "Start-up grace period") {
			cancel()
		}
	}
	done := make(chan struct{})
	var res *ExecutionResult
	var err error
	go func() {
		defer close(done)
		res, err = orch.Run(ctx)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Minute): // a hang guard only
		t.Fatal("the run did not end after its cancellation during the grace wait")
	}
	if err == nil || !errors.Is(err, context.Canceled) || res == nil || res.AllPassed {
		t.Fatalf("run: res=%+v err=%v", res, err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "Start-up grace period for tier 1: 600 s") {
		t.Fatalf("the grace wait never began:\n%s", strings.Join(lines, "\n"))
	}
	record := res.VMRecords[0]
	if record.VerificationStatus != "incomplete" || len(record.ProbeResults) != 1 ||
		!strings.Contains(record.ProbeResults[0].Error, "validation interrupted before probes were run") {
		t.Fatalf("the VM's record = %+v", record)
	}
	if res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned {
		t.Fatalf("the sandbox was not torn down and verified: %+v", res.TeardownEvidence)
	}
	if res.PhaseTimings == nil || res.PhaseTimings.StartupGracePeriodSec > 60 {
		t.Fatalf("the grace wait was not cut short: %+v", res.PhaseTimings)
	}
}
