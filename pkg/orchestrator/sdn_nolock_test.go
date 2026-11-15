// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/sdn"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// PVE 8.4.0 has no /cluster/sdn/lock: the ephemeral sandbox network is
// created, applied, deleted and applied again with no lock, against sdntest's
// PVE 8 mode, whose writes and applies refuse a lock-token or release-lock
// parameter as PVE 8's schema does.

// withShortLockWait bounds the run's wait for a lock to 3 s, so that a run
// that waits for a lock PVE 8 does not have fails its test at once instead of
// idling for the default 2 minutes.
func withShortLockWait(orch *Orchestrator) *Orchestrator {
	orch.sdnMgr.SetLockWait(3 * time.Second)
	return orch
}

// pve8Fake is a PVE 8 whose lock path is answered with status (501 when 0).
func pve8Fake(status int) *sdntest.PVE {
	fake := sdntest.New()
	fake.NoLockAPI, fake.NoLockStatus = true, status
	return fake
}

// noLockSetupWrites are the run's SDN writes up to and including its first
// apply on a PVE without a lock: the one probe, and no lock parameter.
var noLockSetupWrites = []string{
	`POST cluster/sdn/lock`,
	`POST cluster/sdn/zones {"ipam":"pve","nodes":"localhost","type":"simple","zone":"csSb01"}`,
	`POST cluster/sdn/vnets {"alias":"MARKER","vnet":"csVn01","zone":"csSb01"}`,
	`POST cluster/sdn/vnets/csVn01/subnets {"subnet":"10.100.0.0/24","type":"subnet"}`,
	`PUT cluster/sdn`,
}

// noLockTeardownWrites are the deletions and the apply, with no lock.
var noLockTeardownWrites = []string{
	`DELETE cluster/sdn/vnets/csVn01/subnets/csSb01-10.100.0.0-24`,
	`DELETE cluster/sdn/vnets/csVn01`,
	`DELETE cluster/sdn/zones/csSb01`,
	`PUT cluster/sdn`,
}

// captureProgress sends the progress events of the test's process to the
// returned function's result, which also stops the capture.
func captureProgress(t *testing.T) func() []progress.Event {
	t.Helper()
	t.Setenv(progress.EnvironmentEvents, "1")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = writer
	text := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		text <- string(data)
	}()
	stopped := false
	stop := func() []progress.Event {
		if !stopped {
			stopped = true
			os.Stderr = previous
			_ = writer.Close()
		}
		var events []progress.Event
		for _, line := range strings.Split(<-text, "\n") {
			if event, ok := progress.DecodeLine(line); ok {
				events = append(events, event)
			}
		}
		return events
	}
	t.Cleanup(func() {
		if !stopped {
			stop()
		}
	})
	return stop
}

func noLockStatusLines(events []progress.Event) (lines []string) {
	for _, event := range events {
		if strings.Contains(event.Message, "no SDN configuration lock") {
			lines = append(lines, event.Message)
		}
	}
	return lines
}

// watchJournal fails the test when the run's journal, read at each of PVE's
// requests after the first lock request, claims a lock request or a token.
func watchJournal(t *testing.T, fake *sdntest.PVE, stateDir string) {
	t.Helper()
	probed := false
	fake.OnRequest = func(method, path string, _ map[string]string) {
		if method == "POST" && path == "cluster/sdn/lock" {
			probed = true
			return
		}
		if !probed {
			return
		}
		record, err := journal.Load(filepath.Join(stateDir, "active.json"))
		if err != nil {
			return
		}
		if record.SDNLockToken != "" || record.SDNLockRequested != "" {
			t.Errorf("at %s %s the journal claims a lock PVE never granted: token %q, requested %q", method, path, record.SDNLockToken, record.SDNLockRequested)
		}
	}
}

func lockCallsOf(fake *sdntest.PVE) (calls []string) {
	for _, w := range fake.Writes() {
		if _, path, _ := strings.Cut(w, " "); strings.HasPrefix(path, "cluster/sdn/lock") {
			calls = append(calls, w)
		}
	}
	return calls
}

// The default sandbox network works on a PVE 8: no lock is taken, held,
// journaled or released, nothing waits, and the run says once that this PVE
// has none.
func TestEphemeralSandboxOnAPVEWithoutAnSDNLock(t *testing.T) {
	for _, status := range []int{http.StatusNotImplemented, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fake := pve8Fake(status)
			stateDir := t.TempDir()
			watchJournal(t, fake, stateDir)
			orch := withShortLockWait(New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t)))
			hosts := &fakeHostAddressManager{}
			orch.hostAddresses = hosts
			stop := captureProgress(t)
			started := time.Now()
			res, err := orch.Run(context.Background())
			events := stop()
			if elapsed := time.Since(started); elapsed > 30*time.Second {
				t.Fatalf("the run took %v: the missing lock was waited for", elapsed)
			}
			if err != nil || res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned || !res.TeardownEvidence.SDNClusterReloaded {
				t.Fatalf("Run = %v, evidence %+v", err, res.TeardownEvidence)
			}
			if got := strings.Join(hosts.bridges, "; "); got != "settle csVn01 present=true; no-forwarding csVn01; settle csVn01 present=false" {
				t.Fatalf("bridge steps = %s", got)
			}
			want := strings.Join(append(append([]string(nil), noLockSetupWrites...), noLockTeardownWrites...), "\n")
			if got := strings.Join(writesOf(fake), "\n"); got != want {
				t.Fatalf("SDN writes:\n%s\nwant:\n%s", got, want)
			}
			if calls := lockCallsOf(fake); len(calls) != 1 {
				t.Fatalf("lock calls %v; want the one probe", calls)
			}
			if left := sandboxLeft(fake); len(left) > 0 || fake.Pending() {
				t.Fatalf("PVE keeps %v, pending %v", left, fake.Pending())
			}
			record, err := journal.Load(filepath.Join(stateDir, "active.json"))
			if err != nil || record.Phase != "cleaned" || record.SDNLockToken != "" || record.SDNLockRequested != "" {
				t.Fatalf("journal = %+v, %v; want cleaned with no lock held or requested", record, err)
			}
			if lines := noLockStatusLines(events); len(lines) != 1 || !strings.Contains(lines[0], "PVE 8") {
				t.Fatalf("status lines about the missing lock: %q; want one", lines)
			}
		})
	}
}

// A PVE with a lock says nothing about one, and keeps its lock parameters.
func TestEphemeralSandboxOnAPVEWithAnSDNLockSaysNothingOfOne(t *testing.T) {
	fake := sdntest.New()
	orch := withShortLockWait(New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), fake.Serve(t)))
	orch.hostAddresses = &fakeHostAddressManager{}
	stop := captureProgress(t)
	if _, err := orch.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lines := noLockStatusLines(stop()); len(lines) != 0 {
		t.Fatalf("status lines about a missing lock on a PVE that has one: %q", lines)
	}
	if !strings.Contains(strings.Join(fake.Writes(), "\n"), `"lock-token":"tok-1"`) {
		t.Fatalf("writes carry no token: %v", fake.Writes())
	}
}

// A startup failure after the first apply tears down with no lock, in the same
// order, and asks PVE for no lock again.
func TestStartupFailureAfterTheFirstApplyTearsDownOnAPVEWithoutALock(t *testing.T) {
	for _, failAt := range []string{"settle", "forwarding"} {
		t.Run(failAt, func(t *testing.T) {
			fake := pve8Fake(0)
			stateDir := t.TempDir()
			watchJournal(t, fake, stateDir)
			orch := withShortLockWait(New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t)))
			orch.hostAddresses = &failingBridges{failAt: failAt}
			res, err := orch.Run(context.Background())
			if err == nil {
				t.Fatal("the startup failure was not reported")
			}
			want := strings.Join(append(append([]string(nil), noLockSetupWrites...), noLockTeardownWrites...), "\n")
			if got := strings.Join(writesOf(fake), "\n"); got != want {
				t.Fatalf("SDN writes:\n%s\nwant:\n%s", got, want)
			}
			if res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned || !res.TeardownEvidence.SDNClusterReloaded || len(sandboxLeft(fake)) > 0 {
				t.Fatalf("evidence %+v, left %v; want a clean teardown", res.TeardownEvidence, sandboxLeft(fake))
			}
		})
	}
}

// An unapplied change of an administrator's refuses the run before it creates
// anything, though PVE has no lock to refuse it with.
func TestEphemeralSandboxOnAPVEWithoutALockRefusedOverPendingSDNChanges(t *testing.T) {
	fake := pve8Fake(0)
	fake.Zones["prodZ"] = true
	orch := withShortLockWait(New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), fake.Serve(t)))
	orch.hostAddresses = &fakeHostAddressManager{}
	_, err := orch.Run(context.Background())
	if !errors.Is(err, sdn.ErrPendingSDNChanges) || !strings.Contains(err.Error(), "zone prodZ (new)") {
		t.Fatalf("Run = %v, want a refusal naming the pending change", err)
	}
	if got := strings.Join(fake.Writes(), "\n"); got != "POST cluster/sdn/lock" {
		t.Fatalf("the run wrote SDN after the refusal:\n%s", got)
	}
}

// A change that appears during the run keeps teardown from deleting or applying
// anything: without PVE's lock the manager's own read of the pending
// changes is what holds it back. The sandbox stays for recovery.
func TestEphemeralTeardownOnAPVEWithoutALockWritesNothingOverPendingSDNChanges(t *testing.T) {
	fake := pve8Fake(0)
	stateDir := t.TempDir()
	orch := withShortLockWait(New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t)))
	orch.hostAddresses = &failingBridges{failAt: "settle", onFail: func() {
		fake.Do(func(p *sdntest.PVE) { p.Zones["prodZ"] = true })
	}}
	res, _ := orch.Run(context.Background())
	var applies int
	var committed bool
	fake.Do(func(p *sdntest.PVE) { applies, committed = p.Applies, p.RunningZones["prodZ"] })
	if applies != 1 || committed {
		t.Fatalf("applies %d, administrator's zone committed %v; want no apply after the first", applies, committed)
	}
	for _, w := range writesOf(fake)[len(noLockSetupWrites):] {
		t.Fatalf("teardown wrote to SDN over an administrator's pending change: %s", w)
	}
	if left := strings.Join(sandboxLeft(fake), " "); !strings.Contains(left, "zone") || !strings.Contains(left, "vnet") {
		t.Fatalf("SDN left %q; want the zone and VNet still there", left)
	}
	if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned || res.TeardownEvidence.SDNClusterReloaded ||
		!strings.Contains(strings.Join(res.TeardownEvidence.CleanupErrors, "\n"), "left in place") {
		t.Fatalf("evidence %+v; want the objects reported left in place", res.TeardownEvidence)
	}
	record, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil || record.Phase != "cleanup_failed" || record.SDNLockToken != "" || record.SDNLockRequested != "" ||
		len(record.SDNZones) != 1 || len(record.SDNVNets) != 1 || record.SDNOwner == "" {
		t.Fatalf("journal %+v, %v; want the zone, VNet and owner marker kept for recovery, and no lock claimed", record, err)
	}
}

// Nothing could be deleted: no apply, and still no lock call.
func TestEphemeralTeardownOnAPVEWithoutALockAppliesNothingWhenNothingWasDeleted(t *testing.T) {
	fake := pve8Fake(0)
	fake.Fault("DELETE cluster/sdn/vnets/csVn01/subnets/csSb01-10.100.0.0-24", sdntest.Fault{Refuse: "delete sdn subnet object failed: permission denied"})
	stateDir := t.TempDir()
	orch := withShortLockWait(New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t)))
	hosts := &fakeHostAddressManager{}
	orch.hostAddresses = hosts
	res, _ := orch.Run(context.Background())
	if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned || res.TeardownEvidence.SDNClusterReloaded {
		t.Fatalf("evidence = %+v, want the failed deletion reported", res.TeardownEvidence)
	}
	writes := writesOf(fake)
	if tail := strings.Join(writes[len(noLockSetupWrites):], "\n"); strings.Contains(tail, "PUT") || strings.Contains(tail, "lock") {
		t.Fatalf("teardown SDN writes:\n%s\nwant the deletions only", tail)
	}
	record, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil || record.SDNLockToken != "" || record.SDNLockRequested != "" || record.Phase != "cleanup_failed" {
		t.Fatalf("journal = %+v, %v; want cleanup_failed, no lock claimed", record, err)
	}
}

// PVE 8 has no SDN lock to keep another client's creations out while the run
// makes its own. A zone of the plan's name that appears after the availability
// check and that PVE never applied is not provably the run's: where the run's
// creation was refused, teardown leaves it in place and reports it as not
// confirmed as the run's, instead of deleting it because it is new.
func TestNoLockTeardownLeavesAForeignNeverAppliedZoneWhereTheRunsCreationWasRefused(t *testing.T) {
	fake := pve8Fake(0)
	fake.Fault("POST cluster/sdn/zones", sdntest.Fault{
		Before: func() { fake.Do(func(p *sdntest.PVE) { p.Zones["csSb01"] = true }) },
		Refuse: "create sdn zone object failed: sdn zone object ID 'csSb01' already defined",
	})
	stateDir := t.TempDir()
	orch := withShortLockWait(New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t)))
	orch.hostAddresses = &fakeHostAddressManager{}
	res, err := orch.Run(context.Background())
	if err == nil {
		t.Fatal("the refused creation was not reported")
	}
	for _, w := range fake.Writes() {
		if strings.HasPrefix(w, "DELETE cluster/sdn/zones") || strings.HasPrefix(w, "PUT") {
			t.Fatalf("teardown changed SDN on a PVE without a lock after the run's zone creation was refused: %s", w)
		}
	}
	var zone bool
	fake.Do(func(p *sdntest.PVE) { zone = p.Zones["csSb01"] })
	if !zone {
		t.Fatal("the other client's never-applied zone was deleted")
	}
	if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned ||
		!strings.Contains(strings.Join(res.TeardownEvidence.CleanupErrors, "\n"), "cannot show that it is the interrupted run's") {
		t.Fatalf("evidence %+v; want the zone reported as not confirmed as the run's", res.TeardownEvidence)
	}
	record := journalIn(t, stateDir)
	if record.Phase == "cleaned" || record.AllocationPending != "SDN zone csSb01" {
		t.Fatalf("journal %+v; want the allocation still pending, visibly unresolved", record)
	}
}
