// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// runningApply is a reloadnetworkall task PVE still runs.
func runningApply() map[string]interface{} {
	return map[string]interface{}{"type": "reloadnetworkall", "endtime": 0, "upid": "UPID:node1:00000001:1:1:reloadnetworkall::root@pam:"}
}

// The setup apply's reply is lost while its task still runs. Teardown
// deletes under a new lock and applies nothing over the running apply, and the
// journal records both the lock and the unknown apply, so that the recovery
// the controller runs at once does not apply over it either.
func TestLostSetupApplyWhileItRunsLeavesTheDeletionsLockedAndJournaled(t *testing.T) {
	fake := sdntest.New()
	fake.Fault("PUT cluster/sdn", sdntest.Fault{Lose: true})
	fake.Tasks = []map[string]interface{}{runningApply()}
	stateDir := t.TempDir()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
	orch.sdnMgr.SetApplyWait(time.Millisecond)
	orch.hostAddresses = &fakeHostAddressManager{}
	res, err := orch.Run(context.Background())
	if err == nil || res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned {
		t.Fatalf("Run = %v, evidence %+v; want an unclean teardown", err, res.TeardownEvidence)
	}
	if fake.Applies != 1 {
		t.Fatalf("applies = %d; want only the lost setup apply, none over it", fake.Applies)
	}
	record, _ := journal.Load(stateDir + "/active.json")
	if record.Phase != "cleanup_failed" || record.SDNLockToken != "tok-2" || record.SDNApplyUnknown == "" {
		t.Fatalf("journal %+v; want the new lock and the unknown apply journaled", record)
	}
	if !strings.Contains(strings.Join(res.TeardownEvidence.CleanupErrors, "\n"), "outcome is unknown") {
		t.Fatalf("cleanup errors %v; want the unknown apply named", res.TeardownEvidence.CleanupErrors)
	}
}

// Teardown's lock request gets a gateway 503 (not PVE's answer, so no
// lock is known). Nothing promises a deletion an apply, and one left pending
// blocks every SDN lock in the cluster: the zone and VNet stay in place for
// recovery, which deletes and applies them under a lock.
func TestTeardownLeavesTheSandboxInPlaceWhenTheLockCannotBeTaken(t *testing.T) {
	fake := sdntest.New()
	fake.Fault("POST cluster/sdn/lock", sdntest.Fault{}) // setup's lock: fine
	fake.Fault("POST cluster/sdn/lock", sdntest.Fault{Refuse: "Service Unavailable", Status: http.StatusServiceUnavailable})
	stateDir := t.TempDir()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
	orch.hostAddresses = &fakeHostAddressManager{}
	res, err := orch.Run(context.Background())
	if err != nil && res == nil {
		t.Fatal(err)
	}
	if fake.Pending() {
		t.Fatalf("teardown made a deletion nothing will apply: writes %v", fake.Writes())
	}
	for _, w := range fake.Writes() {
		if strings.HasPrefix(w, "DELETE cluster/sdn/vnets") || strings.HasPrefix(w, "DELETE cluster/sdn/zones") {
			t.Fatalf("teardown deleted without a lock: %s", w)
		}
	}
	if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned ||
		!strings.Contains(strings.Join(res.TeardownEvidence.CleanupErrors, "\n"), "left in place") {
		t.Fatalf("evidence %+v; want the objects reported left in place", res.TeardownEvidence)
	}
	record, _ := journal.Load(stateDir + "/active.json")
	if record.Phase != "cleanup_failed" || len(record.SDNZones) != 1 || len(record.SDNVNets) != 1 {
		t.Fatalf("journal %+v; want the zone and VNet kept for recovery", record)
	}
}

// A subnet's deletion is made and the VNet's own is refused. The
// deletion is a change of a running VNet: teardown applies it under the lock it
// holds, rather than releasing the lock over a pending deletion (which blocks
// every SDN lock in the cluster), and waits for no bridge that stays.
func TestTeardownAppliesAPartialDeletionInsteadOfUnlockingOverIt(t *testing.T) {
	fake := sdntest.New()
	fake.Fault("DELETE cluster/sdn/vnets/csVn01", sdntest.Fault{Refuse: "delete sdn vnet object failed: cfs-lock 'domain-sdn' error: got lock request timeout"})
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), fake.Serve(t))
	hosts := &fakeHostAddressManager{}
	orch.hostAddresses = hosts
	res, _ := orch.Run(context.Background())
	var lock string
	fake.Do(func(p *sdntest.PVE) { lock = p.Lock })
	if lock != "" || fake.Pending() {
		t.Fatalf("lock %q, pending %v; want the subnet's deletion applied and no lock kept", lock, fake.Pending())
	}
	if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned {
		t.Fatalf("evidence %+v; the VNet that stays is not clean", res.TeardownEvidence)
	}
	if strings.Contains(strings.Join(hosts.bridges, ";"), "present=false") {
		t.Fatalf("teardown waited for a bridge that stays: %v", hosts.bridges)
	}
}
