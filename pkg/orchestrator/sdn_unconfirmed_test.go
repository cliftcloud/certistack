// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

func runAgainst(t *testing.T, fake *sdntest.PVE) (*ExecutionResult, string, error) {
	t.Helper()
	stateDir := t.TempDir()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
	orch.hostAddresses = &fakeHostAddressManager{}
	res, err := orch.Run(context.Background())
	return res, stateDir, err
}

func journalIn(t *testing.T, stateDir string) journal.Record {
	t.Helper()
	record, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// The reported case: the reply to the zone's or the VNet's creation is
// lost after PVE made the object. The run used to end with the object pending,
// the lock released, and a journal that recovery could not settle. The zone and
// VNet are journaled before their creations are sent, so teardown deletes
// whatever the lost request made, under the lock the run still holds, applies,
// and settles the allocation from PVE's own lists.
func TestLostCreateReplyIsSettledByTeardown(t *testing.T) {
	for _, create := range []string{"POST cluster/sdn/zones", "POST cluster/sdn/vnets"} {
		t.Run(create, func(t *testing.T) {
			fake := sdntest.New()
			fake.Fault(create, sdntest.Fault{Lose: true})
			res, stateDir, err := runAgainst(t, fake)
			if err == nil {
				t.Fatal("the lost reply was not reported")
			}
			if left := sandboxLeft(fake); len(left) > 0 || fake.Pending() {
				t.Fatalf("PVE keeps %v (pending %v) after the run; want nothing of the sandbox, no lock, nothing pending", left, fake.Pending())
			}
			if res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned || !res.TeardownEvidence.SDNClusterReloaded {
				t.Fatalf("evidence %+v; want a clean teardown", res.TeardownEvidence)
			}
			record := journalIn(t, stateDir)
			if record.Phase != "cleaned" || record.AllocationPending != "" || record.SDNLockToken != "" || record.SDNLockRequested != "" {
				t.Fatalf("journal %+v; want cleaned, with the allocation settled and no lock", record)
			}
			// The deletions and the apply carry the lock the run took; the run
			// takes no second lock and PVE is left with nothing pending.
			locks, deletes := 0, 0
			for _, w := range fake.Writes() {
				switch {
				case strings.HasPrefix(w, "POST cluster/sdn/lock"):
					locks++
				case strings.HasPrefix(w, "DELETE cluster/sdn/zones") || strings.HasPrefix(w, "DELETE cluster/sdn/vnets"):
					deletes++
					if !strings.Contains(w, "lock-token=tok-1") {
						t.Fatalf("a deletion without the run's lock: %s", w)
					}
				}
			}
			if locks != 1 || deletes == 0 {
				t.Fatalf("locks %d, deletes %d in %v; want the one lock and the deletions under it", locks, deletes, fake.Writes())
			}
		})
	}
}

// The zone and the VNet are journaled before the request that creates
// them is sent, with the marker and the lock, so a crash at that point leaves
// a journal that names what the request may have made.
func TestSDNCreationsAreJournaledBeforeTheyAreSent(t *testing.T) {
	fake := sdntest.New()
	stateDir := t.TempDir()
	var atZone, atVNet journal.Record
	fake.OnRequest = func(method, path string, _ map[string]string) {
		if method != "POST" {
			return
		}
		switch path {
		case "cluster/sdn/zones":
			atZone, _ = journal.Load(filepath.Join(stateDir, "active.json"))
		case "cluster/sdn/vnets":
			atVNet, _ = journal.Load(filepath.Join(stateDir, "active.json"))
		}
	}
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
	orch.hostAddresses = &fakeHostAddressManager{}
	if _, err := orch.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(atZone.SDNZones, ",") != "csSb01" || len(atZone.SDNVNets) != 0 || atZone.AllocationPending != "SDN zone csSb01" ||
		atZone.SDNOwner == "" || atZone.SDNLockToken != "tok-1" {
		t.Fatalf("journal when the zone request arrived: %+v; want the zone, the marker and the lock, with its creation unconfirmed", atZone)
	}
	if strings.Join(atVNet.SDNVNets, ",") != "csVn01" || atVNet.AllocationPending != "SDN VNet csVn01" || atVNet.SDNOwner != atZone.SDNOwner {
		t.Fatalf("journal when the VNet request arrived: %+v; want the VNet with its creation unconfirmed", atVNet)
	}
	if record := journalIn(t, stateDir); record.AllocationPending != "" {
		t.Fatalf("journal at the end %+v; want no allocation pending", record)
	}
}

// A zone create that PVE refused because a zone of that name was made
// (and applied) by someone else after the availability check is theirs. The
// creation being unconfirmed makes teardown read PVE, not delete: a zone PVE
// runs that the run never applied is left alone and reported.
func TestTeardownLeavesAZoneSomeoneElseMadeWhereTheRunsCreationWasRefused(t *testing.T) {
	fake := sdntest.New()
	fake.Fault("POST cluster/sdn/zones", sdntest.Fault{
		Before: func() {
			fake.Do(func(p *sdntest.PVE) { p.Zones["csSb01"], p.RunningZones["csSb01"] = true, true })
		},
		Refuse: "create sdn zone object failed: sdn zone object ID 'csSb01' already defined",
	})
	res, stateDir, err := runAgainst(t, fake)
	if err == nil {
		t.Fatal("the refused creation was not reported")
	}
	for _, w := range fake.Writes() {
		if strings.HasPrefix(w, "DELETE cluster/sdn/zones") || strings.HasPrefix(w, "PUT") {
			t.Fatalf("teardown changed SDN after the run's zone creation was refused: %s", w)
		}
	}
	var zone bool
	fake.Do(func(p *sdntest.PVE) { zone = p.Zones["csSb01"] && p.RunningZones["csSb01"] })
	if !zone {
		t.Fatal("the other party's zone was deleted")
	}
	if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned ||
		!strings.Contains(strings.Join(res.TeardownEvidence.CleanupErrors, "\n"), "cannot show that it is the interrupted run's") {
		t.Fatalf("evidence %+v; want the zone reported as not provably the run's", res.TeardownEvidence)
	}
	record := journalIn(t, stateDir)
	if record.Phase == "cleaned" || record.AllocationPending != "SDN zone csSb01" || record.SDNLockToken != "" {
		t.Fatalf("journal %+v; want the allocation still pending and no lock held", record)
	}
}

// The teardown's check that the sandbox's zone and VNet are gone reads only what
// the run tracks. An unrelated VNet of the plan's VNet name (here one made while
// the run's zone was being refused, so the run never got as far as its own VNet)
// is not the sandbox's, and is not reported as left behind by it.
func TestTeardownDoesNotBlameTheSandboxForAVNetItNeverCreated(t *testing.T) {
	fake := sdntest.New()
	fake.Fault("POST cluster/sdn/zones", sdntest.Fault{
		Before: func() {
			fake.Do(func(p *sdntest.PVE) {
				p.Zones["otherZ"], p.RunningZones["otherZ"] = true, true
				p.VNets["csVn01"], p.RunningVNets["csVn01"] = "otherZ", "otherZ"
			})
		},
		Refuse: "Permission check failed (/sdn/zones/csSb01, SDN.Allocate)", Status: http.StatusForbidden,
	})
	res, _, err := runAgainst(t, fake)
	if err == nil {
		t.Fatal("the refused creation was not reported")
	}
	if res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned {
		t.Fatalf("evidence %+v; want a clean teardown: the VNet is not the sandbox's", res.TeardownEvidence)
	}
	var vnet bool
	fake.Do(func(p *sdntest.PVE) { vnet = p.VNets["csVn01"] != "" })
	if !vnet {
		t.Fatal("the unrelated VNet was touched")
	}
}

// A delete's success reply is not proof that the zone is gone. Teardown
// reads PVE's lists and reports the zone that is still there; the journal is
// not cleaned on the reply.
func TestTeardownConfirmsTheDeletionsInPVEsLists(t *testing.T) {
	fake := sdntest.New()
	fake.Fault("DELETE cluster/sdn/zones/csSb01", sdntest.Fault{Skip: true})
	res, stateDir, _ := runAgainst(t, fake)
	if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned || res.TeardownEvidence.SDNZoneRemoved != "" ||
		!strings.Contains(strings.Join(res.TeardownEvidence.CleanupErrors, "\n"), "PVE still lists the sandbox's SDN zone csSb01") {
		t.Fatalf("evidence %+v; want the zone PVE still lists reported, not claimed removed", res.TeardownEvidence)
	}
	if record := journalIn(t, stateDir); record.Phase == "cleaned" || len(record.SDNZones) != 1 {
		t.Fatalf("journal %+v; want the zone kept for recovery", record)
	}
}
