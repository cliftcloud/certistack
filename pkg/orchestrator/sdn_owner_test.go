// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// The run journals the marker its VNet carries before it creates the
// VNet, and PVE's VNet has it.
func TestRunMarksItsVNetAndJournalsTheMarker(t *testing.T) {
	fake := sdntest.New()
	stateDir := t.TempDir()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
	orch.hostAddresses = &fakeHostAddressManager{}
	var sawAlias string
	var journaledBeforeCreate string
	fake.OnRequest = func(method, path string, query map[string]string) {
		if method == "POST" && path == "cluster/sdn/vnets" {
			record, _ := journal.Load(stateDir + "/active.json")
			journaledBeforeCreate = record.SDNOwner
			sawAlias = query["alias"]
		}
	}
	if _, err := orch.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sawAlias, "certistack ") || sawAlias != journaledBeforeCreate {
		t.Fatalf("VNet created with alias %q, journal held %q before the request; want the same marker", sawAlias, journaledBeforeCreate)
	}
}

// Another VNet under the run's VNet's name turns up before teardown
// (an administrator's, or another run's). Teardown leaves it, and its subnets,
// alone, and reports it; the journal keeps the objects.
func TestTeardownLeavesAReplacementVNetAlone(t *testing.T) {
	fake := sdntest.New()
	fake.Fault("POST cluster/sdn/lock", sdntest.Fault{}) // setup's lock
	fake.Fault("POST cluster/sdn/lock", sdntest.Fault{Before: func() {
		fake.Do(func(p *sdntest.PVE) { p.Aliases["csVn01"] = "an administrator's VNet" })
	}})
	stateDir := t.TempDir()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
	orch.hostAddresses = &fakeHostAddressManager{}
	res, err := orch.Run(context.Background())
	if err != nil && res == nil {
		t.Fatal(err)
	}
	for _, w := range fake.Writes() {
		if strings.HasPrefix(w, "DELETE cluster/sdn/vnets") {
			t.Fatalf("teardown deleted a VNet that is not the run's: %s", w)
		}
		// The zone has no marker of its own: with its VNet refused, it stays
		// too, rather than resting on PVE's "zone is used by vnet" refusal.
		if strings.HasPrefix(w, "DELETE cluster/sdn/zones") {
			t.Fatalf("teardown deleted the zone of a VNet that is not the run's: %s", w)
		}
	}
	var vnet string
	var subnets int
	var zone bool
	fake.Do(func(p *sdntest.PVE) {
		vnet, subnets, zone = p.VNets["csVn01"], len(p.Subnets["csVn01"]), p.Zones["csSb01"]
	})
	if vnet == "" || subnets != 1 || !zone {
		t.Fatalf("the replacement VNet or its zone was changed: vnet %q, subnets %d, zone %v", vnet, subnets, zone)
	}
	if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned ||
		!strings.Contains(strings.Join(res.TeardownEvidence.CleanupErrors, "\n"), "cannot show that it is the interrupted run's") ||
		!strings.Contains(strings.Join(res.TeardownEvidence.CleanupErrors, "\n"), "SDN zone csSb01 was left in place") {
		t.Fatalf("evidence %+v; want the VNet reported as not provably the run's, and the zone left with it", res.TeardownEvidence)
	}
	record, _ := journal.Load(stateDir + "/active.json")
	if record.Phase == "cleaned" || len(record.SDNVNets) != 1 || record.SDNLockToken != "" {
		t.Fatalf("journal %+v; want the VNet kept and no lock held", record)
	}
}
