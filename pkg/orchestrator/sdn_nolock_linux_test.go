//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/recovery"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// The crash windows on a PVE without an SDN lock: the journal a run really
// writes when its zone's, VNet's or first apply's request is about to be sent
// (or its first deletion) is the image a crash at that instant leaves. Recovery
// of it against PVE 8 settles the SDN with no lock: it releases nothing, sends
// no lock parameter (the fake refuses one), asks PVE for no lock more than
// once, and leaves nothing behind.
func TestRecoveryOfAPVEWithoutALockAtTheMomentARequestIsSent(t *testing.T) {
	type moment struct{ method, path string }
	moments := []moment{
		{"POST", "cluster/sdn/zones"},
		{"POST", "cluster/sdn/vnets"},
		{"POST", "cluster/sdn/vnets/csVn01/subnets"},
		{"PUT", "cluster/sdn"},
		{"DELETE", "cluster/sdn/vnets/csVn01/subnets/csSb01-10.100.0.0-24"},
	}
	// One run, only to capture the journal at each of the requests.
	images := map[moment][]byte{}
	stateDir := t.TempDir()
	probe := pve8Fake(0)
	probe.OnRequest = func(method, path string, _ map[string]string) {
		at := moment{method, path}
		if _, seen := images[at]; !seen {
			images[at], _ = os.ReadFile(filepath.Join(stateDir, "active.json"))
		}
	}
	orch := withShortLockWait(New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), probe.Serve(t)))
	orch.hostAddresses = &fakeHostAddressManager{}
	if _, err := orch.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, at := range moments {
		for _, made := range []bool{true, false} {
			name := at.method + " " + at.path + ", request not processed"
			if made {
				name = at.method + " " + at.path + ", request processed"
			}
			image := images[at]
			t.Run(name, func(t *testing.T) {
				if len(image) == 0 {
					t.Fatal("no journal was captured at the request")
				}
				crashDir := t.TempDir()
				if err := os.WriteFile(filepath.Join(crashDir, "active.json"), image, 0o600); err != nil {
					t.Fatal(err)
				}
				record, err := journal.Load(filepath.Join(crashDir, "active.json"))
				if err != nil {
					t.Fatal(err)
				}
				if record.SDNLockToken != "" {
					t.Fatalf("the journal at the request holds lock %q on a PVE that has none", record.SDNLockToken)
				}

				// PVE as the crash left it. The zone exists by the VNet's
				// request, the VNet (with the run's marker) by the subnet's; the
				// apply and the deletion find everything configured, and the
				// apply's processing makes it run.
				fake := pve8Fake(0)
				zone, vnet, subnet := "csSb01", "csVn01", "csSb01-10.100.0.0-24"
				addZone := func() { fake.Zones[zone] = true }
				addVNet := func() { fake.VNets[vnet], fake.Aliases[vnet] = zone, record.SDNOwner }
				addSubnet := func() { fake.Subnets[vnet] = []string{subnet} }
				run := func() {
					fake.RunningZones[zone], fake.RunningVNets[vnet], fake.RunningSubnets[vnet] = true, zone, []string{subnet}
				}
				switch at.path {
				case "cluster/sdn/zones":
					if made {
						addZone()
					}
				case "cluster/sdn/vnets":
					addZone()
					if made {
						addVNet()
					}
				case "cluster/sdn/vnets/csVn01/subnets":
					addZone()
					addVNet()
					if made {
						addSubnet()
					}
				case "cluster/sdn":
					addZone()
					addVNet()
					addSubnet()
					if made {
						run()
					}
				default:
					addZone()
					addVNet()
					addSubnet()
					run()
					if made {
						// the subnet's deletion went through, unapplied
						delete(fake.Subnets, vnet)
					}
				}
				t.Setenv("PVE_URL", fake.Start(t).URL)
				t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
				t.Setenv("PVE_TOKEN_SECRET", "test-secret")
				t.Setenv("PVE_TLS_INSECURE", "")
				t.Setenv("CERTISTACK_PVE_CA_SOURCE", "")

				if at.path == "cluster/sdn/zones" && made {
					// The one image whose object recovery cannot tell from
					// another client's: a zone that is only configured, never
					// applied, with its creation unconfirmed, and no SDN lock to
					// have held another client's creation of it off. A zone
					// carries no marker, so recovery leaves it and reports
					// it, with the allocation still pending.
					err := recovery.RecoverLocked(crashDir)
					if err == nil || !strings.Contains(err.Error(), "cannot show that it is the interrupted run's") || !strings.Contains(err.Error(), "no SDN lock") {
						t.Fatalf("RecoverLocked = %v; want the zone refused as not confirmed as the run's", err)
					}
					after, _ := journal.Load(filepath.Join(crashDir, "active.json"))
					if left := sandboxLeft(fake); len(left) != 1 || left[0] != "zone" || after.Phase == "cleaned" || after.AllocationPending != "SDN zone csSb01" {
						t.Fatalf("PVE keeps %v; journal %+v; want the zone left in place and the allocation still pending", left, after)
					}
					for _, w := range fake.Writes() {
						if w != "POST cluster/sdn/lock" {
							t.Fatalf("recovery wrote %q beside a zone it could not show to be the run's", w)
						}
					}
					return
				}
				if err := recovery.RecoverLocked(crashDir); err != nil {
					t.Fatalf("RecoverLocked: %v", err)
				}
				after, _ := journal.Load(filepath.Join(crashDir, "active.json"))
				if left := sandboxLeft(fake); len(left) > 0 || fake.Pending() || after.Phase != "cleaned" || after.AllocationPending != "" || after.SDNLockToken != "" || after.SDNLockRequested != "" {
					t.Fatalf("PVE keeps %v (pending %v); journal %+v; want nothing left and the journal cleaned", left, fake.Pending(), after)
				}
				calls := lockCallsOf(fake)
				if len(calls) > 1 || (len(calls) == 1 && calls[0] != "POST cluster/sdn/lock") {
					t.Fatalf("lock calls %v; want at most the one probe, and no release", calls)
				}
				for _, w := range fake.Writes() {
					if strings.Contains(w, "lock-token") || strings.Contains(w, "release-lock") {
						t.Fatalf("a lock parameter reached PVE: %s", w)
					}
				}
			})
		}
	}
}
