//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/recovery"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// The crash window: the journal a run really writes when its zone's (or
// VNet's) creation request is about to be sent is the image a crash at that
// instant leaves. Recovery of it settles PVE whether the request was made or
// not: the run's lock stands, the object is pending or absent, and nothing is
// left behind.
func TestRecoveryOfTheJournalAtTheMomentACreationIsSent(t *testing.T) {
	for _, create := range []string{"zones", "vnets"} {
		for _, made := range []bool{true, false} {
			name := create + ", request not processed"
			if made {
				name = create + ", request processed"
			}
			t.Run(name, func(t *testing.T) {
				// The run, only to capture the journal at the request.
				var image []byte
				stateDir := t.TempDir()
				probe := sdntest.New()
				probe.OnRequest = func(method, path string, _ map[string]string) {
					if method == "POST" && path == "cluster/sdn/"+create {
						image, _ = os.ReadFile(filepath.Join(stateDir, "active.json"))
					}
				}
				orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), probe.Serve(t))
				orch.hostAddresses = &fakeHostAddressManager{}
				if _, err := orch.Run(context.Background()); err != nil {
					t.Fatal(err)
				}
				if len(image) == 0 {
					t.Fatal("no journal was captured at the request")
				}

				// PVE as the crash left it: the run's lock stands, and the
				// request made its object (New: configured, never applied) or not.
				crashDir := t.TempDir()
				if err := os.WriteFile(filepath.Join(crashDir, "active.json"), image, 0o600); err != nil {
					t.Fatal(err)
				}
				record, err := journal.Load(filepath.Join(crashDir, "active.json"))
				if err != nil {
					t.Fatal(err)
				}
				fake := sdntest.New()
				fake.Lock = record.SDNLockToken
				if fake.Lock != "tok-1" {
					t.Fatalf("the journal at the request holds lock %q; want the run's tok-1", record.SDNLockToken)
				}
				fake.Zones["csSb01"] = true // the zone exists by either request's time
				if create == "vnets" && made {
					fake.VNets["csVn01"], fake.Aliases["csVn01"] = "csSb01", record.SDNOwner
				}
				if create == "zones" && !made {
					delete(fake.Zones, "csSb01")
				}
				t.Setenv("PVE_URL", fake.Start(t).URL)
				t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
				t.Setenv("PVE_TOKEN_SECRET", "test-secret")
				t.Setenv("PVE_TLS_INSECURE", "")
				t.Setenv("CERTISTACK_PVE_CA_SOURCE", "")

				if err := recovery.RecoverLocked(crashDir); err != nil {
					t.Fatalf("RecoverLocked: %v", err)
				}
				left := sandboxLeft(fake)
				after, _ := journal.Load(filepath.Join(crashDir, "active.json"))
				if len(left) > 0 || fake.Pending() || after.Phase != "cleaned" || after.AllocationPending != "" || after.SDNLockToken != "" {
					t.Fatalf("PVE keeps %v (pending %v); journal %+v; want nothing left and the journal cleaned", left, fake.Pending(), after)
				}
			})
		}
	}
}
