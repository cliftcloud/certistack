// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// A run journals the host probe address it is about to add, and recovery settles
// an interrupted run's by reading that text. The two must agree on what the text
// is, so the journal on disk at the moment the run touches the host is read here
// with the parser recovery uses, and after the address is recorded the text is
// gone.
func TestRunJournalsTheHostProbeAddressInTheFormRecoveryReads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data json.RawMessage
		switch r.URL.Path {
		case "/api2/json/cluster/sdn/zones":
			data = json.RawMessage(`[{"zone":"csSbExternal","type":"simple","ipam":"pve"}]`)
		case "/api2/json/cluster/sdn/vnets":
			data = json.RawMessage(`[{"vnet":"csVnExternal","zone":"csSbExternal"}]`)
		case "/api2/json/cluster/sdn/vnets/csVnExternal/subnets":
			data = json.RawMessage(`[{"cidr":"10.100.0.0/24","vnet":"csVnExternal"}]`)
		case "/api2/json/cluster/resources": // no other guest on the sandbox VNet
			data = json.RawMessage(`[]`)
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: data})
	}))
	t.Cleanup(server.Close)
	plan := &config.Plan{
		Version: "v1", PlanID: "host-allocation", Name: "Host allocation",
		AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 100.0, MaxHostIOWaitPercent: 100.0, DeferRetryIntervalSec: 1, MaxDeferRetries: 1},
		Network:          config.Network{Mode: "simple", Lifecycle: "preprovisioned", ZoneID: "csSbExternal", VNetID: "csVnExternal", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
	}
	stateDir := t.TempDir()
	orch := New(plan, Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
	orch.bridgePortsFn = noForeignBridgePorts
	var seen journal.Record
	var seenIface, seenCIDR string
	var parsed bool
	orch.hostAddresses = &fakeHostAddressManager{onAdd: func() {
		record, err := journal.Load(filepath.Join(stateDir, "active.json"))
		if err != nil {
			t.Fatalf("the journal is not readable when the host is first touched: %v", err)
		}
		seen = record
		seenIface, seenCIDR, parsed = record.PendingHostAddressAllocation()
	}}
	res, err := orch.Run(context.Background())
	if err != nil || !res.AllPassed {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	if !parsed || seenIface != "csVnExternal" || seenCIDR != "10.100.0.1/24" {
		t.Fatalf("when the host was first touched the journal held allocation_pending %q: recovery reads (%q, %q, %v); want the address and VNet the run is adding", seen.AllocationPending, seenIface, seenCIDR, parsed)
	}
	if final, err := journal.Load(filepath.Join(stateDir, "active.json")); err != nil || final.AllocationPending != "" {
		t.Fatalf("the allocation was not cleared once the address was recorded: %+v, %v", final, err)
	}
}

// An address or containment table that is on the host before the run starts is
// not the run's. The run stops before it journals the allocation as pending and
// before it adds anything, so recovery can never settle an interrupted run by
// removing it, and says what it found.
func TestRunRefusesAProbeAddressOrTableThatWasThereFirst(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data json.RawMessage
		switch r.URL.Path {
		case "/api2/json/cluster/sdn/zones":
			data = json.RawMessage(`[{"zone":"csSbExternal","type":"simple","ipam":"pve"}]`)
		case "/api2/json/cluster/sdn/vnets":
			data = json.RawMessage(`[{"vnet":"csVnExternal","zone":"csSbExternal"}]`)
		case "/api2/json/cluster/sdn/vnets/csVnExternal/subnets":
			data = json.RawMessage(`[{"cidr":"10.100.0.0/24","vnet":"csVnExternal"}]`)
		case "/api2/json/cluster/resources": // no other guest on the sandbox VNet
			data = json.RawMessage(`[]`)
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: data})
	}))
	t.Cleanup(server.Close)
	newPlan := func() *config.Plan {
		return &config.Plan{
			Version: "v1", PlanID: "host-allocation", Name: "Host allocation",
			AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 100.0, MaxHostIOWaitPercent: 100.0, DeferRetryIntervalSec: 1, MaxDeferRetries: 1},
			Network:          config.Network{Mode: "simple", Lifecycle: "preprovisioned", ZoneID: "csSbExternal", VNetID: "csVnExternal", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		}
	}
	for name, host := range map[string]*fakeHostAddressManager{
		"table and address there first": {taken: "address 10.100.0.1/24 is already on interface csVnExternal and containment table csiso_x already exists"},
		"unreadable host":               {takenErr: context.DeadlineExceeded},
	} {
		t.Run(name, func(t *testing.T) {
			stateDir := t.TempDir()
			orch := New(newPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
			added := false
			host.onAdd = func() { added = true }
			orch.hostAddresses = host
			res, err := orch.Run(context.Background())
			if err == nil && (res == nil || res.AllPassed) {
				t.Fatalf("the run went on over a probe address that was not its own: %+v", res)
			}
			if added {
				t.Fatal("the run added its probe address although something of that name was already on the host")
			}
			if record, loadErr := journal.Load(filepath.Join(stateDir, "active.json")); loadErr == nil && record.AllocationPending != "" {
				t.Fatalf("the allocation was journaled as pending (%q) before the host was found to be taken", record.AllocationPending)
			}
		})
	}
}
