//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

// Linux-only, as the soak runs are: Run starts with the host's admission
// check, which reads the node's /proc counters.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// vnetGuestsPVE serves soakRunPlan's pre-provisioned sandbox, and answers the
// guest list with lists[i] on its i-th read (the last one from then on). VM
// 9101 is the run's own sandbox VM and carries the run's markers; VM 105 is
// someone else's, on the sandbox VNet.
func vnetGuestsPVE(t *testing.T, runID *atomic.Pointer[string], lists ...string) (*pve.Client, *atomic.Int64) {
	t.Helper()
	var reads atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "preprovisioned sandbox must not be mutated", http.StatusInternalServerError)
			return
		}
		var data json.RawMessage
		switch {
		case r.URL.Path == "/api2/json/cluster/sdn/zones":
			data = json.RawMessage(`[{"zone":"csSbExternal","type":"simple","ipam":"pve"}]`)
		case r.URL.Path == "/api2/json/cluster/sdn/vnets":
			data = json.RawMessage(`[{"vnet":"csVnExternal","zone":"csSbExternal"}]`)
		case r.URL.Path == "/api2/json/cluster/sdn/vnets/csVnExternal/subnets":
			data = json.RawMessage(`[{"cidr":"10.100.0.0/24","vnet":"csVnExternal"}]`)
		case r.URL.Path == "/api2/json/cluster/resources":
			n := int(reads.Add(1))
			data = json.RawMessage(lists[min(n, len(lists))-1])
		case r.URL.Path == "/api2/json/nodes/pve1/qemu/9101/pending":
			id := *runID.Load()
			data = json.RawMessage(`[{"key":"net0","value":"virtio=BC:24:11:00:91:01,bridge=csVnExternal"},` +
				`{"key":"tags","value":"certistack;` + id + `"},{"key":"description","value":"owner=certistack\nrun_id=` + id + `"}]`)
		case r.URL.Path == "/api2/json/nodes/pve1/qemu/105/pending":
			data = json.RawMessage(`[{"key":"net0","value":"virtio=BC:24:11:00:01:05,bridge=csVnExternal"}]`)
		case strings.HasSuffix(r.URL.Path, "/status/current"):
			data = json.RawMessage(`{"status":"running","qmpstatus":"running"}`)
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: data})
	}))
	t.Cleanup(server.Close)
	return pve.NewClient(pve.Config{BaseURL: server.URL}), &reads
}

const (
	noGuests     = `[]`
	ownVMOnly    = `[{"vmid":9101,"type":"qemu","node":"pve1","name":"app","status":"running"}]`
	anotherGuest = `[{"vmid":9101,"type":"qemu","node":"pve1","name":"app","status":"running"},{"vmid":105,"type":"qemu","node":"pve1","name":"web-01","status":"running"}]`
	// What the run says of VM 105.
	vm105 = "sandbox VNet csVnExternal is also attached to VM 105 (web-01) on pve1, running, net0"
)

// The run's own sandbox VM records itself as the real boot does (trackOwnedVM).
func vnetGuestsOrchestrator(t *testing.T, plan *config.Plan, client *pve.Client, runID *atomic.Pointer[string]) (*Orchestrator, *atomic.Int64) {
	t.Helper()
	dir := shortSocketDir(t)
	guestAgent(t, dir, -1)
	orch := soakRunOrchestrator(t, plan, client, dir)
	id := orch.record.RunID
	runID.Store(&id)
	var boots atomic.Int64
	orch.bootVMFn = func(_ context.Context, vm config.VM, _ int, _ *attest.PhaseTimings) (*probe.VMValidationRecord, error) {
		boots.Add(1)
		orch.record.AddVM(vm.VMID, "pve1", 0, "")
		return &probe.VMValidationRecord{VMID: vm.VMID, Name: vm.Name, AllPassed: true}, nil
	}
	return orch, &boots
}

// A pre-provisioned VNet that another guest is attached to is refused before
// anything is made: that guest could answer a probe in a restored VM's place.
func TestRunRefusesAPreprovisionedVNetAnotherGuestIsAttachedTo(t *testing.T) {
	var runID atomic.Pointer[string]
	plan, _ := soakRunPlan(t, 0)
	client, _ := vnetGuestsPVE(t, &runID, `[{"vmid":105,"type":"qemu","node":"pve1","name":"web-01","status":"running"}]`)
	orch, boots := vnetGuestsOrchestrator(t, plan, client, &runID)
	res, err := orch.Run(context.Background())
	if err == nil || res.AllPassed || !strings.Contains(err.Error(), "SDN sandbox setup failed: validate preprovisioned sandbox: "+vm105) ||
		!strings.Contains(err.Error(), "network.lifecycle: ephemeral") {
		t.Fatalf("run: err=%v", err)
	}
	if boots.Load() != 0 {
		t.Fatalf("%d VMs were restored on a VNet another guest is attached to", boots.Load())
	}
}

// A guest attached during the run, after the check at its start, fails the
// tier it was there for. The run's own sandbox VM on the VNet is not one.
func TestRunFailsATierWhenAnotherGuestJoinsTheSandboxVNet(t *testing.T) {
	for _, tc := range []struct {
		name    string
		soakSec int
		lists   []string
		want    string // the run's error; "" for a pass
	}{
		{name: "no other guest", lists: []string{noGuests, ownVMOnly}},
		{name: "a guest that joined before the probes ended", lists: []string{noGuests, anotherGuest}, want: "VM 9101 (app) probes: " + vm105},
		{name: "a guest that joined during the soak", soakSec: 1, lists: []string{noGuests, ownVMOnly, anotherGuest}, want: "VM 9101 (app) during the soak: " + vm105},
	} {
		t.Run(tc.name, func(t *testing.T) {
			soakFast(t, 100*time.Millisecond)
			var runID atomic.Pointer[string]
			plan, _ := soakRunPlan(t, tc.soakSec)
			client, reads := vnetGuestsPVE(t, &runID, tc.lists...)
			orch, _ := vnetGuestsOrchestrator(t, plan, client, &runID)
			res, err := orch.Run(context.Background())
			if tc.want == "" {
				if err != nil || !res.AllPassed {
					t.Fatalf("run: err=%v res=%+v", err, res)
				}
			} else {
				if err == nil || res.AllPassed || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "VM 9101 (app) on") {
					t.Fatalf("run: err=%v, want %q", err, tc.want)
				}
				if status := res.VMRecords[0].VerificationStatus; status != "failed" {
					t.Fatalf("the VM's status is %q, want failed", status)
				}
			}
			if got := int(reads.Load()); got != len(tc.lists) {
				t.Fatalf("the guest list was read %d times, want %d", got, len(tc.lists))
			}
		})
	}
}

// A guest the token's list does not show (one the token may not audit) but
// that the kernel has attached to the sandbox VNet's bridge on the node is
// refused as well: before anything is made, and during the run, where the
// run's own sandbox VM's tap device is not one.
func TestRunRefusesAGuestOnTheNodesSandboxBridgeThatPVEDoesNotList(t *testing.T) {
	const foreign = "sandbox VNet csVnExternal's bridge on this node (pve1) also has tap105i0 (VM 105) attached"
	t.Run("before anything is made", func(t *testing.T) {
		var runID atomic.Pointer[string]
		plan, _ := soakRunPlan(t, 0)
		client, _ := vnetGuestsPVE(t, &runID, noGuests)
		orch, boots := vnetGuestsOrchestrator(t, plan, client, &runID)
		orch.bridgePortsFn = func(string) ([]string, error) { return []string{"tap105i0"}, nil }
		res, err := orch.Run(context.Background())
		if err == nil || res.AllPassed || !strings.Contains(err.Error(), "SDN sandbox setup failed: validate preprovisioned sandbox: "+foreign) {
			t.Fatalf("run: err=%v", err)
		}
		if boots.Load() != 0 {
			t.Fatalf("%d VMs were restored on a VNet another guest is attached to", boots.Load())
		}
	})
	t.Run("joined before the probes ended", func(t *testing.T) {
		var runID atomic.Pointer[string]
		plan, _ := soakRunPlan(t, 0)
		client, _ := vnetGuestsPVE(t, &runID, noGuests, ownVMOnly)
		orch, _ := vnetGuestsOrchestrator(t, plan, client, &runID)
		boot := orch.bootVMFn
		orch.bootVMFn = func(ctx context.Context, vm config.VM, grace int, timings *attest.PhaseTimings) (*probe.VMValidationRecord, error) {
			record, err := boot(ctx, vm, grace, timings)
			orch.noteVMCreated(vm.VMID)
			return record, err
		}
		var reads atomic.Int64
		orch.bridgePortsFn = func(string) ([]string, error) {
			if reads.Add(1) == 1 {
				return nil, nil
			}
			return []string{"fwpr9101p0", "tap105i0", "tap9101i0"}, nil
		}
		res, err := orch.Run(context.Background())
		if err == nil || res.AllPassed || !strings.Contains(err.Error(), "VM 9101 (app) probes: "+foreign) || strings.Contains(err.Error(), "9101i0 (VM") {
			t.Fatalf("run: err=%v", err)
		}
		if status := res.VMRecords[0].VerificationStatus; status != "failed" {
			t.Fatalf("the VM's status is %q, want failed", status)
		}
	})
}
