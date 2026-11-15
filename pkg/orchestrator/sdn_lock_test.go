// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/sdn"
)

// lockingPVE is a PVE whose SDN lock answers the tries in locks in turn:
// "" grants a token, "pending" refuses over pending changes. As PVE does, it
// refuses to delete a VNet that still has its subnet; refuseSubnet
// also refuses the subnet's deletion.
type lockingPVE struct {
	mu           sync.Mutex
	locks        []string
	requests     []string
	subnet       bool
	refuseSubnet bool
	// intercept answers a request itself, before the SDN cases, when it
	// returns true: a test that needs more of PVE than the SDN.
	intercept func(w http.ResponseWriter, r *http.Request) bool
}

func (f *lockingPVE) serve(t *testing.T) *pve.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		line := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			line += "?" + r.URL.RawQuery
		}
		if len(body) > 2 {
			line += " " + string(body)
		}
		f.requests = append(f.requests, line)
		f.mu.Unlock()
		if f.intercept != nil && f.intercept(w, r) {
			return
		}
		answer := func(data string) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(data)})
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/cluster/sdn/lock":
			f.mu.Lock()
			next := ""
			if len(f.locks) > 0 {
				next, f.locks = f.locks[0], f.locks[1:]
			}
			f.mu.Unlock()
			if next == "pending" {
				http.Error(w, `{"data":null,"message":"there are pending changes in the SDN configuration\n"}`, http.StatusInternalServerError)
				return
			}
			answer(`"tok-1"`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/sdn/zones" && r.URL.Query().Get("pending") == "1":
			answer(`[{"zone":"prodZ","type":"evpn","state":"changed"}]`)
		case r.Method == http.MethodGet && (r.URL.Path == "/api2/json/cluster/sdn/zones" || r.URL.Path == "/api2/json/cluster/sdn/vnets" || r.URL.Path == "/api2/json/cluster/sdn/controllers"):
			answer(`[]`)
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/cluster/sdn/vnets/csVn01/subnets":
			f.mu.Lock()
			f.subnet = true
			f.mu.Unlock()
			answer(`null`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/sdn/vnets/csVn01/subnets":
			f.mu.Lock()
			has := f.subnet
			f.mu.Unlock()
			if has {
				answer(`[{"subnet":"csSb01-10.100.0.0-24","cidr":"10.100.0.0/24","type":"subnet","vnet":"csVn01","zone":"csSb01"}]`)
			} else {
				answer(`[]`)
			}
		case r.Method == http.MethodDelete && r.URL.Path == "/api2/json/cluster/sdn/vnets/csVn01/subnets/csSb01-10.100.0.0-24":
			f.mu.Lock()
			refuse := f.refuseSubnet
			if !refuse {
				f.subnet = false
			}
			f.mu.Unlock()
			if refuse {
				http.Error(w, `{"data":null,"message":"delete sdn subnet object failed: permission denied\n"}`, http.StatusInternalServerError)
				return
			}
			answer(`null`)
		case r.Method == http.MethodDelete && r.URL.Path == "/api2/json/cluster/sdn/vnets/csVn01":
			f.mu.Lock()
			has := f.subnet
			f.mu.Unlock()
			if has {
				// PVE 9 rewraps the hook's parameter exception, losing its reason.
				http.Error(w, `{"data":null,"message":"delete sdn vnet object failed: 400 Parameter verification failed.\n"}`, http.StatusInternalServerError)
				return
			}
			answer(`null`)
		case r.Method == http.MethodDelete && r.URL.Path == "/api2/json/cluster/sdn/zones/csSb01":
			f.mu.Lock()
			has := f.subnet
			f.mu.Unlock()
			if has {
				http.Error(w, `{"data":null,"message":"delete sdn zone object failed: zone csSb01 is used by vnet csVn01\n"}`, http.StatusInternalServerError)
				return
			}
			answer(`null`)
		case r.Method == http.MethodPut && r.URL.Path == "/api2/json/cluster/sdn":
			answer(`"UPID:pve1:1:1:1:1:1:"`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/status"):
			answer(`{"status":"stopped","exitstatus":"OK"}`)
		default:
			answer(`"OK"`)
		}
	}))
	t.Cleanup(server.Close)
	return pve.NewClient(pve.Config{BaseURL: server.URL})
}

func (f *lockingPVE) sdnRequests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		if strings.Contains(r, "/cluster/sdn") && !strings.HasPrefix(r, "GET") {
			r = ownerMarker.ReplaceAllString(r, `"alias":"MARKER"`)
			out = append(out, strings.TrimPrefix(strings.Replace(r, "/api2/json/cluster/sdn", "", 1), ""))
		}
	}
	return out
}

func ephemeralPlan() *config.Plan {
	return &config.Plan{
		Version: "v1", PlanID: "sdn-lock", Name: "SDN lock",
		AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 100, MaxHostIOWaitPercent: 100, DeferRetryIntervalSec: 1, MaxDeferRetries: 1},
		Network:          config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		Tiers:            []config.Tier{},
	}
}

// Applying SDN is all or nothing, on every node: the run holds PVE's SDN
// lock from its first SDN write to each apply, so what it applies is its
// own change and nothing an administrator left pending.
func TestEphemeralSandboxAppliesOnlyUnderPVEsSDNLock(t *testing.T) {
	fake := &lockingPVE{}
	stateDir := t.TempDir()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.serve(t))
	hosts := &fakeHostAddressManager{}
	orch.hostAddresses = hosts
	res, err := orch.Run(context.Background())
	if err != nil || res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned || !res.TeardownEvidence.SDNClusterReloaded {
		t.Fatalf("Run = %v, evidence %+v", err, res.TeardownEvidence)
	}
	// The apply's end says nothing about this node's bridge, and
	// ifupdown2 brings it up forwarding.
	if got := strings.Join(hosts.bridges, "; "); got != "settle csVn01 present=true; no-forwarding csVn01; settle csVn01 present=false" {
		t.Fatalf("bridge steps = %s", got)
	}
	got := strings.Join(fake.sdnRequests(), "\n")
	want := strings.Join([]string{
		`POST /lock`,
		`POST /zones {"ipam":"pve","lock-token":"tok-1","nodes":"localhost","type":"simple","zone":"csSb01"}`,
		`POST /vnets {"alias":"MARKER","lock-token":"tok-1","vnet":"csVn01","zone":"csSb01"}`,
		`POST /vnets/csVn01/subnets {"lock-token":"tok-1","subnet":"10.100.0.0/24","type":"subnet"}`,
		`PUT  {"lock-token":"tok-1","release-lock":1}`,
		`POST /lock`,
		`DELETE /vnets/csVn01/subnets/csSb01-10.100.0.0-24?lock-token=tok-1`,
		`DELETE /vnets/csVn01?lock-token=tok-1`,
		`DELETE /zones/csSb01?lock-token=tok-1`,
		`PUT  {"lock-token":"tok-1","release-lock":1}`,
	}, "\n")
	if got != want {
		t.Fatalf("SDN writes:\n%s\nwant:\n%s", got, want)
	}
	record, err := journal.Load(stateDir + "/active.json")
	if err != nil || record.SDNLockToken != "" || record.Phase != "cleaned" {
		t.Fatalf("journal = %+v, %v; want cleaned with no lock held", record, err)
	}
}

// An administrator's pending SDN change refuses the run before it creates
// anything, and names the change.
func TestEphemeralSandboxRefusedOverPendingSDNChanges(t *testing.T) {
	fake := &lockingPVE{locks: []string{"pending"}}
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), fake.serve(t))
	orch.hostAddresses = &fakeHostAddressManager{}
	_, err := orch.Run(context.Background())
	if !errors.Is(err, sdn.ErrPendingSDNChanges) || !strings.Contains(err.Error(), "zone prodZ (changed)") {
		t.Fatalf("Run = %v, want a refusal naming the pending change", err)
	}
	for _, r := range fake.sdnRequests() {
		if r != "POST /lock" {
			t.Fatalf("the run wrote SDN after the refusal: %v", fake.sdnRequests())
		}
	}
}

// A pending change that appears during the run keeps teardown from taking
// the lock, and so from writing anything to SDN: a deletion made
// without the lock would mix with the administrator's change, and the apply
// that enacts theirs would enact it. The sandbox's zone and VNet stay, the
// journal keeps them, and the report says so.
func TestEphemeralTeardownWritesNothingOverPendingSDNChanges(t *testing.T) {
	fake := &lockingPVE{locks: []string{"", "pending"}}
	stateDir := t.TempDir()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.serve(t))
	orch.hostAddresses = &fakeHostAddressManager{}
	res, _ := orch.Run(context.Background())
	if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned || res.TeardownEvidence.SDNClusterReloaded {
		t.Fatalf("evidence = %+v, want the objects reported left in place", res.TeardownEvidence)
	}
	if !strings.Contains(strings.Join(res.TeardownEvidence.CleanupErrors, "\n"), "left in place") {
		t.Fatalf("cleanup errors = %v", res.TeardownEvidence.CleanupErrors)
	}
	writes := fake.sdnRequests()
	if last := writes[len(writes)-1]; last != "POST /lock" {
		t.Fatalf("teardown SDN writes = %v, want the lock refused and nothing written after it", writes)
	}
	for _, w := range writes {
		if strings.HasPrefix(w, "DELETE") {
			t.Fatalf("teardown deleted without the lock: %v", writes)
		}
	}
}

// The VNet and zone could not be deleted, and teardown applied the unchanged
// configuration anyway, reloading every node's network and turning forwarding
// back on for the leftover bridge. When nothing can be deleted, teardown
// releases the lock and applies nothing.
func TestEphemeralTeardownAppliesNothingWhenNothingWasDeleted(t *testing.T) {
	fake := &lockingPVE{refuseSubnet: true}
	stateDir := t.TempDir()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.serve(t))
	hosts := &fakeHostAddressManager{}
	orch.hostAddresses = hosts
	res, _ := orch.Run(context.Background())
	if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned || res.TeardownEvidence.SDNClusterReloaded {
		t.Fatalf("evidence = %+v, want the failed deletion reported", res.TeardownEvidence)
	}
	errs := strings.Join(res.TeardownEvidence.CleanupErrors, "\n")
	if !strings.Contains(errs, "delete SDN subnet csSb01-10.100.0.0-24") || !strings.Contains(errs, "Parameter verification failed") {
		t.Fatalf("cleanup errors = %v", res.TeardownEvidence.CleanupErrors)
	}
	writes := fake.sdnRequests()
	if tail := strings.Join(writes[len(writes)-5:], "\n"); tail != "POST /lock\nDELETE /vnets/csVn01/subnets/csSb01-10.100.0.0-24?lock-token=tok-1\nDELETE /vnets/csVn01?lock-token=tok-1\nDELETE /zones/csSb01?lock-token=tok-1\nDELETE /lock?lock-token=tok-1" {
		t.Fatalf("teardown SDN writes:\n%s\nwant the lock released and no apply", tail)
	}
	if strings.Contains(strings.Join(hosts.bridges, ";"), "present=false") {
		t.Fatalf("teardown waited for a bridge nothing removed: %v", hosts.bridges)
	}
	record, err := journal.Load(stateDir + "/active.json")
	if err != nil || record.SDNLockToken != "" || record.Phase != "cleanup_failed" {
		t.Fatalf("journal = %+v, %v; want cleanup_failed, no lock held", record, err)
	}
}
