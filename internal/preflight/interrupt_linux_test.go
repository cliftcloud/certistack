// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// holdingPVE is a PVE API that answers until it is told to stop, then
// withholds one reply until the client gives up on the request: a valid
// version reply, then a privilege request held in flight.
type holdingPVE struct {
	*httptest.Server
	mu        sync.Mutex
	privilege int           // privilege requests answered so far
	held      chan struct{} // closed when the first held request has arrived
	gone      chan string   // the held request's context ending, with why
	once      sync.Once
}

// newHoldingPVE holds the version request when holdVersion is set, else the
// privilege request that comes after answerBefore answered ones.
func newHoldingPVE(t *testing.T, holdVersion bool, answerBefore int) *holdingPVE {
	t.Helper()
	grant := map[string]int{"VM.Allocate": 1, "VM.Audit": 1, "VM.PowerMgmt": 1, "VM.Console": 1, "VM.Config.Disk": 1, "VM.Config.CPU": 1, "VM.Config.Memory": 1, "VM.Config.Network": 1, "VM.Config.Options": 1, "VM.Config.HWType": 1, "VM.Config.CDROM": 1, "SDN.Allocate": 1, "SDN.Audit": 1, "SDN.Use": 1, "Sys.Audit": 1, "Datastore.AllocateSpace": 1, "Datastore.Audit": 1}
	h := &holdingPVE{held: make(chan struct{}), gone: make(chan string, 1)}
	hold := func(w http.ResponseWriter, r *http.Request) {
		h.once.Do(func() { close(h.held) })
		<-r.Context().Done()
		select {
		case h.gone <- r.Context().Err().Error():
		default:
		}
	}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/version"):
			if holdVersion {
				hold(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"version": "8.4"}})
		case strings.HasSuffix(r.URL.Path, "/access/permissions"):
			h.mu.Lock()
			n := h.privilege
			h.privilege++
			h.mu.Unlock()
			if n == answerBefore {
				hold(w, r)
				return
			}
			path := r.URL.Query().Get("path")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{path: grant}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(h.Close)
	return h
}

// The PVE requests of the preflight end when the context the caller gave Check
// ends, so an interrupted command does not wait out their own time limits (5
// seconds for the version request, 10 for each privilege request, one request
// for every path a run touches) after it has printed that it is stopping. The
// cases are a held first privilege request, a held version request and a held
// late privilege request. A Check that waited for the client's own time limit
// would take 5 seconds and more; the bound here is 4, which a loaded machine
// meets.
func TestCheckEndsItsPVERequestsWhenItsContextEnds(t *testing.T) {
	plan := &config.Plan{
		Network: config.Network{ZoneID: "csLab70", VNetID: "csVn70"},
		Storage: config.Storage{OverlayStorage: "certistack-scratch"},
		Tiers:   []config.Tier{{VMs: []config.VM{{VMID: 717011}}}},
	}
	for name, tc := range map[string]struct {
		holdVersion  bool
		answerBefore int
	}{
		"the version request":                {true, 0},
		"the first privilege request":        {false, 0},
		"a late privilege request (the 5th)": {false, 4},
	} {
		for _, worker := range []bool{false, true} {
			mode := "doctor"
			if worker {
				mode = "node worker"
			}
			t.Run(name+", "+mode, func(t *testing.T) {
				server := newHoldingPVE(t, tc.holdVersion, tc.answerBefore)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan Result, 1)
				go func() {
					done <- Check(ctx, plan, Options{
						ScratchDir: t.TempDir(), StateDir: t.TempDir(),
						PVEURL: server.URL, PVETokenID: "certistack@pve!doctor", PVETokenSecret: "s", NodeName: "pve-node-02",
						RequirePVEConnectivity: worker,
					})
				}()
				select {
				case <-server.held:
				case <-time.After(10 * time.Second):
					t.Fatal("the request that is held never arrived")
				}
				interrupted := time.Now()
				cancel()
				select {
				case <-done:
					if elapsed := time.Since(interrupted); elapsed > 4*time.Second {
						t.Fatalf("Check took %v to return after its context ended", elapsed)
					}
				case <-time.After(8 * time.Second):
					t.Fatal("Check was still waiting for the PVE API 8 seconds after its context ended")
				}
				select {
				case why := <-server.gone:
					if why != "context canceled" {
						t.Errorf("the held request ended for %q, not because the client gave up", why)
					}
				case <-time.After(2 * time.Second):
					t.Error("the PVE API never saw the request given up")
				}
			})
		}
	}
}

// The context only ends requests: one that was never interrupted still gives
// the answer it did, and a Check that is handed a nil context behaves.
func TestCheckWithAnUnendedContextStillReportsThePVEChecks(t *testing.T) {
	server := newHoldingPVE(t, false, 1<<30) // never holds
	plan := &config.Plan{
		Network: config.Network{ZoneID: "csLab70", VNetID: "csVn70"},
		Tiers:   []config.Tier{{VMs: []config.VM{{VMID: 717011}}}},
	}
	opts := Options{ScratchDir: t.TempDir(), StateDir: t.TempDir(), PVEURL: server.URL, PVETokenID: "certistack@pve!doctor", PVETokenSecret: "s", NodeName: "pve-node-02"}
	for name, ctx := range map[string]context.Context{"background": context.Background(), "nil": nil} {
		result := Check(ctx, plan, opts)
		statuses := map[string]string{}
		for _, item := range result.Checks {
			statuses[item.Name] = item.Status
		}
		if statuses["pve_connectivity"] != "passed" || statuses["pve_privileges"] != "passed" {
			t.Errorf("%s: PVE checks = %v", name, statuses)
		}
	}
}
