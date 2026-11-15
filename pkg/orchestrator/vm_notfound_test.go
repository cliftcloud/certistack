// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// notFoundPVE is PVE as a proxy in front of it, or a PVE with a lie in one
// answer, would present it for VM 9101 on node1: every request about the VM
// that a test marks answers HTTP 404, whatever the VM is doing.
type notFoundPVE struct {
	mu sync.Mutex
	// list is the cluster's resource list; nil answers 404 to it too (a proxy
	// that answers 404 to the whole API).
	list *[]int
	// status is the VM's real status: "running", "stopped" or "gone"
	// (PVE's own wording for a missing configuration).
	status string
	// stop404 and destroy404 answer the POST stop and the DELETE with 404.
	stop404, destroy404 bool
	// all404 answers every request with 404.
	all404 bool
	// vm404 answers every request about the VM, its status and configuration
	// included, with 404.
	vm404 bool
	calls []string
}

func (f *notFoundPVE) called(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (f *notFoundPVE) client(t *testing.T) *pve.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		call := r.Method + " " + r.URL.Path
		f.calls = append(f.calls, call)
		w.Header().Set("Content-Type", "application/json")
		answer := func(data any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": data}) }
		notFound := func() {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"data":null,"message":"Not Found (injected by a proxy)"}`))
		}
		missing := func() {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "message": "Configuration file 'nodes/node1/qemu-server/9101.conf' does not exist"})
		}
		const vm = "/api2/json/nodes/node1/qemu/9101"
		switch {
		case f.all404:
			notFound()
		case call == "GET /api2/json/cluster/resources":
			if f.list == nil {
				notFound()
				return
			}
			entries := []map[string]any{}
			for _, id := range *f.list {
				entries = append(entries, map[string]any{"vmid": id})
			}
			answer(entries)
		case f.vm404 && strings.HasPrefix(r.URL.Path, vm):
			notFound()
		case call == "GET "+vm+"/config":
			if f.status == "gone" {
				missing()
				return
			}
			answer(map[string]any{"tags": "certistack,run-test", "description": "owner=certistack; run_id=run-test"})
		case call == "GET "+vm+"/status/current":
			if f.status == "gone" {
				missing()
				return
			}
			answer(map[string]any{"status": f.status})
		case call == "POST "+vm+"/status/stop":
			if f.stop404 {
				notFound()
				return
			}
			f.status = "stopped"
			answer("UPID:node1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9101:root@pam:")
		case call == "DELETE "+vm:
			if f.destroy404 {
				notFound()
				return
			}
			f.status = "gone"
			answer("UPID:node1:0000A1B3:00C3D4E6:66A1B2C4:qmdestroy:9101:root@pam:")
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/node1/tasks/"):
			answer(map[string]any{"status": "stopped", "exitstatus": "OK", "node": "node1"})
		default:
			t.Errorf("unexpected PVE request %s", call)
			notFound()
		}
	}))
	t.Cleanup(server.Close)
	return pve.NewClient(pve.Config{BaseURL: server.URL})
}

func ids(n ...int) *[]int { return &n }

// An HTTP 404 was PVE's definite answer that the VM does not exist, from any
// source. A proxy that answers 404 to the API, or in front of one VM's
// endpoints, read as "every VM is gone": teardown released the overlays, the
// PBS maps and the probe address of a VM that was still running, and the final
// sweep called it absent. A 404 is now an absence only when the cluster's own
// list, read now, names no such guest.
func TestAnHTTP404IsNotTheVMsAbsenceUnlessTheClusterAgrees(t *testing.T) {
	for name, f := range map[string]*notFoundPVE{
		"a proxy that answers 404 to the whole API":     {status: "running", all404: true},
		"404 for the VM's endpoints, the list names it": {status: "running", vm404: true, list: ids(9101)},
		"404 for the VM's endpoints, the list is 404":   {status: "running", vm404: true},
	} {
		t.Run(name, func(t *testing.T) {
			orch := &Orchestrator{opts: Options{NodeName: "node1"}, pveClient: f.client(t)}
			if err := orch.vmMayStillExist(9101); err == nil {
				t.Error("vmMayStillExist = nil: a 404 was taken for the VM's absence")
			}
			orch.record.AddVM(9101, "node1", 0, "")
			if sweep := orch.verifyTrackedVMsAbsent(); sweep == nil {
				t.Error("the exact-VM sweep called a running VM absent on a 404")
			}
			if err := orch.destroyOwnedVM(9101, "run-test"); err == nil || !strings.Contains(err.Error(), "cannot verify CertiStack ownership") {
				t.Errorf("destroyOwnedVM = %v, want the ownership unverifiable, not the VM gone", err)
			}
			if f.called("POST ") || f.called("DELETE ") {
				t.Errorf("teardown acted on a 404: %v", f.calls)
			}
		})
	}
	// The control: a 404 that the cluster's list backs is the VM's absence.
	f := &notFoundPVE{status: "gone", vm404: true, list: ids(9001)}
	orch := &Orchestrator{opts: Options{NodeName: "node1"}, pveClient: f.client(t)}
	if err := orch.vmMayStillExist(9101); err != nil {
		t.Fatalf("a 404 for a VM the cluster does not list: %v", err)
	}
	if err := orch.destroyOwnedVM(9101, "run-test"); err != nil {
		t.Fatalf("destroyOwnedVM of a VM the cluster does not list: %v", err)
	}
}
