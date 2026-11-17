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

// reusedVMID is VM 9300 on node1, whose occupant changes as another actor's
// deleting and recreating it would: "ours" (owned by run-test), "foreign"
// (no markers of the run) or "" (nothing).
type reusedVMID struct {
	mu       sync.Mutex
	occupant string
	status   string
	// onStopTask runs when the stop task is polled, before it answers.
	onStopTask func()
	// otherVMMissing makes every read of VM 9300's config or status answer with
	// another VM's missing configuration (HTTP 500).
	otherVMMissing bool
	calls          []string
}

func (f *reusedVMID) called(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (f *reusedVMID) client(t *testing.T) *pve.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		call := r.Method + " " + r.URL.Path
		f.calls = append(f.calls, call)
		w.Header().Set("Content-Type", "application/json")
		answer := func(data any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": data}) }
		missing := func(vmid string) {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "message": "Configuration file 'nodes/node1/qemu-server/" + vmid + ".conf' does not exist"})
		}
		switch call {
		case "GET /api2/json/nodes/node1/qemu/9300/config":
			switch {
			case f.otherVMMissing:
				missing("9999")
			case f.occupant == "":
				missing("9300")
			case f.occupant == "ours":
				answer(map[string]any{"tags": "certistack,run-test", "description": "owner=certistack; run_id=run-test"})
			default:
				answer(map[string]any{"tags": "customer", "description": "somebody else's VM"})
			}
		case "GET /api2/json/nodes/node1/qemu/9300/status/current":
			switch {
			case f.otherVMMissing:
				missing("9999")
			case f.occupant == "":
				missing("9300")
			default:
				answer(map[string]any{"status": f.status})
			}
		case "POST /api2/json/nodes/node1/qemu/9300/status/stop":
			f.status = "stopped"
			answer("UPID:node1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9300:root@pam:")
		case "DELETE /api2/json/nodes/node1/qemu/9300":
			f.occupant = "" // whoever is there is deleted
			answer("UPID:node1:0000A1B3:00C3D4E6:66A1B2C4:qmdestroy:9300:root@pam:")
		default:
			if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/node1/tasks/") {
				if strings.Contains(r.URL.Path, "qmstop") && f.onStopTask != nil {
					f.onStopTask()
				}
				answer(map[string]any{"status": "stopped", "exitstatus": "OK", "node": "node1"})
				return
			}
			t.Errorf("unexpected PVE request %s", call)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return pve.NewClient(pve.Config{BaseURL: server.URL})
}

// Teardown checks the VM's ownership again after the stop, not only before
// it: a foreign VM created at the ID once the run's own is gone is not
// destroyed, and its absence cannot satisfy the cleanup postcondition.
func TestTeardownNeverDestroysAVMThatReusesTheIDAfterTheStop(t *testing.T) {
	f := &reusedVMID{occupant: "ours", status: "running"}
	f.onStopTask = func() { f.occupant, f.status = "foreign", "stopped" } // another VM takes the ID during the stop
	orch := &Orchestrator{opts: Options{NodeName: "node1"}, pveClient: f.client(t)}

	err := orch.destroyOwnedVM(9300, "run-test")
	if f.called("DELETE ") {
		t.Fatalf("teardown destroyed a VM that is not the run's: %v", f.calls)
	}
	if err == nil || !strings.Contains(err.Error(), "does not carry this run's CertiStack ownership markers") {
		t.Fatalf("destroyOwnedVM = %v, want the replacement left alone and reported", err)
	}
	if f.occupant != "foreign" {
		t.Fatalf("the replacement was changed: occupant %q", f.occupant)
	}
	// The run's VM is not confirmed gone: what it uses is kept, and the final
	// sweep does not call the ID absent (it is not: a VM is there).
	orch.record.AddVM(9300, "node1", 0, "")
	if sweep := orch.verifyTrackedVMsAbsent(); sweep == nil || !strings.Contains(sweep.Error(), "remains") {
		t.Fatalf("the exact-VM sweep = %v, want it to report the VM at the ID", sweep)
	}
}

func TestTeardownDestroysTheRunsOwnVMAfterCheckingItAgain(t *testing.T) {
	f := &reusedVMID{occupant: "ours", status: "running"}
	orch := &Orchestrator{opts: Options{NodeName: "node1"}, pveClient: f.client(t)}
	if err := orch.destroyOwnedVM(9300, "run-test"); err != nil {
		t.Fatal(err)
	}
	if !f.called("DELETE ") || f.occupant != "" {
		t.Fatalf("the run's own VM was not destroyed: %v", f.calls)
	}
	// One read at the start and one right before the destroy.
	reads := 0
	for _, c := range f.calls {
		if c == "GET /api2/json/nodes/node1/qemu/9300/config" {
			reads++
		}
	}
	if reads < 2 {
		t.Fatalf("ownership reads = %d, want one before the stop and one before the destroy", reads)
	}
}

// Another VM's missing configuration is not this VM's absence, for the
// ownership read, the status read and the sweep that proves teardown clean.
func TestAnotherVMsMissingConfigIsNotThisVMsAbsence(t *testing.T) {
	f := &reusedVMID{occupant: "ours", status: "running", otherVMMissing: true}
	orch := &Orchestrator{opts: Options{NodeName: "node1"}, pveClient: f.client(t)}

	if err := orch.destroyOwnedVM(9300, "run-test"); err == nil || !strings.Contains(err.Error(), "cannot verify CertiStack ownership") {
		t.Fatalf("destroyOwnedVM = %v, want the ownership unverifiable, not the VM gone", err)
	}
	if f.called("POST ") || f.called("DELETE ") {
		t.Fatalf("teardown acted on an answer that was not about the VM: %v", f.calls)
	}
	orch.record.AddVM(9300, "node1", 0, "")
	if sweep := orch.verifyTrackedVMsAbsent(); sweep == nil || !strings.Contains(sweep.Error(), "cannot verify sandbox VM 9300 is absent") {
		t.Fatalf("the sweep = %v, want it unable to verify absence", sweep)
	}
	if remains := orch.vmMayStillExist(9300); remains == nil {
		t.Fatal("another VM's missing configuration was taken for VM 9300's absence")
	}

	// The VM's own missing configuration is absence.
	f.mu.Lock()
	f.otherVMMissing, f.occupant = false, ""
	f.mu.Unlock()
	if remains := orch.vmMayStillExist(9300); remains != nil {
		t.Fatalf("VM 9300's own missing configuration = %v, want absence", remains)
	}
	if sweep := orch.verifyTrackedVMsAbsent(); sweep != nil {
		t.Fatalf("the sweep = %v, want clean", sweep)
	}
}
