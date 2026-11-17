//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
)

// reuseFixture is PVE with one VM ID, 9100 on node1, whose occupant can change
// between calls: "ours" (the run's own, run-old), "foreign" (another VM with
// no markers of the run), or "" (nothing). status is the occupant's power
// state. The hooks run inside a request, before it is answered, and may change
// the occupant, as another actor deleting and recreating the VM would.
type reuseFixture struct {
	mu       sync.Mutex
	occupant string
	status   string
	// stopNotFound answers a stop with HTTP 404 whatever the hook did.
	stopNotFound bool
	// wrongMissing makes a status read answer with another VM's missing
	// configuration (HTTP 500), whatever is at 9100.
	wrongMissing bool
	// all404 answers every request with HTTP 404, as a proxy in front of the
	// API would.
	all404 bool

	onStop     func()
	onStopTask func()

	statusReads int
	calls       []string
}

func (f *reuseFixture) called(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (f *reuseFixture) serve(t *testing.T) {
	t.Helper()
	const (
		stopHandle    = "UPID:node1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9100:root@pam:"
		destroyHandle = "UPID:node1:0000A1B3:00C3D4E6:66A1B2C4:qmdestroy:9100:root@pam:"
	)
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
		if f.all404 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"data":null,"message":"Not Found (injected by a proxy)"}`))
			return
		}
		switch call {
		case "GET /api2/json/cluster/resources":
			// What backs an HTTP 404: the cluster lists whatever is at the ID.
			if f.occupant == "" {
				answer([]map[string]any{})
			} else {
				answer([]map[string]any{{"vmid": 9100}})
			}
		case "GET /api2/json/nodes/node1/qemu/9100/status/current":
			f.statusReads++
			switch {
			case f.wrongMissing:
				missing("9999")
			case f.occupant == "":
				missing("9100")
			default:
				answer(map[string]any{"vmid": 9100, "status": f.status})
			}
		case "GET /api2/json/nodes/node1/qemu/9100/config":
			switch f.occupant {
			case "":
				missing("9100")
			case "ours":
				answer(map[string]any{"tags": "certistack,run-old", "description": "owner=certistack; run_id=run-old"})
			default:
				answer(map[string]any{"tags": "customer", "description": "somebody else's VM"})
			}
		case "POST /api2/json/nodes/node1/qemu/9100/status/stop":
			if f.onStop != nil {
				f.onStop()
			}
			if f.occupant == "" || f.stopNotFound {
				w.WriteHeader(http.StatusNotFound)
				answer(nil)
				return
			}
			f.status = "stopped"
			answer(stopHandle)
		case "DELETE /api2/json/nodes/node1/qemu/9100":
			f.occupant = "" // whoever is there is deleted
			answer(destroyHandle)
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
	t.Setenv("PVE_URL", server.URL)
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "synthetic-token")
	t.Setenv("PVE_TLS_INSECURE", "")
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", "")
}

func reuseJournal(t *testing.T) string {
	t.Helper()
	return journalForRun(t, "run-old", 9100)
}

func journalForRun(t *testing.T, runID string, vmid int) string {
	t.Helper()
	stateDir := t.TempDir()
	record := journal.Record{RunID: runID, Phase: "running"}
	record.AddVM(vmid, "node1", 0, "")
	if err := journal.Write(stateDir+"/active.json", record); err != nil {
		t.Fatal(err)
	}
	return stateDir
}

func assertKept(t *testing.T, stateDir string) {
	t.Helper()
	after := journalPhase(t, stateDir)
	if after.Phase != "cleanup_failed" || len(after.VMs) != 1 || after.VMs[0].VMID != 9100 {
		t.Fatalf("journal after recovery = %+v, want cleanup_failed with VM 9100 kept for the operator", after)
	}
}

// A stop that answered not-found fell through to a destroy of the same
// ID, and a VM another actor had created there in between was deleted.
func TestRecoveryNeverDestroysAVMThatReusesTheID(t *testing.T) {
	t.Run("the stop answers not-found and a foreign VM now holds the ID", func(t *testing.T) {
		// When the stop arrives, the run's VM is deleted and a foreign VM
		// created at the ID, and the stop is answered 404.
		f := &reuseFixture{occupant: "ours", status: "running", stopNotFound: true}
		f.onStop = func() { f.occupant, f.status = "foreign", "running" }
		f.serve(t)
		stateDir := reuseJournal(t)

		err := RecoverLocked(stateDir)
		if f.called("DELETE ") {
			t.Fatalf("recovery destroyed the VM at the ID after the stop found none: %v", f.calls)
		}
		if err == nil || !strings.Contains(err.Error(), "does not carry this run's ownership markers") {
			t.Fatalf("recovery = %v, want the replacement reported and left alone", err)
		}
		if f.occupant != "foreign" {
			t.Fatalf("the replacement was changed: occupant %q", f.occupant)
		}
		assertKept(t, stateDir)
	})

	t.Run("the stop succeeds and a foreign VM takes the ID before the destroy", func(t *testing.T) {
		f := &reuseFixture{occupant: "ours", status: "running"}
		f.onStopTask = func() { f.occupant, f.status = "foreign", "stopped" }
		f.serve(t)
		stateDir := reuseJournal(t)

		err := RecoverLocked(stateDir)
		if f.called("DELETE ") {
			t.Fatalf("recovery destroyed a VM that is not the run's: %v", f.calls)
		}
		if err == nil || !strings.Contains(err.Error(), "refusing to destroy recorded VM 9100: it does not carry this run's CertiStack ownership markers") {
			t.Fatalf("recovery = %v, want the destroy refused before it was sent", err)
		}
		if f.occupant != "foreign" {
			t.Fatalf("the replacement was changed: occupant %q", f.occupant)
		}
		assertKept(t, stateDir)
	})

	t.Run("a foreign VM holds the ID from the start", func(t *testing.T) {
		f := &reuseFixture{occupant: "foreign", status: "running"}
		f.serve(t)
		stateDir := reuseJournal(t)
		err := RecoverLocked(stateDir)
		if f.called("DELETE ") || f.called("POST ") {
			t.Fatalf("recovery acted on a VM that is not the run's: %v", f.calls)
		}
		if err == nil || !strings.Contains(err.Error(), "does not carry this run's") {
			t.Fatalf("recovery = %v", err)
		}
		assertKept(t, stateDir)
	})

	// The control: the run's own VM is stopped, checked again and destroyed.
	t.Run("the run's own VM is destroyed", func(t *testing.T) {
		f := &reuseFixture{occupant: "ours", status: "running"}
		f.serve(t)
		stateDir := reuseJournal(t)
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		if !f.called("POST ") || !f.called("DELETE ") {
			t.Fatalf("calls %v, want a stop and a destroy", f.calls)
		}
		if after := journalPhase(t, stateDir); after.Phase != "cleaned" {
			t.Fatalf("journal phase = %q, want cleaned", after.Phase)
		}
	})
}

// PVE 9 says a missing VM with HTTP 500 and the file's name; the answer
// for another VM's file was read as this VM being gone, and recovery cleaned
// the journal over a VM that was still there.
func TestRecoveryDoesNotTakeAnotherVMsMissingConfigForItsOwnAbsence(t *testing.T) {
	f := &reuseFixture{occupant: "ours", status: "running", wrongMissing: true}
	f.serve(t)
	stateDir := reuseJournal(t)

	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "read recorded VM 9100 on node1") {
		t.Fatalf("recovery = %v, want the unreadable VM reported", err)
	}
	if f.called("POST ") || f.called("DELETE ") {
		t.Fatalf("recovery changed something on an answer that was not about the VM: %v", f.calls)
	}
	assertKept(t, stateDir)
	// The independent exact-VM query behind the clean verdict says the same.
	f.mu.Lock()
	reads := f.statusReads
	f.mu.Unlock()
	if reads < 2 {
		t.Fatalf("status reads = %d, want the recovery's read and the final confirmation", reads)
	}

	// And the VM's own missing-configuration answer is absence.
	f.mu.Lock()
	f.wrongMissing, f.occupant = false, ""
	f.mu.Unlock()
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("retry with the VM really gone = %v", err)
	}
	if after := journalPhase(t, stateDir); after.Phase != "cleaned" {
		t.Fatalf("journal phase = %q, want cleaned", after.Phase)
	}
}
