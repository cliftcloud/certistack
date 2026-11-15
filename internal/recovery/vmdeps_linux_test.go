//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/process"
)

// vmRecoveryPVE answers recovery for VM 9101 on node1, owned by run
// run-deps. failure picks what goes wrong: "status_unreadable",
// "stop_refused", "destroy_refused", or "" for a VM that does not exist.
func vmRecoveryPVE(t *testing.T, failure string) {
	t.Helper()
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		answer := func(data any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": data}) }
		refuse := func() {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "message": "operation refused"})
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api2/json/nodes/node1/qemu/9101/status/current":
			switch failure {
			case "":
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "message": "Configuration file 'nodes/node1/qemu-server/9101.conf' does not exist"})
			case "status_unreadable":
				refuse()
			default:
				answer(map[string]any{"status": "running"})
			}
		case "GET /api2/json/nodes/node1/qemu/9101/config":
			answer(map[string]any{"tags": "certistack,run-deps", "description": "owner=certistack; run_id=run-deps"})
		case "POST /api2/json/nodes/node1/qemu/9101/status/stop":
			if failure == "stop_refused" {
				refuse()
				return
			}
			answer("UPID:node1:stop")
		case "GET /api2/json/nodes/node1/tasks/UPID:node1:stop/status":
			answer(map[string]any{"status": "stopped", "exitstatus": "OK"})
		default: // destroy_refused refuses the DELETE, as anything else
			refuse()
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("PVE_URL", server.URL)
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "synthetic-token")
	t.Setenv("PVE_TLS_INSECURE", "")
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", "")
}

// depsJournal journals VM 9101 with an overlay a consumer holds open, and
// returns the state directory, the overlay and the consumer.
func depsJournal(t *testing.T, vmProcess journal.Process, withNetwork bool) (string, string, *os.File) {
	t.Helper()
	stateDir := t.TempDir()
	overlay := filepath.Join(t.TempDir(), "certistack-delta-vm9101-scsi0-1-0.qcow2")
	if err := os.WriteFile(overlay, []byte("disposable backing data"), 0o600); err != nil {
		t.Fatal(err)
	}
	consumer, err := os.Open(overlay)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = consumer.Close() })
	record := journal.Record{RunID: "run-deps", Phase: "running", UpdatedAt: time.Now().UTC(), DeltaFiles: []string{overlay}}
	record.VMs = []journal.TrackedVM{{VMID: 9101, Node: "node1", Process: vmProcess}}
	if withNetwork {
		record.AddHostAddress("csVn01", "10.100.0.1/24")
		record.AddLoop("/dev/loop999999", "recorded-backing")
	}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	return stateDir, overlay, consumer
}

// Recovery that could not establish a VM was gone (its status
// unreadable, its stop or destruction refused) still unlinked its overlay
// and removed the host probe address and containment on its VNet, the
// maps, and the map process. They now stay, journaled, for the next
// attempt.
func TestRecoveryKeepsWhatAVMNotConfirmedGoneUses(t *testing.T) {
	for _, failure := range []string{"status_unreadable", "stop_refused", "destroy_refused"} {
		t.Run(failure, func(t *testing.T) {
			vmRecoveryPVE(t, failure)
			stateDir, overlay, _ := depsJournal(t, journal.Process{}, true)

			err := RecoverLocked(stateDir)
			if err == nil || !strings.Contains(err.Error(), "kept host probe address 10.100.0.1/24 on csVn01 and its containment, 1 PBS map(s), 1 overlay file(s) in place: sandbox VM 9101 on node1") {
				t.Fatalf("recovery = %v, want what VM 9101 uses kept", err)
			}
			if strings.Contains(err.Error(), "failed to remove host probe") {
				t.Fatalf("recovery touched the host probe address: %v", err)
			}
			if _, statErr := os.Stat(overlay); statErr != nil {
				t.Fatalf("overlay unlinked while VM 9101 may run: %v", statErr)
			}
			after, loadErr := journal.Load(filepath.Join(stateDir, "active.json"))
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if after.Phase != "cleanup_failed" || len(after.VMs) != 1 || len(after.DeltaFiles) != 1 || len(after.HostAddresses) != 1 || len(after.Loops) != 1 {
				t.Fatalf("journal after recovery = %+v, want everything kept for the retry", after)
			}
		})
	}
}

// A recorded QEMU process whose stop is not confirmed may still use the
// overlay, whatever PVE says of its VM, and both failing at once is
// reported as such.
func TestRecoveryKeepsWhatAnUnstoppedQEMUProcessUses(t *testing.T) {
	for _, failure := range []string{"", "status_unreadable"} {
		t.Run("API "+map[string]string{"": "says gone", "status_unreadable": "unreadable"}[failure], func(t *testing.T) {
			vmRecoveryPVE(t, failure)
			child := exec.Command("sleep", "30")
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
			// No start time: StopRecorded cannot confirm which process it is.
			stateDir, overlay, _ := depsJournal(t, journal.Process{PID: child.Process.Pid}, false)

			err := RecoverLocked(stateDir)
			if err == nil || !strings.Contains(err.Error(), "kept 1 overlay file(s) in place: VM 9101's QEMU process") {
				t.Fatalf("recovery = %v, want the overlay kept for the unconfirmed process", err)
			}
			if failure != "" && !strings.Contains(err.Error(), "was not confirmed stopped; sandbox VM 9101 on node1 cannot be confirmed gone") {
				t.Fatalf("recovery = %v, want both the process and the VM named", err)
			}
			if _, statErr := os.Stat(overlay); statErr != nil {
				t.Fatalf("overlay unlinked while its QEMU process may run: %v", statErr)
			}
			if !runs(child.Process.Pid) {
				t.Fatal("recovery signalled a process whose identity it could not confirm")
			}
		})
	}
}

// runs reports whether pid is a process that has not exited (not a zombie).
func runs(pid int) bool {
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(stat[strings.LastIndex(string(stat), ")")+1:]))
	return len(fields) > 0 && fields[0] != "Z"
}

// The controls. A VM PVE confirms gone releases what it used, and a
// recorded PID that now names another process is not a survivor (the
// journal still stays unclean over the refusal to signal it).
func TestRecoveryReleasesWhatAVMConfirmedGoneUsed(t *testing.T) {
	t.Run("VM gone", func(t *testing.T) {
		vmRecoveryPVE(t, "")
		stateDir, overlay, consumer := depsJournal(t, journal.Process{}, false)
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(overlay); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("overlay of a destroyed VM kept: %v", err)
		}
		_ = consumer.Close()
	})
	t.Run("PID reused", func(t *testing.T) {
		vmRecoveryPVE(t, "")
		other := exec.Command("sleep", "30")
		if err := other.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
		stateDir, overlay, _ := depsJournal(t, journal.Process{PID: other.Process.Pid, StartTicks: "1"}, false)
		err := RecoverLocked(stateDir)
		if !errors.Is(err, process.ErrPIDReused) || strings.Contains(err.Error(), "kept") {
			t.Fatalf("recovery = %v, want only the PID reuse reported", err)
		}
		if _, statErr := os.Stat(overlay); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("overlay kept for a process that is gone: %v", statErr)
		}
		if !runs(other.Process.Pid) {
			t.Fatal("recovery signalled the process that reuses the PID")
		}
	})
}

// Recovery deletes the journal's VNet before it decides whether a VM
// remains, so a kept probe address goes with its bridge; the message says so
// whenever an address (not only its containment) is kept behind a VNet.
func TestKeptProbeAddressMessageSaysTheVNetGoesAhead(t *testing.T) {
	withAddress := &journal.Record{SDNVNets: []string{"csVn01"}}
	withAddress.AddHostAddress("csVn01", "10.100.0.1/24")
	withContainment := &journal.Record{SDNVNets: []string{"csVn01"}}
	withContainment.AddHostContainment("csVn01", "10.100.0.1/24")
	noVNet := &journal.Record{}
	noVNet.AddHostAddress("csVn01", "10.100.0.1/24")

	if note := vnetDeletionNote(withAddress); !strings.Contains(note, "does not wait for the VMs") || !strings.Contains(note, "only the containment stays") {
		t.Errorf("note for a kept address behind a deleted VNet = %q", note)
	}
	if note := vnetDeletionNote(withContainment); note != "" {
		t.Errorf("note for a kept containment table alone = %q, want none: no address is on the bridge", note)
	}
	if note := vnetDeletionNote(noVNet); note != "" {
		t.Errorf("note for a journal without a VNet = %q, want none", note)
	}
}
