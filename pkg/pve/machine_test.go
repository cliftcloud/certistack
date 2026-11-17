// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// machineServer serves a VM config whose machine is stored, and records the
// config updates it receives. putStatus, when set, fails every update.
func machineServer(t *testing.T, stored string, putStatus int) (*httptest.Server, *[]map[string]interface{}) {
	t.Helper()
	var updates []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/nodes/pve1/qemu/17214/config" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		switch r.Method {
		case http.MethodGet:
			config := map[string]interface{}{"ostype": "win10"}
			if stored != "" {
				config["machine"] = stored
			}
			data, _ := json.Marshal(config)
			_ = json.NewEncoder(w).Encode(APIResponse{Data: data})
		case http.MethodPut:
			if putStatus != 0 {
				w.WriteHeader(putStatus)
				return
			}
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			updates = append(updates, body)
			_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`null`)})
		}
	}))
	t.Cleanup(server.Close)
	return server, &updates
}

// PVE pins a Windows guest's machine version on create (the backup's
// q35 became pc-q35-11.0+pve2) while a restore keeps q35, which PVE resolved
// to pc-q35-11.0+pve0 on the same nodes.
func TestKeepRequestedMachineUndoesTheCreatePin(t *testing.T) {
	for _, tc := range []struct {
		name, stored, requested string
		wantPinned              string
		wantUpdate              map[string]interface{}
	}{
		{"q35 pinned", "pc-q35-11.0+pve2", "q35", "pc-q35-11.0+pve2", map[string]interface{}{"machine": "q35"}},
		{"q35 with options pinned", "pc-q35-11.0+pve2,viommu=virtio", "q35,viommu=virtio", "pc-q35-11.0+pve2,viommu=virtio", map[string]interface{}{"machine": "q35,viommu=virtio"}},
		{"default pinned", "pc-i440fx-11.0+pve2", "", "pc-i440fx-11.0+pve2", map[string]interface{}{"delete": "machine"}},
		{"version kept", "pc-q35-8.1", "pc-q35-8.1", "", nil},
		{"linux unpinned", "q35", "q35", "", nil},
		{"linux default", "", "", "", nil},
	} {
		server, updates := machineServer(t, tc.stored, 0)
		client := NewClient(Config{BaseURL: server.URL})
		pinned, err := client.KeepRequestedMachine(context.Background(), "pve1", 17214, tc.requested)
		if err != nil || pinned != tc.wantPinned {
			t.Fatalf("%s: pinned = %q, %v; want %q", tc.name, pinned, err, tc.wantPinned)
		}
		if tc.wantUpdate == nil && len(*updates) != 0 || tc.wantUpdate != nil && (len(*updates) != 1 || !reflect.DeepEqual((*updates)[0], tc.wantUpdate)) {
			t.Fatalf("%s: updates = %v, want %v", tc.name, *updates, tc.wantUpdate)
		}
	}
}

func TestKeepRequestedMachineFallsBackToLocalQMOnlyWhenForbidden(t *testing.T) {
	server, _ := machineServer(t, "pc-q35-11.0+pve2", http.StatusForbidden)
	client := NewClient(Config{BaseURL: server.URL})
	client.isRootFn = func() bool { return true }
	client.isLocalNodeFn = func(string) bool { return true }
	var qmArgs []string
	client.runQMFn = func(_ context.Context, args []string) error {
		qmArgs = args
		return nil
	}
	if pinned, err := client.KeepRequestedMachine(context.Background(), "pve1", 17214, "q35"); err != nil || pinned != "pc-q35-11.0+pve2" {
		t.Fatalf("pinned = %q, %v", pinned, err)
	}
	if !reflect.DeepEqual(qmArgs, []string{"set", "17214", "--machine", "q35"}) {
		t.Fatalf("local qm args = %v", qmArgs)
	}

	failing, _ := machineServer(t, "pc-q35-11.0+pve2", http.StatusInternalServerError)
	client = NewClient(Config{BaseURL: failing.URL})
	client.runQMFn = func(context.Context, []string) error {
		t.Fatal("only a permission refusal may fall back to local qm")
		return nil
	}
	if _, err := client.KeepRequestedMachine(context.Background(), "pve1", 17214, "q35"); err == nil {
		t.Fatal("a failed reset must be reported")
	}
}

func TestVMStatusReadsTheRunningMachine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"vmid":17214,"status":"running","pid":4242,"running-machine":"pc-q35-11.0+pve0","running-qemu":"11.0.3"}}`))
	}))
	defer server.Close()
	status, err := NewClient(Config{BaseURL: server.URL}).GetVMStatus(context.Background(), "pve1", 17214)
	if err != nil || status.RunningMachine != "pc-q35-11.0+pve0" || status.RunningQEMU != "11.0.3" {
		t.Fatalf("status = %+v, %v", status, err)
	}
}

func TestQEMUMachinesListsTheNodesMachineIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/nodes/pve1/capabilities/qemu/machines" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"pc-q35-11.0","type":"q35","version":"11.0"},{"id":"pc-q35-11.0+pve2","type":"q35","version":"11.0+pve2"},{"id":"pc-i440fx-5.1","type":"i440fx","version":"5.1"}]}`))
	}))
	defer server.Close()
	ids, err := NewClient(Config{BaseURL: server.URL}).QEMUMachines(context.Background(), "pve1")
	if err != nil || !reflect.DeepEqual(ids, []string{"pc-q35-11.0", "pc-q35-11.0+pve2", "pc-i440fx-5.1"}) {
		t.Fatalf("ids = %v, %v", ids, err)
	}
}
