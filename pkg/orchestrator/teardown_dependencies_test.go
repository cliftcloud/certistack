// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/cleanup"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// teardownPVE answers a teardown: VM 9101 runs and its ownership cannot be
// read, so it cannot be destroyed; every other VM does not exist (an HTTP 404,
// which the cluster's resource list, naming 9101 alone, backs).
func teardownPVE(t *testing.T) *pve.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"vmid": 9101}}})
		case "/api2/json/nodes/node1/qemu/9101/status/current":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"status": "running"}})
		case "/api2/json/nodes/node1/qemu/9101/config":
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "message": "ownership read refused"})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"data":null,"errors":{"vmid":"does not exist"}}`))
		}
	}))
	t.Cleanup(server.Close)
	return pve.NewClient(pve.Config{BaseURL: server.URL})
}

func disposableOverlay(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func failedStep(failures []cleanup.StepError, prefix string) error {
	for _, failure := range failures {
		if strings.HasPrefix(failure.Step, prefix) {
			return failure.Err
		}
	}
	return nil
}

// A VM whose destruction failed may still be running, so teardown does not
// delete its overlay or remove the host probe address and its containment
// from the VNet it is on: what a VM uses stays until the VM is confirmed
// destroyed, and a VM that is confirmed destroyed releases its own.
func TestTeardownKeepsWhatAnUndestroyedVMUses(t *testing.T) {
	orch := New(ephemeralPlan(), Options{NodeName: "node1", StateDir: t.TempDir(), ScratchDir: t.TempDir()}, pbs.New(pbs.Config{}), teardownPVE(t))
	hosts := &fakeHostAddressManager{}
	orch.hostAddresses = hosts
	// setupNetwork registers the address's removal before any VM.
	orch.cleanup.Push("remove host probe address 10.100.0.1/24 from csVn01", func() error {
		return orch.removeHostAddress("csVn01", "10.100.0.1/24")
	})
	destroyed := disposableOverlay(t, "vm9102.qcow2")
	if err := orch.trackDeltaOverlay(9102, destroyed); err != nil {
		t.Fatal(err)
	}
	if err := orch.trackOwnedVM(9102); err != nil {
		t.Fatal(err)
	}
	survivor := disposableOverlay(t, "vm9101.qcow2")
	if err := orch.trackDeltaOverlay(9101, survivor); err != nil {
		t.Fatal(err)
	}
	if err := orch.trackOwnedVM(9101); err != nil {
		t.Fatal(err)
	}

	failures := orch.cleanup.Unwind()
	if failedStep(failures, "destroy VM 9101") == nil || failedStep(failures, "destroy VM 9102") != nil {
		t.Fatalf("teardown failures = %v, want VM 9101's destruction alone to fail", failures)
	}
	if _, err := os.Stat(survivor); err != nil {
		t.Fatalf("VM 9101's overlay was removed while the VM may run: %v", err)
	}
	if err := failedStep(failures, "remove delta overlay "+survivor); err == nil || !strings.Contains(err.Error(), "sandbox VM 9101 was not confirmed destroyed") {
		t.Fatalf("kept overlay reported as %v, want the VM that keeps it named", err)
	}
	if _, err := os.Stat(destroyed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destroyed VM 9102's overlay was kept: %v", err)
	}
	if len(hosts.removed) != 0 {
		t.Fatalf("host probe address removed with VM 9101 not confirmed destroyed: %v", hosts.removed)
	}
	if err := failedStep(failures, "remove host probe address"); err == nil || !strings.Contains(err.Error(), "kept host probe address 10.100.0.1/24 on csVn01 and its containment") {
		t.Fatalf("kept host probe address reported as %v", err)
	}
	remain := orch.sandboxVMsMayRemain()
	if remain == nil || !strings.Contains(remain.Error(), "9101") || strings.Contains(remain.Error(), "9102") {
		t.Fatalf("VMs that may remain = %v, want VM 9101 alone", remain)
	}
	if len(orch.record.DeltaFiles) != 2 || len(orch.record.VMs) != 2 || len(orch.record.HostAddresses) != 0 {
		// The journal is what recovery retries from; the host address is
		// journaled by setupNetwork, not by this test.
		t.Fatalf("journal = %+v, want both VMs and overlays kept", orch.record)
	}
}

// The control: with every VM confirmed destroyed, teardown releases all.
func TestTeardownReleasesWhatDestroyedVMsUsed(t *testing.T) {
	orch := New(ephemeralPlan(), Options{NodeName: "node1", StateDir: t.TempDir(), ScratchDir: t.TempDir()}, pbs.New(pbs.Config{}), teardownPVE(t))
	hosts := &fakeHostAddressManager{}
	orch.hostAddresses = hosts
	orch.cleanup.Push("remove host probe address 10.100.0.1/24 from csVn01", func() error {
		return orch.removeHostAddress("csVn01", "10.100.0.1/24")
	})
	overlay := disposableOverlay(t, "vm9102.qcow2")
	if err := orch.trackDeltaOverlay(9102, overlay); err != nil {
		t.Fatal(err)
	}
	if err := orch.trackOwnedVM(9102); err != nil {
		t.Fatal(err)
	}
	if failures := orch.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures = %v", failures)
	}
	if _, err := os.Stat(overlay); !errors.Is(err, os.ErrNotExist) || len(hosts.removed) != 1 || orch.sandboxVMsMayRemain() != nil {
		t.Fatalf("overlay %v, host removals %v, VMs that may remain %v; want all released", err, hosts.removed, orch.sandboxVMsMayRemain())
	}
}

// A VM whose teardown has not run (it panicked, say) is not confirmed
// destroyed either.
func TestVMWhoseTeardownDidNotRunMayRemain(t *testing.T) {
	orch := &Orchestrator{opts: Options{NodeName: "node1", StateDir: t.TempDir()}, cleanup: cleanup.New()}
	if err := orch.trackOwnedVM(9103); err != nil {
		t.Fatal(err)
	}
	if err := orch.keptForVM(9103, "overlay x"); err == nil || !strings.Contains(err.Error(), "its teardown did not run") {
		t.Fatalf("kept = %v, want the unrun teardown named", err)
	}
	if err := orch.keptForVM(9104, "overlay y"); err != nil {
		t.Fatalf("a VM never sent to PVE keeps its overlay: %v", err)
	}
}
