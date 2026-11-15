// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// haltPVE answers every VM status read with qmpstatus, as PVE does: status
// stays "running" while QEMU has stopped the guest.
func haltPVE(t *testing.T, status, qmpstatus string) *pve.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status/current") {
			_, _ = w.Write([]byte(`{"data":{"status":"` + status + `","qmpstatus":"` + qmpstatus + `"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	return pve.NewClient(pve.Config{BaseURL: server.URL})
}

func fastHaltPolls(t *testing.T) {
	t.Helper()
	old := haltPollInterval
	haltPollInterval = 20 * time.Millisecond
	t.Cleanup(func() { haltPollInterval = old })
}

func TestAStatusReadCannotOutliveItsOwnBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	o := New(&config.Plan{}, Options{NodeName: "pve1"}, nil, pve.NewClient(pve.Config{BaseURL: server.URL}))
	obs := &vmObservation{started: time.Now()}
	started := time.Now()
	_ = o.observeVMWithin(context.Background(), 100, obs, time.Now().Add(50*time.Millisecond))
	if time.Since(started) > 2*time.Second {
		t.Fatal("status read inherited the client's minute-long timeout")
	}
	if obs.reads != 1 || obs.failed != 1 || obs.ok() {
		t.Fatalf("a timed-out read was treated as evidence: %+v", obs)
	}
}

// A guest stopped on a write to a full overlay storage is named
// as such, with the room left where its overlays are.
func TestVMHaltedNamesAFullOverlayStorage(t *testing.T) {
	o := New(&config.Plan{}, Options{NodeName: "pve1", OverlayStorage: "cs-drill-full", StateDir: t.TempDir()}, nil, haltPVE(t, "running", "io-error"))
	o.overlayVolumePathFn = func(context.Context, string) (string, error) {
		return "/mnt/drill/images/1/certistack-storage-check.qcow2", nil
	}
	o.freeBytesFn = func(string) (int64, error) { return 1 << 20, nil }
	err := o.vmHalted(context.Background(), 817214)
	var halt *vmHaltedError
	if !errors.As(err, &halt) || !strings.Contains(err.Error(), "VM 817214 stopped on a disk write error") || !strings.Contains(err.Error(), "overlay storage cs-drill-full, which has 1 MiB free (/mnt/drill)") {
		t.Fatalf("halt = %v", err)
	}
	for qmp, want := range map[string]string{"guest-panicked": "guest OS crashed", "internal-error": "QEMU internal error", "shutdown": "no longer running"} {
		o.pveClient = haltPVE(t, "running", qmp)
		if err := o.vmHalted(context.Background(), 9001); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", qmp, err)
		}
	}
	o.pveClient = haltPVE(t, "running", "running")
	if err := o.vmHalted(context.Background(), 9001); err != nil {
		t.Errorf("a running VM halted: %v", err)
	}
}

// The grace wait ends as soon as every VM it watches has stopped, and says
// which.
func TestWaitWatchingVMsStopsEarly(t *testing.T) {
	fastHaltPolls(t)
	o := New(&config.Plan{}, Options{NodeName: "pve1", ScratchDir: "/var/lib/certistack/scratch", StateDir: t.TempDir()}, nil, haltPVE(t, "running", "io-error"))
	o.freeBytesFn = func(string) (int64, error) { return 0, errors.New("unknown") }
	start := time.Now()
	halted, err := o.waitWatchingVMs(context.Background(), time.Minute, []int{9001, 9002})
	if err != nil || len(halted) != 2 || time.Since(start) > 10*time.Second {
		t.Fatalf("halted %v, err %v, after %s", halted, err, time.Since(start))
	}
	if !strings.Contains(halted[9001].Error(), "the scratch directory /var/lib/certistack/scratch: check that it has not filled up") {
		t.Errorf("halt = %v", halted[9001])
	}
}

// A probe of a stopped guest ends when the stop is seen, with its reason,
// instead of running to its timeout as a network error.
func TestProbesEndWhenTheGuestStops(t *testing.T) {
	fastHaltPolls(t)
	o := New(&config.Plan{}, Options{NodeName: "pve1", StateDir: t.TempDir()}, nil, haltPVE(t, "running", "io-error"))
	o.freeBytesFn = func(string) (int64, error) { return 0, errors.New("unknown") }
	vm := config.VM{VMID: 9001, Probes: []config.Probe{
		{Type: "tcp", TargetIP: "127.0.0.1", Port: 1, TimeoutSec: 60, Description: "ssh"},
		{Type: "tcp", TargetIP: "127.0.0.1", Port: 1, TimeoutSec: 60, Description: "http"},
	}}
	start := time.Now()
	results, passed, err := o.runProbes(context.Background(), vm)
	if passed || err == nil || time.Since(start) > 30*time.Second {
		t.Fatalf("passed %v err %v after %s", passed, err, time.Since(start))
	}
	if len(results) != 1 || !strings.Contains(results[0].Error, "stopped on a disk write error") {
		t.Fatalf("results = %+v", results)
	}
	if n := strings.Count(err.Error(), "stopped on a disk write error"); n != 1 {
		t.Errorf("the stop is reported %d times: %v", n, err)
	}
}
