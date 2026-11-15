// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// At the call site: the signed record of a VM's hardware and the create
// request PVE receives are the same thing. The two regression tests of the fix
// built the record by calling the helper directly, so reverting the call in
// bootAndVerifyVM to a record without the CPU weight kept the whole package green.
// This drives bootAndVerifyVM itself, through the map, the overlay and the scan, to
// PVE's create request, which a fake answers by refusing after it has read the
// body, and compares the record the run returned with that body.
func TestTheRunsRestoredHardwareIsWhatCreateVMSent(t *testing.T) {
	for _, weight := range []int{0, 50, 500} {
		t.Run(fmt.Sprintf("cpu weight %d", weight), func(t *testing.T) {
			f := newLoopFixture(t, "exit 0")
			qemuImg := "#!/bin/sh\nfor last; do :; done\n: > \"$last\"\n"
			if err := os.WriteFile(filepath.Join(filepath.Dir(f.log), "qemu-img"), []byte(qemuImg), 0o755); err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var created map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.Method + " " + r.URL.Path {
				case "GET /api2/json/cluster/resources":
					_, _ = w.Write([]byte(`{"data":[]}`))
				case "GET /api2/json/nodes/localhost/qemu/9001/status/current":
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"data":null,"message":"Configuration file 'nodes/localhost/qemu-server/9001.conf' does not exist"}`))
				case "POST /api2/json/nodes/localhost/qemu":
					mu.Lock()
					defer mu.Unlock()
					created = map[string]any{}
					_ = json.NewDecoder(r.Body).Decode(&created)
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"data":null,"message":"the create request is refused after it was read"}`))
				default:
					t.Errorf("unexpected PVE request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)

			o := New(&config.Plan{Network: config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"}},
				Options{NodeName: "localhost", StateDir: t.TempDir(), ScratchDir: t.TempDir()}, pbs.New(pbs.Config{Repository: "u@pbs!tok@pbs.example:store"}), pve.NewClient(pve.Config{BaseURL: server.URL}))
			if err := os.Chmod(o.opts.ScratchDir, 0o700); err != nil {
				t.Fatal(err)
			}
			o.verifyImageFn = func(_ context.Context, snapshot, _ string, _ pbs.DiskSize, _ func(int64)) (*pbs.VerifySummary, string, error) {
				return &pbs.VerifySummary{Snapshot: snapshot, Passed: true, Detail: "synthetic scan"}, "digest", nil
			}
			vm := mapTestVM()
			vm.NetworkRecovery = config.NetworkRecovery{Mode: "preserve"}
			vm.CopyBeforeBoot = config.CopyBeforeBootNever
			vm.HardwareOverrides = config.HardwareOverrides{Cores: 4, Sockets: 2, MemoryMB: 8192, BalloonMB: 4096, CPUWeight: weight}

			record, err := o.bootAndVerifyVM(context.Background(), vm, 60, nil)
			if err == nil || !strings.Contains(err.Error(), "PVE CreateVM error") || record == nil {
				t.Fatalf("bootAndVerifyVM = %+v, %v; want the run to reach the create request and be refused there", record, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if created == nil {
				t.Fatalf("PVE never received a create request (the run ended with %v)", err)
			}
			recorded := record.RestoredHardware
			if recorded == nil {
				t.Fatal("the run's record has no restored hardware: it was not built from the create request")
			}
			want := weight
			if want == 0 {
				want = 50 // the orchestrator's default
			}
			for key, got := range map[string]any{
				"cpuunits": float64(recorded.CPUWeight),
				"cores":    float64(recorded.Cores),
				"sockets":  float64(recorded.Sockets),
				"memory":   float64(recorded.MemoryMB),
			} {
				if created[key] != got {
					t.Errorf("create request %s = %v, but the record says %v: the signed hardware is not what PVE was asked for", key, created[key], got)
				}
			}
			if recorded.CPUWeight != want || created["cpuunits"] != float64(want) {
				t.Errorf("CPU weight recorded %d and sent %v, want %d in both", recorded.CPUWeight, created["cpuunits"], want)
			}
			// The boot order the record names is the one PVE got.
			if len(recorded.BootOrder) == 0 || recorded.BootOrder[0] != recorded.BootDisk || created["boot"] != "order="+strings.Join(recorded.BootOrder, ";") {
				t.Errorf("boot order recorded %v (boot disk %q) and sent %v, want the same order in both", recorded.BootOrder, recorded.BootDisk, created["boot"])
			}
		})
	}
}
