// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

const (
	teardownStopTask    = "UPID:node1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9200:root@pam:"
	teardownDestroyTask = "UPID:node1:0000A1B3:00C3D4E6:66A1B2C4:qmdestroy:9200:root@pam:"
	// An unrelated same-node task, well shaped, whose status reads stopped/OK.
	teardownForeignTask = "UPID:node1:00001234:00005678:00000001:vzdump:foreign-backup:root@pam:"
)

// destroyScenario scripts PVE for VM 9200 on node1, owned by run-test: a
// stop that succeeds and leaves the VM stopped, then a destroy that returns
// destroyHandle, whose task ends with taskExit ("OK" when unset), and after
// which the VM answers vmAfterDestroy: "stopped", "gone" or "unreadable".
type destroyScenario struct {
	destroyHandle  string
	taskExit       string
	vmAfterDestroy string

	mu        *sync.Mutex // set by client, so a scenario can be copied
	destroyed bool
}

func (s *destroyScenario) client(t *testing.T) *pve.Client {
	t.Helper()
	s.mu = new(sync.Mutex)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		answer := func(data any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": data}) }
		switch r.Method + " " + r.URL.Path {
		case "GET /api2/json/cluster/resources":
			// The cluster's list backs the HTTP 404 that "gone" is.
			if s.destroyed && s.vmAfterDestroy == "gone" {
				answer([]map[string]any{})
			} else {
				answer([]map[string]any{{"vmid": 9200}})
			}
		case "GET /api2/json/nodes/node1/qemu/9200/config":
			answer(map[string]any{"tags": "certistack,run-test", "description": "owner=certistack; run_id=run-test"})
		case "POST /api2/json/nodes/node1/qemu/9200/status/stop":
			answer(teardownStopTask)
		case "DELETE /api2/json/nodes/node1/qemu/9200":
			s.destroyed = true
			answer(s.destroyHandle)
		case "GET /api2/json/nodes/node1/qemu/9200/status/current":
			switch {
			case !s.destroyed:
				answer(map[string]any{"status": "stopped"})
			case s.vmAfterDestroy == "gone":
				w.WriteHeader(http.StatusNotFound)
				answer(nil)
			case s.vmAfterDestroy == "unreadable":
				w.WriteHeader(http.StatusForbidden)
				answer(nil)
			default:
				answer(map[string]any{"status": s.vmAfterDestroy})
			}
		default:
			if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/node1/tasks/") {
				exit := "OK"
				if s.taskExit != "" && strings.Contains(r.URL.Path, "qmdestroy") {
					exit = s.taskExit
				}
				answer(map[string]any{"status": "stopped", "exitstatus": exit, "node": "node1"})
				return
			}
			t.Errorf("unexpected PVE request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return pve.NewClient(pve.Config{BaseURL: server.URL})
}

// Teardown took a destroy task's success (or `qm destroy`'s exit
// status) for the VM's removal, and released what the VM uses while it still
// existed. The VM is now asked after every destroy, and only PVE's "does not
// exist" is success. The stop before it was never taken on a task's word:
// its outcome is discarded and the VM's status polled for "stopped".
func TestDestroyOwnedVMSucceedsOnlyWhenPVEConfirmsTheVMGone(t *testing.T) {
	for name, tc := range map[string]struct {
		scenario destroyScenario
		// wantErr is in the error; "" wants success.
		wantErr string
		// wantFallback: `qm destroy` ran.
		wantFallback bool
		// fallbackErr is `qm destroy`'s own result.
		fallbackErr error
	}{
		"destroy task succeeds and the VM is gone": {
			scenario: destroyScenario{destroyHandle: teardownDestroyTask, vmAfterDestroy: "gone"},
		},
		"destroy task fails but the VM is gone": {
			scenario: destroyScenario{destroyHandle: teardownDestroyTask, taskExit: "unable to remove VM 9200", vmAfterDestroy: "gone"},
		},
		"destroy task succeeds and the VM remains": {
			scenario: destroyScenario{destroyHandle: teardownDestroyTask, vmAfterDestroy: "stopped"},
			wantErr:  "the destroy task of VM 9200 reported success, but sandbox VM 9200 still exists (status: stopped)",
		},
		"destroy task succeeds and the VM cannot be read": {
			scenario: destroyScenario{destroyHandle: teardownDestroyTask, vmAfterDestroy: "unreadable"},
			wantErr:  "the destroy task of VM 9200 reported success, but sandbox VM 9200 cannot be confirmed gone",
		},
		"destroy task fails and the VM remains": {
			scenario: destroyScenario{destroyHandle: teardownDestroyTask, taskExit: "unable to remove VM 9200", vmAfterDestroy: "stopped"},
			wantErr:  "unable to remove VM 9200",
		},
		// The reporter's handle: an unrelated task that would report OK. It is
		// refused, and the fallback's exit status is no proof either.
		"unrelated task, and qm destroy exits 0 with the VM remaining": {
			scenario:     destroyScenario{destroyHandle: teardownForeignTask, vmAfterDestroy: "stopped"},
			wantFallback: true,
			wantErr:      `qm destroy of VM 9200 reported success (the API said: PVE answered the destruction of VM 9200 with a "vzdump" task for "foreign-backup"`,
		},
		"unrelated task, and qm destroy removes the VM": {
			scenario:     destroyScenario{destroyHandle: teardownForeignTask, vmAfterDestroy: "gone"},
			wantFallback: true,
		},
		"unrelated task, and qm destroy fails with the VM remaining": {
			scenario:     destroyScenario{destroyHandle: teardownForeignTask, vmAfterDestroy: "stopped"},
			fallbackErr:  errors.New("exit status 255"),
			wantFallback: true,
			wantErr:      "CLI: exit status 255",
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := tc.scenario
			fallbackRan := false
			orch := &Orchestrator{
				opts:      Options{NodeName: "node1"},
				pveClient: s.client(t),
				runQMFallbackFn: func(_ context.Context, args []string) ([]byte, error) {
					if args[0] == "destroy" {
						fallbackRan = true
						s.mu.Lock()
						s.destroyed = true
						s.mu.Unlock()
						return nil, tc.fallbackErr
					}
					return nil, nil
				},
			}
			err := orch.destroyOwnedVM(9200, "run-test")
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("destroyOwnedVM = %v, want success", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("destroyOwnedVM = %v, want an error containing %q", err, tc.wantErr)
			}
			if fallbackRan != tc.wantFallback {
				t.Errorf("qm destroy ran = %v, want %v", fallbackRan, tc.wantFallback)
			}
		})
	}
}

// End to end: a destroy task that succeeded for a VM that still
// exists keeps what the VM uses (the overlay, the host probe address), which
// released them before, and the teardown reports the VM.
func TestTeardownKeepsWhatAVMUsesWhenItsDestroyTaskLied(t *testing.T) {
	s := &destroyScenario{destroyHandle: teardownDestroyTask, vmAfterDestroy: "stopped"}
	orch := New(ephemeralPlan(), Options{NodeName: "node1", RunID: "run-test", StateDir: t.TempDir(), ScratchDir: t.TempDir()}, pbs.New(pbs.Config{}), s.client(t))
	hosts := &fakeHostAddressManager{}
	orch.hostAddresses = hosts
	orch.cleanup.Push("remove host probe address 10.100.0.1/24 from csVn01", func() error {
		return orch.removeHostAddress("csVn01", "10.100.0.1/24")
	})
	overlay := disposableOverlay(t, "vm9200.qcow2")
	if err := orch.trackDeltaOverlay(9200, overlay); err != nil {
		t.Fatal(err)
	}
	if err := orch.trackOwnedVM(9200); err != nil {
		t.Fatal(err)
	}

	failures := orch.cleanup.Unwind()
	if err := failedStep(failures, "destroy VM 9200"); err == nil || !strings.Contains(err.Error(), "reported success, but sandbox VM 9200 still exists") {
		t.Fatalf("teardown failures = %v, want the destroy step to name the VM that remains", failures)
	}
	if _, err := os.Stat(overlay); err != nil {
		t.Fatalf("overlay removed while VM 9200 exists: %v", err)
	}
	if len(hosts.removed) != 0 {
		t.Fatalf("host probe address removed while VM 9200 exists: %v", hosts.removed)
	}
	if remain := orch.sandboxVMsMayRemain(); remain == nil || !strings.Contains(remain.Error(), "9200") {
		t.Fatalf("VMs that may remain = %v, want VM 9200", remain)
	}
	if err := orch.verifyTrackedVMsAbsent(); err == nil || !strings.Contains(err.Error(), "remains") {
		t.Fatalf("the exact-VM sweep = %v, want it to fail as well", err)
	}
}

// What a VM that may remain shares on the host (the probe address and its
// containment) is kept, but the SDN zone and VNet are not held back: their
// deletion goes through, which removes the bridge and the address on it. The
// message says so, and so do the docs.
func TestSandboxVNetIsDeletedWhileAVMMayRemain(t *testing.T) {
	fake := sdntest.New()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), fake.Serve(t))
	hosts := &fakeHostAddressManager{}
	orch.hostAddresses = hosts
	if err := orch.setupNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A VM registered after the network, so its destruction runs first, and
	// fails.
	orch.vmTeardown = map[int]error{9101: errVMTeardownNotRun}
	orch.cleanup.Push("destroy VM 9101", func() error {
		err := errors.New("PVE refused the destruction")
		orch.vmTeardown[9101] = err
		return err
	})

	failures := orch.cleanup.Unwind()
	if len(hosts.removed) != 0 {
		t.Fatalf("host probe address removed while VM 9101 may remain: %v", hosts.removed)
	}
	kept := failedStep(failures, "remove host probe address")
	if kept == nil || !strings.Contains(kept.Error(), "kept host probe address 10.100.0.1/24 on csVn01 and its containment in place") ||
		!strings.Contains(kept.Error(), "the VNet's deletion does not wait for the VMs") {
		t.Fatalf("kept host probe address reported as %v, want it to say the VNet's deletion goes ahead", kept)
	}
	if failedStep(failures, "delete SDN VNet") != nil || failedStep(failures, "delete SDN zone") != nil {
		t.Fatalf("the VNet or zone deletion was held back: %v", failures)
	}
	writes := strings.Join(fake.Writes(), "; ")
	for _, want := range []string{"DELETE cluster/sdn/vnets/csVn01?", "DELETE cluster/sdn/zones/csSb01?"} {
		if !strings.Contains(writes, want) {
			t.Fatalf("SDN writes lack %q: %s", want, writes)
		}
	}
	if left := sandboxLeft(fake); len(left) > 0 {
		t.Fatalf("SDN objects left: %v", left)
	}
}
