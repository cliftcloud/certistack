// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pbs"
)

// Teardown returned success when the stop or the destroy answered 404, without
// reading the VM again: the overlay and the host probe address of a VM that
// still ran were released, and only the final sweep reported it. The answer is
// now taken for the end of the VM only when a fresh read of the VM agrees, and
// otherwise the teardown goes on to stop and destroy it.
func TestTeardownRereadsTheVMWhenTheStopOrTheDestroyAnswers404(t *testing.T) {
	t.Run("the stop answers 404 and the VM runs", func(t *testing.T) {
		// The cluster's list is empty: the 404 is "backed", and only the
		// re-read of the VM's own status says it still runs.
		f := &notFoundPVE{status: "running", stop404: true, list: ids()}
		qm := []string{}
		orch := &Orchestrator{opts: Options{NodeName: "node1"}, pveClient: f.client(t)}
		orch.runQMFallbackFn = func(_ context.Context, args []string) ([]byte, error) {
			qm = append(qm, strings.Join(args, " "))
			if args[0] == "stop" {
				f.mu.Lock()
				f.status = "stopped"
				f.mu.Unlock()
			}
			return nil, nil
		}
		if err := orch.destroyOwnedVM(9101, "run-test"); err != nil {
			t.Fatalf("destroyOwnedVM = %v; the VM is stopped by the fallback and destroyed by the API", err)
		}
		if len(qm) == 0 || qm[0] != "stop 9101 --skiplock 1" {
			t.Fatalf("qm calls = %v; want the stop that the 404 did not do", qm)
		}
		if !f.called("DELETE ") || f.status != "gone" {
			t.Fatalf("the VM was not destroyed after the stop (status %q): %v", f.status, f.calls)
		}
	})

	t.Run("the destroy answers 404 and the VM exists", func(t *testing.T) {
		f := &notFoundPVE{status: "stopped", destroy404: true, list: ids()}
		qm := []string{}
		orch := &Orchestrator{opts: Options{NodeName: "node1"}, pveClient: f.client(t)}
		orch.runQMFallbackFn = func(_ context.Context, args []string) ([]byte, error) {
			qm = append(qm, strings.Join(args, " "))
			if args[0] == "destroy" {
				f.mu.Lock()
				f.status = "gone"
				f.mu.Unlock()
			}
			return nil, nil
		}
		if err := orch.destroyOwnedVM(9101, "run-test"); err != nil {
			t.Fatalf("destroyOwnedVM = %v", err)
		}
		if got := strings.Join(qm, ";"); !strings.Contains(got, "destroy 9101") {
			t.Fatalf("qm calls = %v; want the destroy that the 404 did not do", qm)
		}
	})

	t.Run("nothing removes the VM: what it uses stays", func(t *testing.T) {
		f := &notFoundPVE{status: "running", stop404: true, destroy404: true, list: ids()}
		orch := New(ephemeralPlan(), Options{NodeName: "node1", RunID: "run-test", StateDir: t.TempDir(), ScratchDir: t.TempDir()}, pbs.New(pbs.Config{}), f.client(t))
		hosts := &fakeHostAddressManager{}
		orch.hostAddresses = hosts
		orch.runQMFallbackFn = func(_ context.Context, args []string) ([]byte, error) {
			if args[0] == "stop" {
				f.mu.Lock()
				f.status = "stopped"
				f.mu.Unlock()
			}
			return nil, errors.New("qm destroy: exit status 255")
		}
		orch.cleanup.Push("remove host probe address 10.100.0.1/24 from csVn01", func() error {
			return orch.removeHostAddress("csVn01", "10.100.0.1/24")
		})
		overlay := disposableOverlay(t, "vm9101.qcow2")
		if err := orch.trackDeltaOverlay(9101, overlay); err != nil {
			t.Fatal(err)
		}
		if err := orch.trackOwnedVM(9101); err != nil {
			t.Fatal(err)
		}
		failures := orch.cleanup.Unwind()
		if failedStep(failures, "destroy VM 9101") == nil {
			t.Fatalf("teardown failures = %v, want the VM's destruction reported", failures)
		}
		if _, err := os.Stat(overlay); err != nil {
			t.Fatalf("the overlay of a VM that was not removed was released: %v", err)
		}
		if len(hosts.removed) != 0 {
			t.Fatalf("host probe address removed with the VM not confirmed destroyed: %v", hosts.removed)
		}
	})
}
