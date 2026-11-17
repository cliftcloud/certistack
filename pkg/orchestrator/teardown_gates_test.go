// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pbs"
)

// A VM whose destruction failed may still be running, so teardown must not
// release what it uses. The release of each kind of resource asks whether a VM
// that uses it may remain (keptForVM). These tests cover three of those gates:
// the published overlay, firmware copy and disk copy (the files that matter
// once a creator's output is staged), the overlay directory, and the PBS map's
// loop device. Each registers the release exactly where the run does, lets the
// VM's teardown fail, and asserts that the resource is still there and that
// the failure names the VM.

// The published file of createTracked: an overlay, a firmware copy, a local
// copy of a disk.
func TestPublishedOverlayIsKeptWhileItsVMMayRemain(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the node worker needs Linux host memory and mount-table semantics")
	}
	orch := New(ephemeralPlan(), Options{NodeName: "node1", StateDir: t.TempDir(), ScratchDir: t.TempDir()}, pbs.New(pbs.Config{}), teardownPVE(t))
	dir := t.TempDir()
	published := func(vmid int, name string) string {
		final := filepath.Join(dir, name)
		if err := orch.createTracked(vmid, final, func(staging string) error {
			return os.WriteFile(staging, []byte("the run's overlay"), 0o600)
		}); err != nil {
			t.Fatal(err)
		}
		return final
	}
	// teardownPVE refuses VM 9101's ownership read, so it cannot be destroyed,
	// and has no VM 9102.
	survivor := published(9101, "certistack-delta-vm9101-scsi0-1-0.qcow2")
	destroyed := published(9102, "certistack-delta-vm9102-scsi0-1-0.qcow2")
	if err := orch.trackOwnedVM(9102); err != nil {
		t.Fatal(err)
	}
	if err := orch.trackOwnedVM(9101); err != nil {
		t.Fatal(err)
	}

	failures := orch.cleanup.Unwind()
	if _, err := os.Stat(survivor); err != nil {
		t.Fatalf("VM 9101's published overlay was removed while the VM may run: %v", err)
	}
	if err := failedStep(failures, "remove delta overlay "+survivor); err == nil || !strings.Contains(err.Error(), "sandbox VM 9101 was not confirmed destroyed") {
		t.Fatalf("kept overlay reported as %v (failures %v), want the VM that keeps it named", err, failures)
	}
	if _, err := os.Stat(destroyed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destroyed VM 9102's published overlay was kept: %v", err)
	}
}

// The directory a run made for a VM's overlays goes only once the VM is gone.
func TestOverlayDirectoryIsKeptWhileItsVMMayRemain(t *testing.T) {
	for name, tc := range map[string]struct {
		vmid     int   // the VM whose teardown result is set
		teardown error // its teardown result; nil is a destroyed VM
		kept     bool
	}{
		"the VM's destruction failed":    {vmid: 9101, teardown: errors.New("PVE refused the destruction"), kept: true},
		"the VM's teardown did not run":  {vmid: 9101, teardown: errVMTeardownNotRun, kept: true},
		"the VM is confirmed destroyed":  {vmid: 9101},
		"another VM's destruction fails": {vmid: 9102, teardown: errors.New("PVE refused the destruction")},
	} {
		t.Run(name, func(t *testing.T) {
			orch := artifactOrch(t)
			orch.preparedOverlayDirs = map[string]bool{}
			dir := filepath.Join(t.TempDir(), "images", "9101")
			if err := os.Mkdir(filepath.Dir(dir), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := orch.prepareOverlayDirOnce(dir, 9101); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(dir); err != nil {
				t.Fatalf("the directory was not made: %v", err)
			}
			orch.vmTeardown = map[int]error{tc.vmid: tc.teardown}

			failures := orch.cleanup.Unwind()
			_, statErr := os.Stat(dir)
			if tc.kept {
				if statErr != nil {
					t.Fatalf("the overlay directory was removed while VM 9101 may run: %v", statErr)
				}
				if err := failedStep(failures, "remove overlay directory"); err == nil || !strings.Contains(err.Error(), "kept overlay directory "+dir+" in place") || !strings.Contains(err.Error(), "sandbox VM 9101 was not confirmed destroyed") {
					t.Fatalf("kept directory reported as %v (failures %v), want it kept for VM 9101", err, failures)
				}
				return
			}
			if !errors.Is(statErr, os.ErrNotExist) || len(failures) != 0 {
				t.Fatalf("the directory of a VM that does not hold it: stat %v, failures %v; want it removed", statErr, failures)
			}
		})
	}
}

// The loop device of a PBS map goes only once the VM that boots from it is
// gone. The release is registered by the run where it records the map, so the
// test maps as the run does (the fixture's client makes /dev/loop7) and fails
// at the overlay, leaving the release on the cleanup stack.
func TestPBSMapIsKeptWhileItsVMMayRemain(t *testing.T) {
	t.Run("the VM may remain", func(t *testing.T) {
		f := newLoopFixture(t, "exit 0")
		o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
		f.mapAndFail(o)
		o.vmTeardown = map[int]error{9001: errors.New("PVE refused the destruction")}

		failures := o.cleanup.Unwind()
		if err := failedStep(failures, "unmap loop device /dev/loop7"); err == nil || !strings.Contains(err.Error(), "kept PBS map /dev/loop7 in place") || !strings.Contains(err.Error(), "sandbox VM 9001 was not confirmed destroyed") {
			t.Fatalf("kept map reported as %v (failures %v), want it kept for VM 9001", err, failures)
		}
		if calls := f.calls(); calls != "" {
			t.Fatalf("the map's loop was released while VM 9001 may boot from it:\n%s", calls)
		}
	})
	t.Run("the VM is confirmed destroyed", func(t *testing.T) {
		f := newLoopFixture(t, "exit 0")
		o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
		f.mapAndFail(o)
		o.vmTeardown = map[int]error{9001: nil}

		if failures := o.cleanup.Unwind(); len(failures) != 0 {
			t.Fatalf("teardown failures = %v", failures)
		}
		if calls := f.calls(); calls == "" {
			t.Fatal("the map of a destroyed VM was not released")
		}
	})
}
