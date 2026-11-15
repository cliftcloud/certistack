// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
)

// Before its own work, a run recovers an unfinished run's journal and
// removes idle retained workspaces' credentials: the plan says what that
// would delete.
func TestPlanBeforeListsRecoveryAndRetainedCredentials(t *testing.T) {
	stateDir := t.TempDir()
	record := journal.Record{RunID: "run-old", Phase: "running", VMs: []journal.TrackedVM{{VMID: 17214}}, SDNOwner: "certistack run-old",
		Loops: []journal.TrackedLoop{{Device: "/dev/loop3"}}, SDNZones: []string{"csSb01"}, SDNVNets: []string{"csVn01"}, DeltaFiles: []string{"/scratch/certistack-delta-vm17214-scsi0-1-0.qcow2"},
		HostAddresses: []journal.TrackedHostAddress{{Interface: "csVn70", CIDR: "10.60.70.1/23"}}}
	record.AddMapIntent("vm/7214/2026-09-27T03:12:59Z", "drive-scsi1.img", `\x3a`, time.Now())
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	makeWorkspace(t, filepath.Join(stateDir, "workers"), "0b8e6c2e-8f65-4c55-9b0a-3f4f3c1f5a11", map[string]string{"runtime.env": "s"}, 2*time.Hour)

	var got []string
	steps, recovered := planBefore(stateDir, "", time.Now())
	for _, step := range steps {
		got = append(got, step.Action+" "+step.Kind+" "+step.Target)
	}
	joined := strings.Join(got, "\n")
	// The probe address's containment table goes with it.
	for _, want := range []string{"delete pve-vm VM 17214", "delete host-address 10.60.70.1/23", "delete nft-table inet csiso_", "delete pbs-map /dev/loop3", "delete pbs-map vm/7214/2026-09-27T03:12:59Z/drive-scsi1.img", "delete overlay /scratch/certistack-delta-vm17214-scsi0-1-0.qcow2", "delete sdn-zone csSb01", "delete workspace-credentials "} {
		if !strings.Contains(joined, want) {
			t.Errorf("before-the-run steps lack %q:\n%s", want, joined)
		}
	}
	// The run's own checks find what recovery deletes gone.
	if fmt.Sprint(recovered.VMIDs) != "[17214]" || fmt.Sprint(recovered.SDNIDs) != "[csSb01 csVn01]" {
		t.Errorf("recovered = %+v", recovered)
	}
	// Listing changes nothing.
	if _, err := os.Stat(filepath.Join(stateDir, "workers", "0b8e6c2e-8f65-4c55-9b0a-3f4f3c1f5a11", "runtime.env")); err != nil {
		t.Fatalf("planning removed a credential: %v", err)
	}

	// A cleaned journal and no idle workspace: nothing before the run.
	if err := journal.Write(filepath.Join(stateDir, "active.json"), journal.Record{RunID: "run-old", Phase: "cleaned"}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(stateDir, "workers")); err != nil {
		t.Fatal(err)
	}
	if steps, _ := planBefore(stateDir, "", time.Now()); len(steps) != 0 {
		t.Fatalf("steps before a clean run: %+v", steps)
	}
}

// A journal that names no ownership marker has recovery delete nothing PVE
// lists of its zone and VNet, so the plan does not list their deletion or count
// them as gone for the run's own availability check; it says what the operator
// does. A zone or VNet whose creation was never confirmed is one of the run's
// too.
func TestPlanBeforeListsWhatRecoveryLeavesAndWhatItSettles(t *testing.T) {
	stateDir := t.TempDir()
	write := func(r journal.Record) {
		t.Helper()
		if err := journal.Write(filepath.Join(stateDir, "active.json"), r); err != nil {
			t.Fatal(err)
		}
	}
	write(journal.Record{RunID: "run-old", Phase: "cleanup_failed", SDNZones: []string{"csSb01"}, SDNVNets: []string{"csVn01"}})
	steps, recovered := planBefore(stateDir, "", time.Now())
	var got []string
	for _, step := range steps {
		got = append(got, step.Action+" "+step.Kind+" "+step.Target+" | "+step.Detail)
	}
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "delete sdn-") || !strings.Contains(joined, "check journal SDN VNet csVn01") || !strings.Contains(joined, "check journal SDN zone csSb01") ||
		!strings.Contains(joined, "delete it in PVE") {
		t.Errorf("legacy journal steps:\n%s\nwant the zone and VNet left in place, with what the operator does", joined)
	}
	if len(recovered.SDNIDs) != 0 {
		t.Errorf("recovered %+v; want nothing counted as deleted by recovery", recovered)
	}

	write(journal.Record{RunID: "run-old", Phase: "cleanup_failed", SDNOwner: "certistack run-old", SDNZones: []string{"csSb01"}, AllocationPending: "SDN VNet csVn01"})
	steps, recovered = planBefore(stateDir, "", time.Now())
	got = nil
	for _, step := range steps {
		got = append(got, step.Action+" "+step.Kind+" "+step.Target)
	}
	joined = strings.Join(got, "\n")
	if !strings.Contains(joined, "delete sdn-vnet csVn01") || !strings.Contains(joined, "delete sdn-zone csSb01") || strings.Contains(joined, "unconfirmed allocation") {
		t.Errorf("steps:\n%s\nwant the unconfirmed VNet listed for deletion like the recorded zone, not as a stop", joined)
	}
	if fmt.Sprint(recovered.SDNIDs) != "[csSb01 csVn01]" || recovered.SDNOwner != "certistack run-old" {
		t.Errorf("recovered %+v", recovered)
	}
}

func TestWritePlan(t *testing.T) {
	p := &orchestrator.RunPlan{PlanID: "p1", Node: "pve1", Mode: "release",
		Steps: []orchestrator.PlanStep{
			{Phase: "sandbox network", Action: orchestrator.PlanCreate, Kind: "sdn-zone", Target: "csSb01", Detail: "simple zone"},
			{Phase: "VM 9001 (web01)", Action: orchestrator.PlanCheck, Kind: "vmid-free", Target: "VM 9002", Status: orchestrator.StatusFailed, Detail: "VM 9002 already exists"},
			{Phase: "VM 9001 (web01)", Action: orchestrator.PlanCheck, Kind: "copy-before-boot", Target: "VM 9003", Status: orchestrator.StatusWarning, Detail: "not copied"},
			{Phase: "VM 9001 (web01)", Action: orchestrator.PlanCreate, Kind: "overlay", Target: "/x.qcow2", Status: orchestrator.StatusNotReached},
			{Phase: "VM 9001 (web01)", Action: orchestrator.PlanCreate, Kind: "pve-vm", Target: "VM 9001", Params: map[string]string{"net0": "virtio,bridge=csVn01,firewall=1", "cores": "2"}},
			{Phase: "teardown", Action: orchestrator.PlanDelete, Kind: "pve-vm", Target: "VM 9001"},
		},
		Warnings: []string{"VM 9001's backup is crash-consistent"},
		Refusals: []string{"VM 9001 already exists in the PVE cluster"},
	}
	var out bytes.Buffer
	writePlan(&out, p)
	text := out.String()
	for _, want := range []string{
		`CertiStack plan "p1" on node pve1 (release)`, "Nothing has been changed.",
		"\nSandbox network\n  + create  sdn-zone             csSb01  (simple zone)",
		"        cores = 2\n        net0 = virtio,bridge=csVn01,firewall=1",
		"\nTeardown\n  - delete  pve-vm               VM 9001",
		"Warnings (1)\n  ! VM 9001's backup is crash-consistent",
		"A run would refuse this plan (1): it stops at the first ✗, and steps marked · are not reached\n  ✗ VM 9001 already exists",
		"  ✗ check   vmid-free            VM 9002  (VM 9002 already exists)",
		"  ! check   copy-before-boot     VM 9003  (not copied)",
		"  · create  overlay              /x.qcow2  [not reached]",
		"Summary: 2 to create, 0 to change inside the sandbox, 1 to delete",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("plan output lacks %q:\n%s", want, text)
		}
	}
}

// Recovery removes a journaled disk file without a recorded identity only when
// it is named as the run's disk files are; the plan says what recovery does
// with one that is not: it is left, and a run stops there.
func TestPlanSaysRecoveryLeavesAnUnidentifiedOverlayNotNamedAsTheRuns(t *testing.T) {
	stateDir := t.TempDir()
	record := journal.Record{RunID: "run-old", Phase: "running", DeltaFiles: []string{"/var/lib/vz/images/100/vm-100-disk-0.qcow2", "/scratch/certistack-delta-vm9100-scsi0-1-0.qcow2"}}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	steps, _, stops := planBeforeChecked(stateDir, "", time.Now())
	var foreign, ours *orchestrator.PlanStep
	for i := range steps {
		switch steps[i].Target {
		case record.DeltaFiles[0]:
			foreign = &steps[i]
		case record.DeltaFiles[1]:
			ours = &steps[i]
		}
	}
	if foreign == nil || foreign.Action == orchestrator.PlanDelete || foreign.Status != orchestrator.StatusFailed || !strings.Contains(foreign.Detail, "recovery leaves it") {
		t.Fatalf("step for the foreign file = %+v; want a failed check that says recovery leaves it", foreign)
	}
	if ours == nil || ours.Action != orchestrator.PlanDelete {
		t.Fatalf("step for the run's overlay = %+v; want a delete", ours)
	}
	if len(stops) != 1 || !strings.Contains(stops[0], record.DeltaFiles[0]) {
		t.Fatalf("stops = %q; want the run to stop for the foreign file", stops)
	}
}

// A journaled loop on a file that is not a PBS map is left attached by
// recovery; the plan says so instead of listing it for deletion.
func TestPlanSaysRecoveryLeavesALoopNotOnAPBSMapFile(t *testing.T) {
	stateDir := t.TempDir()
	record := journal.Record{RunID: "run-old", Phase: "running", Loops: []journal.TrackedLoop{{Device: "/dev/loop5", Backing: "/srv/disk.img"}, {Device: "/dev/loop6", Backing: "/run/pbs-loopdev/repo.img"}}}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	steps, _ := planBefore(stateDir, "", time.Now())
	var got []string
	for _, step := range steps {
		got = append(got, step.Action+" "+step.Kind+" "+step.Target+" "+step.Status)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, orchestrator.PlanCheck+" journal /dev/loop5 "+orchestrator.StatusWarning) || strings.Contains(joined, "delete pbs-map /dev/loop5") || !strings.Contains(joined, "delete pbs-map /dev/loop6") {
		t.Fatalf("steps:\n%s", joined)
	}
}
