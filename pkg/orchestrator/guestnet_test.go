// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// The overlays guest-network recovery opens are those of every
// restored disk, in the order the guest sees its disks, whatever order the
// plan lists them in.
func TestGuestNetworkOverlaysAreEveryRestoredDisk(t *testing.T) {
	disks := []pve.DiskOverlay{
		{Slot: "virtio0", Path: "/o/virtio0.qcow2"},
		{Slot: "scsi1", Path: "/o/scsi1.qcow2"},
		{Slot: "scsi0", Path: "/o/scsi0.qcow2"},
		{Slot: "ide0", Path: "/o/ide0.qcow2"},
	}
	got, err := guestNetworkOverlays(disks, "scsi0")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/o/ide0.qcow2", "/o/scsi0.qcow2", "/o/scsi1.qcow2", "/o/virtio0.qcow2"}; !slices.Equal(got, want) {
		t.Fatalf("overlays = %v, want every disk in slot order %v", got, want)
	}
	if disks[0].Slot != "virtio0" {
		t.Fatal("the caller's disk list was reordered")
	}

	// Fail closed: a disk without an overlay, or a boot disk that is not
	// among them, is an error, never a smaller list.
	if _, err := guestNetworkOverlays([]pve.DiskOverlay{{Slot: "scsi0", Path: "/o/scsi0.qcow2"}, {Slot: "scsi1"}}, "scsi0"); err == nil || !strings.Contains(err.Error(), "scsi1") {
		t.Fatalf("a disk without an overlay = %v, want it named", err)
	}
	if _, err := guestNetworkOverlays([]pve.DiskOverlay{{Slot: "scsi1", Path: "/o/scsi1.qcow2"}}, "scsi0"); err == nil || !strings.Contains(err.Error(), "scsi0") {
		t.Fatalf("a missing boot disk = %v, want it named", err)
	}
	if _, err := guestNetworkOverlays(nil, ""); err == nil {
		t.Fatal("no disks were accepted")
	}
}

// The call site. What the run hands the adapter carries every overlay,
// not the singular boot path the reporter found.
func TestGuestNetworkConfigCarriesEveryOverlay(t *testing.T) {
	plan := planTestPlan()
	vm := plan.Tiers[0].VMs[0]
	vm.MAC = "BC:24:11:90:01:01"
	vm.NetworkRecovery = config.NetworkRecovery{Mode: "networkmanager", InterfaceName: "eth0", CaptureDiagnostics: true}
	o := planOrchestrator(t, plan, planPVE(t, ""))
	overlays := []string{"/o/scsi0.qcow2", "/o/scsi1.qcow2"}
	var progress []string
	cfg := o.guestNetworkConfig(vm, "10.100.0.10", overlays, func(message string) { progress = append(progress, message) })
	if !slices.Equal(cfg.Overlays, overlays) {
		t.Fatalf("adapter overlays = %v, want %v", cfg.Overlays, overlays)
	}
	if cfg.VMID != 9001 || cfg.MAC != vm.MAC || cfg.Address != "10.100.0.10" || cfg.CIDR != "10.100.0.0/24" || cfg.ProbeIP != "10.100.0.1" ||
		cfg.Mode != "networkmanager" || cfg.InterfaceName != "eth0" || !cfg.OnlyNIC || !cfg.CaptureDiagnostics {
		t.Fatalf("adapter config = %+v", cfg)
	}
	cfg.Progress("x")
	if len(progress) != 1 {
		t.Fatal("the progress callback was not carried")
	}
}

// The planner reported case. A two-disk VM (scsi0 boots, scsi1 holds
// more of the guest) used to be previewed as a guest-network write against the
// boot overlay only, although the run creates an overlay for each disk. The
// step now names every overlay the run opens.
func TestPlanGuestNetworkStepNamesEveryOverlay(t *testing.T) {
	plan := planTestPlan()
	plan.Tiers[0].VMs[0].BootDisk = "scsi0"
	plan.Tiers[0].VMs[0].NetworkRecovery.Mode = "auto"
	plan.Tiers[0].VMs[0].NetworkRecovery.SandboxIP = "10.100.0.10"
	o := planOrchestrator(t, plan, planPVE(t, ""))
	preview, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var overlays []string
	var step *PlanStep
	for i, s := range preview.Steps {
		if s.Kind == "overlay" && s.Action == PlanCreate {
			overlays = append(overlays, s.Target)
		}
		if s.Kind == "guest-network" && s.Action == PlanWrite {
			step = &preview.Steps[i]
		}
	}
	if len(overlays) != 2 || step == nil {
		t.Fatalf("overlays = %v, guest-network step = %v", overlays, step)
	}
	if want := strings.Join(overlays, ", "); step.Target != want {
		t.Fatalf("guest-network target = %q, want every overlay the run creates, %q", step.Target, want)
	}
	if !strings.Contains(step.Target, "-scsi0-") || !strings.Contains(step.Target, "-scsi1-") || !strings.Contains(step.Detail, "all 2 restored disks") {
		t.Fatalf("guest-network step = %+v", *step)
	}
}
