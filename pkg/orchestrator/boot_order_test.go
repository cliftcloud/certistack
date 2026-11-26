// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// The VM the run creates boots the source's order of the restored disks, the
// record says so, and the record is what PVE was sent. A guest with
// /boot on a second disk ("boot: order=scsi0;scsi1") restored with only
// "order=scsi0" would never see scsi1 from SeaBIOS.

func sandboxFor(t *testing.T, vm config.VM, slots ...string) (probe.VMValidationRecord, map[string]any) {
	t.Helper()
	o := &Orchestrator{plan: &config.Plan{Network: config.Network{VNetID: "csVn01"}}, runID: "run-boot-order"}
	var disks []pve.DiskOverlay
	for _, slot := range slots {
		disks = append(disks, pve.DiskOverlay{Slot: slot, Path: "/tmp/delta-" + slot + ".qcow2"})
	}
	record := probe.VMValidationRecord{VMID: vm.VMID, Name: "restore", VerificationStatus: "verified", AllPassed: true}
	bootSlot, err := bootSlotFor(vm, sourceDrives(slots))
	if err != nil {
		t.Fatal(err)
	}
	cfg := o.sandboxVMWithEvidence(context.Background(), vm, disks, bootSlot, nil, &record)
	params, err := cfg.CreateParams()
	if err != nil {
		t.Fatal(err)
	}
	return record, params
}

func sourceDrives(slots []string) []config.SourceDrive {
	var drives []config.SourceDrive
	for _, slot := range slots {
		drives = append(drives, config.SourceDrive{Slot: slot, Archive: "drive-" + slot})
	}
	return drives
}

func TestSandboxVMBootsTheSourceOrderAndRecordsIt(t *testing.T) {
	for name, tc := range map[string]struct {
		vm    config.VM
		slots []string
		want  string
		order []string
	}{
		"/boot on the second disk":              {config.VM{VMID: 17615, BootDisk: "scsi0", BootOrder: []string{"scsi0", "scsi1"}}, []string{"scsi0", "scsi1"}, "order=scsi0;scsi1", []string{"scsi0", "scsi1"}},
		"second disk first":                     {config.VM{VMID: 17615, BootDisk: "scsi1", BootOrder: []string{"scsi1", "scsi0"}}, []string{"scsi0", "scsi1"}, "order=scsi1;scsi0", []string{"scsi1", "scsi0"}},
		"one disk":                              {config.VM{VMID: 17615, BootDisk: "scsi0", BootOrder: []string{"scsi0"}}, []string{"scsi0"}, "order=scsi0", []string{"scsi0"}},
		"a plan outside the worker: first disk": {config.VM{VMID: 17615}, []string{"scsi1", "scsi0"}, "order=scsi0", []string{"scsi0"}},
	} {
		t.Run(name, func(t *testing.T) {
			record, params := sandboxFor(t, tc.vm, tc.slots...)
			if params["boot"] != tc.want {
				t.Errorf("create request boot = %v, want %q", params["boot"], tc.want)
			}
			hw := record.RestoredHardware
			if hw == nil || !reflect.DeepEqual(hw.BootOrder, tc.order) || hw.BootDisk != tc.order[0] {
				t.Errorf("recorded boot disk and order %+v, want %q and %v", hw, tc.order[0], tc.order)
			}
		})
	}
}

// The report says the order: two VMs that differ only in the boot order
// sign different bytes, and the report carries the order that was sent.
func TestDifferentBootOrdersSignDifferentRestoredHardware(t *testing.T) {
	one, _ := sandboxFor(t, config.VM{VMID: 17615, BootDisk: "scsi0", BootOrder: []string{"scsi0"}}, "scsi0", "scsi1")
	both, _ := sandboxFor(t, config.VM{VMID: 17615, BootDisk: "scsi0", BootOrder: []string{"scsi0", "scsi1"}}, "scsi0", "scsi1")
	oneJSON, bothJSON := evidenceReportJSON(t, one), evidenceReportJSON(t, both)
	if bytes.Equal(oneJSON, bothJSON) {
		t.Fatal("VMs created with boot orders scsi0 and scsi0;scsi1 sign byte-identical reports")
	}
	if !bytes.Contains(bothJSON, []byte(`"boot_order":["scsi0","scsi1"]`)) || !bytes.Contains(oneJSON, []byte(`"boot_order":["scsi0"]`)) {
		t.Fatalf("the reports do not carry the boot order: %s", bothJSON)
	}
}
