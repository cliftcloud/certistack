// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// The balloon device's presence follows the backup, on both the
// layout-only path and use_backup_config's profile path.
func TestApplySourceLayoutCarriesBalloonDevicePresence(t *testing.T) {
	for _, noBalloon := range []bool{true, false} {
		vm := &config.VM{VMID: 7214, Name: "win", SourcePBS: config.SourcePBS{Drive: "drive-scsi0.img.fidx"}}
		if err := applySourceLayout(vm, pbs.VMLayout{Disks: []string{"scsi0"}, NoBalloon: noBalloon}); err != nil {
			t.Fatal(err)
		}
		if vm.NoBalloon != noBalloon {
			t.Fatalf("layout NoBalloon %v: vm.NoBalloon = %v", noBalloon, vm.NoBalloon)
		}
		if got := layoutOf(pbs.VMProfile{NoBalloon: noBalloon}).NoBalloon; got != noBalloon {
			t.Fatalf("profile NoBalloon %v: layout NoBalloon = %v", noBalloon, got)
		}
	}
}

// The controller names the run so it can find its own journal; the
// name goes into PVE tags and descriptions, so only a safe one is accepted.
func TestRunRefusesAnUnsafeRunID(t *testing.T) {
	for _, id := range []string{"run 1", "run-", "x-1", "run-a;b", "run-" + strings.Repeat("a", 80)} {
		if _, err := run(context.Background(), &config.Plan{}, Options{RunID: id}); err == nil || !strings.Contains(err.Error(), "invalid run ID") {
			t.Fatalf("run ID %q: err = %v", id, err)
		}
	}
	if !runIDExpr.MatchString("run-2f1c6d0e-5b7a-4c1e-9d3f-8a2b4c6d8e0f") {
		t.Fatal("a controller run ID is refused")
	}
}

// The SMBIOS identity follows the backup on both paths.
func TestApplySourceLayoutCarriesSMBIOSIdentity(t *testing.T) {
	const smbios1 = "uuid=8b0e2d6a-4f1c-4c3e-9a55-0d2b8c6e7f10"
	vm := &config.VM{VMID: 7214, Name: "win", SourcePBS: config.SourcePBS{Drive: "drive-scsi0.img.fidx"}}
	if err := applySourceLayout(vm, pbs.VMLayout{Disks: []string{"scsi0"}, SMBIOS1: smbios1}); err != nil || vm.SMBIOS1 != smbios1 {
		t.Fatalf("vm.SMBIOS1 = %q, %v", vm.SMBIOS1, err)
	}
	if got := layoutOf(pbs.VMProfile{SMBIOS1: smbios1}).SMBIOS1; got != smbios1 {
		t.Fatalf("profile path SMBIOS1 = %q", got)
	}
}

// The backup's meta line follows it on both paths.
func TestApplySourceLayoutCarriesMeta(t *testing.T) {
	const meta = "creation-qemu=9.0.2,ctime=1726000000"
	vm := &config.VM{VMID: 7214, Name: "win", SourcePBS: config.SourcePBS{Drive: "drive-scsi0.img.fidx"}}
	if err := applySourceLayout(vm, pbs.VMLayout{Disks: []string{"scsi0"}, Meta: meta}); err != nil || vm.SourceMeta != meta {
		t.Fatalf("vm.SourceMeta = %q, %v", vm.SourceMeta, err)
	}
	if got := layoutOf(pbs.VMProfile{Meta: meta}).Meta; got != meta {
		t.Fatalf("profile path Meta = %q", got)
	}
}

func TestApplySourceLayoutCarriesCDROMs(t *testing.T) {
	vm := &config.VM{VMID: 7214, Name: "win", SourcePBS: config.SourcePBS{Drive: "drive-scsi0.img.fidx"}}
	if err := applySourceLayout(vm, pbs.VMLayout{Disks: []string{"scsi0"}, CDROMs: []string{"sata0"}}); err != nil || strings.Join(vm.SourceCDROMs, ",") != "sata0" {
		t.Fatalf("vm.SourceCDROMs = %v, %v", vm.SourceCDROMs, err)
	}
	if got := layoutOf(pbs.VMProfile{CDROMs: []string{"ide2"}}).CDROMs; strings.Join(got, ",") != "ide2" {
		t.Fatalf("profile path CDROMs = %v", got)
	}
}

func TestLayoutOfCarriesDiskSizes(t *testing.T) {
	layout := layoutOf(pbs.VMProfile{Drives: []pbs.SourceDrive{{Slot: "scsi0"}}, DiskBytes: map[string]int64{"scsi0": 32 << 30}})
	if layout.DiskBytes["scsi0"] != 32<<30 {
		t.Fatalf("DiskBytes = %v", layout.DiskBytes)
	}
}
