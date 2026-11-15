// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"reflect"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// The worker carries the source's boot order, restricted to the disks the plan
// restores, to the VM it creates. It parses real qemu-server.conf text (the
// lines of fixture 7615 and its variants) and applies the layout the way the
// worker does.

const (
	rocky7615 = "boot: order=scsi0;scsi1\nscsi0: local-lvm:vm-7615-disk-0,size=20G\nscsi1: local-lvm:vm-7615-disk-1,size=1G\nnet0: virtio=BC:24:11:76:15:01,bridge=vmbr0\nscsihw: virtio-scsi-single\nostype: l26\n"
)

// bootVM applies the layout of conf to a VM that restores the named slots (all
// of the backup's disks when none is named).
func bootVM(t *testing.T, conf string, restore ...string) config.VM {
	t.Helper()
	layout, err := pbs.ParseVMLayout([]byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	if len(restore) == 0 {
		restore = layout.Disks
	}
	vm := config.VM{VMID: 17615, Name: "boot-order", SourcePBS: config.SourcePBS{Snapshot: "vm/7615/2026-09-30T00:00:00Z"}}
	for _, slot := range restore {
		vm.SourcePBS.Drives = append(vm.SourcePBS.Drives, config.SourceDrive{Slot: slot, Archive: "drive-" + slot})
	}
	if err := applySourceLayout(&vm, layout); err != nil {
		t.Fatal(err)
	}
	return vm
}

func TestSourceLayoutCarriesTheBootOrderOfTheRestoredDisks(t *testing.T) {
	disks2 := "scsi0: local-lvm:vm-1-disk-0,size=8G\nscsi1: local-lvm:vm-1-disk-1,size=8G\n"
	disks3 := disks2 + "scsi2: local-lvm:vm-1-disk-2,size=8G\n"
	for name, tc := range map[string]struct {
		conf     string
		restore  []string
		wantBoot string
		want     []string
	}{
		"fixture 7615: /boot on the second disk": {rocky7615, nil, "scsi0", []string{"scsi0", "scsi1"}},
		"one disk, network after it":             {"boot: order=scsi0;net0\nscsi0: local-lvm:vm-1-disk-0,size=8G\n", nil, "scsi0", []string{"scsi0"}},
		"second disk first":                      {"boot: order=scsi1;scsi0\n" + disks2, nil, "scsi1", []string{"scsi1", "scsi0"}},
		"cdrom and network are not disks":        {"boot: order=scsi0;ide2;net0\nide2: none,media=cdrom\nscsi0: local-lvm:vm-1-disk-0,size=8G\n", nil, "scsi0", []string{"scsi0"}},
		"a disk the plan omits":                  {"boot: order=scsi0;scsi1;scsi2\n" + disks3, []string{"scsi0", "scsi2"}, "scsi0", []string{"scsi0", "scsi2"}},
		"the boot disk is omitted":               {"boot: order=scsi1;scsi0\n" + disks2, []string{"scsi0"}, "scsi0", []string{"scsi0"}},
		"legacy bootdisk and no boot line":       {"bootdisk: scsi0\n" + disks2, nil, "scsi0", []string{"scsi0"}},
		"legacy boot: cdn with bootdisk":         {"boot: cdn\nbootdisk: scsi1\n" + disks2, nil, "scsi1", []string{"scsi1"}},
		"UEFI: efidisk0 is not in the order":     {"bios: ovmf\nboot: order=scsi0;net0\nefidisk0: local-lvm:vm-1-disk-0,efitype=4m,pre-enrolled-keys=1,size=4M\nscsi0: local-lvm:vm-1-disk-1,size=8G\nscsi1: local-lvm:vm-1-disk-2,size=8G\n", nil, "scsi0", []string{"scsi0"}},
		"UEFI with an ESP on the second disk":    {"bios: ovmf\nboot: order=scsi1;scsi0\nefidisk0: local-lvm:vm-1-disk-0,efitype=4m,size=4M\nscsi0: local-lvm:vm-1-disk-1,size=8G\nscsi1: local-lvm:vm-1-disk-2,size=8G\n", nil, "scsi1", []string{"scsi1", "scsi0"}},
		"the order names no restored disk":       {"boot: order=scsi0;net0\n" + disks3, []string{"scsi1"}, "scsi1", nil},
		"no boot setting at all":                 {disks3, []string{"scsi2", "scsi1"}, "scsi1", nil},
	} {
		t.Run(name, func(t *testing.T) {
			vm := bootVM(t, tc.conf, tc.restore...)
			if vm.BootDisk != tc.wantBoot || !reflect.DeepEqual(vm.BootOrder, tc.want) {
				t.Fatalf("boot disk %q, boot order %v; want %q, %v", vm.BootDisk, vm.BootOrder, tc.wantBoot, tc.want)
			}
		})
	}
}
