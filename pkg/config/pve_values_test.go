// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"strings"
	"testing"
)

// validate holds machine, ostype, bios and scsihw to Proxmox VE's values, so a
// typo is refused with the field's name and not when the run creates the VM.
func TestValidateHoldsPVEValuesToPVEsOwn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		set   func(*VM)
		field string // the field the loader names; "" when the plan is valid
		want  string // text the message holds
	}{
		{"ostype l26", func(v *VM) { v.OSType = "l26" }, "", ""},
		{"ostype win11", func(v *VM) { v.OSType = "win11" }, "", ""},
		{"ostype solaris", func(v *VM) { v.OSType = "solaris" }, "", ""},
		{"ostype linux", func(v *VM) { v.OSType = "linux" }, "ostype", "l26"},
		{"ostype in upper case", func(v *VM) { v.OSType = "L26" }, "ostype", "other, wxp"},
		{"ostype windows", func(v *VM) { v.OSType = "windows" }, "ostype", "win10"},
		{"bios ovmf", func(v *VM) { v.BIOS = "ovmf" }, "", ""},
		{"bios seabios", func(v *VM) { v.BIOS = "seabios" }, "", ""},
		{"bios uefi", func(v *VM) { v.BIOS = "uefi" }, "bios", "seabios, ovmf"},
		{"scsihw virtio-scsi-single", func(v *VM) { v.SCSIHW = "virtio-scsi-single" }, "", ""},
		{"scsihw pvscsi", func(v *VM) { v.SCSIHW = "pvscsi" }, "", ""},
		{"scsihw virtio", func(v *VM) { v.SCSIHW = "virtio" }, "scsihw", "virtio-scsi-pci"},
		{"scsihw lsi53c895a", func(v *VM) { v.SCSIHW = "lsi53c895a" }, "scsihw", "lsi53c810"},
		{"machine q35", func(v *VM) { v.Machine = "q35" }, "", ""},
		{"machine pc", func(v *VM) { v.Machine = "pc" }, "", ""},
		{"machine pc-i440fx-9.2", func(v *VM) { v.Machine = "pc-i440fx-9.2" }, "", ""},
		{"machine pc-i440fx-2.12", func(v *VM) { v.Machine = "pc-i440fx-2.12" }, "", ""},
		{"machine pc-4.1", func(v *VM) { v.Machine = "pc-4.1" }, "", ""},
		{"machine pc-q35-8.1+pve1", func(v *VM) { v.Machine = "pc-q35-8.1+pve1" }, "", ""},
		{"machine pc-q35-9.2+pve12", func(v *VM) { v.Machine = "pc-q35-9.2+pve12" }, "", ""},
		{"machine pc-q35-6.2.pxe", func(v *VM) { v.Machine = "pc-q35-6.2.pxe" }, "", ""},
		{"machine virt-9.2", func(v *VM) { v.Machine = "virt-9.2" }, "", ""},
		{"machine type= form", func(v *VM) { v.Machine = "type=q35" }, "", ""},
		{"machine with viommu virtio", func(v *VM) { v.Machine = "q35,viommu=virtio" }, "", ""},
		{"machine with viommu intel on q35", func(v *VM) { v.Machine = "pc-q35-9.2+pve1,viommu=intel" }, "", ""},
		{"machine with an option and a width", func(v *VM) { v.Machine = "type=q35,viommu=intel,aw-bits=48" }, "", ""},
		{"machine with s3 off", func(v *VM) { v.Machine = "q35,enable-s3=0,enable-s4=false" }, "", ""},
		{"machine with an option this release does not know", func(v *VM) { v.Machine = "q35,somethingnew=1" }, "", ""},
		{"machine q36", func(v *VM) { v.Machine = "q36" }, "machine", `"q36"`},
		{"machine in upper case", func(v *VM) { v.Machine = "Q35" }, "machine", `"Q35"`},
		{"machine pc-q35 without a version", func(v *VM) { v.Machine = "pc-q35" }, "machine", "pc-q35-9.2+pve1"},
		{"machine with an empty revision", func(v *VM) { v.Machine = "pc-q35-9.2+pve" }, "machine", "pc-q35-9.2+pve"},
		{"machine with a trailing space", func(v *VM) { v.Machine = "q35 " }, "machine", "q35 "},
		{"machine longer than PVE allows", func(v *VM) { v.Machine = "pc-q35-" + strings.Repeat("1.", 20) + "1" }, "machine", "which is not one Proxmox VE has"},
		{"machine with viommu amd", func(v *VM) { v.Machine = "q35,viommu=amd" }, "machine", "viommu=intel or viommu=virtio"},
		{"machine with viommu intel on pc", func(v *VM) { v.Machine = "pc,viommu=intel" }, "machine", "needs a q35 machine type"},
		{"machine with a width and no viommu", func(v *VM) { v.Machine = "q35,aw-bits=48" }, "machine", "without viommu"},
		{"machine with an Intel width PVE refuses", func(v *VM) { v.Machine = "q35,viommu=intel,aw-bits=40" }, "machine", "39 or 48"},
		{"machine with s3 not a boolean", func(v *VM) { v.Machine = "q35,enable-s3=maybe" }, "machine", "enable-s3=maybe"},
		{"machine with a space after the comma", func(v *VM) { v.Machine = "q35, viommu=virtio" }, "machine", "no spaces"},
		{"machine with the type after an option", func(v *VM) { v.Machine = "viommu=virtio,q35" }, "machine", `"q35" after the machine type`},
		{"machine with an option without a value", func(v *VM) { v.Machine = "q35,viommu=" }, "machine", "no value"},
		{"machine with an option twice", func(v *VM) { v.Machine = "q35,viommu=virtio,viommu=intel" }, "machine", "twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := validPlan()
			tc.set(&plan.Tiers[0].VMs[0])
			var got []ValidationError
			for _, e := range Validate(plan) {
				if strings.HasPrefix(e.Field, "tiers[0].vms[0].") {
					got = append(got, e)
				}
			}
			if tc.field == "" {
				if len(got) > 0 {
					t.Fatalf("PVE takes this, validate refused it: %v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Field != "tiers[0].vms[0]."+tc.field || !strings.Contains(got[0].Message, tc.want) {
				t.Fatalf("errors = %v, want one on %s that says %q", got, tc.field, tc.want)
			}
		})
	}
}

// Every value of PVE's own lists is taken, and a plan that gives none of the four
// is not judged.
func TestEveryPVEValueIsAccepted(t *testing.T) {
	for _, list := range [][]string{pveOSTypes, pveBIOS, pveSCSIHW} {
		for _, value := range list {
			if problem := pveEnumProblem(list, value); problem != "" {
				t.Errorf("%q: %s", value, problem)
			}
		}
	}
	if len(pveOSTypes) != 13 || len(pveBIOS) != 2 || len(pveSCSIHW) != 6 {
		t.Errorf("PVE's lists have 13 ostypes, 2 BIOS and 6 SCSI controllers, not %d, %d and %d", len(pveOSTypes), len(pveBIOS), len(pveSCSIHW))
	}
	if errs := Validate(validPlan()); len(errs) != 0 {
		t.Errorf("a plan that sets none of the four: %v", errs)
	}
}
