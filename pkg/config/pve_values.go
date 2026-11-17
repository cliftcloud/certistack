// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The values a plan may give the sandbox VM's machine, ostype, bios and scsihw
// are Proxmox VE's own, so that a mistake is refused by validate and not when
// the run creates the VM. They are read from qemu-server's schema (the VM
// configuration's ostype, bios and scsihw enumerations, and the
// pve-qemu-machine format in PVE::QemuServer::Machine); PVE 8 and 9 take these
// values. Where PVE may take more than is listed here (an option a later
// release adds to machine), validate does not judge it: a value PVE accepts is
// never refused here.
var (
	pveOSTypes = []string{"other", "wxp", "w2k", "w2k3", "w2k8", "wvista", "win7", "win8", "win10", "win11", "l24", "l26", "solaris"}
	pveBIOS    = []string{"seabios", "ovmf"}
	pveSCSIHW  = []string{"lsi", "lsi53c810", "virtio-scsi-pci", "virtio-scsi-single", "megasas", "pvscsi"}
)

// pveMachineType is the machine type of PVE's machine property: the
// unversioned pc and q35, the versioned pc-i440fx-* and pc-q35-* (with an
// optional +pveN revision and a .pxe suffix), and the arm64 virt. PVE matches it
// against the whole value, and allows 40 characters.
var pveMachineType = regexp.MustCompile(`^(?:pc|pc(?:-i440fx)?-[0-9]+(?:\.[0-9]+)+(?:\+pve[0-9]+)?(?:\.pxe)?|q35|pc-q35-[0-9]+(?:\.[0-9]+)+(?:\+pve[0-9]+)?(?:\.pxe)?|virt(?:-[0-9]+(?:\.[0-9]+)+)?(?:\+pve[0-9]+)?)$`)

const pveMachineTypeMaxLength = 40

// machineOptionName is what the name of a machine option looks like: PVE's
// own (viommu, aw-bits, enable-s3) and any it may add.
var machineOptionName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

// pveMachineExample is how the messages show a machine setting.
const pveMachineExample = "q35, pc, pc-i440fx-9.2, pc-q35-9.2+pve1 or q35,viommu=virtio"

// pveEnumProblem is why value is not one of values, or "" when it is. Proxmox VE
// reads these values in lower case only.
func pveEnumProblem(values []string, value string) string {
	for _, accepted := range values {
		if value == accepted {
			return ""
		}
	}
	return "must be one of Proxmox VE's values: " + strings.Join(values, ", ")
}

// pveBoolean reads Proxmox VE's boolean spellings.
func pveBoolean(text string) (value, ok bool) {
	switch strings.ToLower(text) {
	case "1", "on", "yes", "true":
		return true, true
	case "0", "off", "no", "false":
		return false, true
	}
	return false, false
}

// machineProblem is why value is not a machine setting Proxmox VE takes, or ""
// when it may be one. A setting is "[type=]<type>[,option=value]...". The type
// and the options checked here (viommu, aw-bits, enable-s3, enable-s4) are
// held to PVE's rules; any other option is left to PVE.
func machineProblem(value string) string {
	var (
		machineType string
		seen        = map[string]bool{}
		viommu      string
		awBits      float64
		hasAWBits   bool
	)
	example := " (" + pveMachineExample + ")"
	for i, part := range strings.Split(value, ",") {
		if part == "" {
			continue
		}
		name, option, hasValue := strings.Cut(part, "=")
		if !hasValue {
			if i != 0 {
				return fmt.Sprintf("has %q after the machine type, which is not an option=value pair%s", part, example)
			}
			name, option = "type", part
		}
		if strings.ContainsAny(name, " \t") {
			return fmt.Sprintf("has the option name %q, which holds a space: write the options with no spaces around the comma or the equals sign%s", name, example)
		}
		if !machineOptionName.MatchString(name) {
			return fmt.Sprintf("has %q, whose option name is not one Proxmox VE could take: an option is name=value, the name a letter followed by letters, digits and -%s", part, example)
		}
		if option == "" {
			return fmt.Sprintf("gives the option %q no value", name)
		}
		if seen[name] {
			return fmt.Sprintf("gives %q twice", name)
		}
		seen[name] = true
		switch name {
		case "type":
			machineType = option
		case "viommu":
			if option != "intel" && option != "virtio" {
				return fmt.Sprintf("has viommu=%s; Proxmox VE takes viommu=intel or viommu=virtio", option)
			}
			viommu = option
		case "aw-bits":
			bits, err := strconv.ParseFloat(option, 64)
			if err != nil || bits < 32 || bits > 64 {
				return fmt.Sprintf("has aw-bits=%s; Proxmox VE takes a number from 32 to 64", option)
			}
			awBits, hasAWBits = bits, true
		case "enable-s3", "enable-s4":
			if _, ok := pveBoolean(option); !ok {
				return fmt.Sprintf("has %s=%s; Proxmox VE takes 1 or 0", name, option)
			}
		}
	}
	if seen["type"] {
		if len(machineType) > pveMachineTypeMaxLength || !pveMachineType.MatchString(machineType) {
			return fmt.Sprintf("has the machine type %q, which is not one Proxmox VE has; it takes %s", machineType, pveMachineExample)
		}
	}
	// PVE::QemuServer::Machine::assert_valid_machine_property.
	if viommu == "intel" && !strings.Contains(machineType, "q35") {
		return "has viommu=intel, which needs a q35 machine type; add q35 as the type, for example q35,viommu=intel"
	}
	if hasAWBits && viommu == "" {
		return "has aw-bits without viommu: the address width belongs to a vIOMMU, so add viommu=intel or viommu=virtio"
	}
	if hasAWBits && viommu == "intel" && awBits != 39 && awBits != 48 {
		return "has aw-bits that Intel vIOMMU does not take; it takes 39 or 48"
	}
	return ""
}

// vmHardwareValueErrors holds a VM's machine, ostype, bios and scsihw to
// Proxmox VE's values. A value left out takes the backup's, and is not judged.
func vmHardwareValueErrors(prefix string, vm VM) []ValidationError {
	var errors []ValidationError
	if vm.Machine != "" {
		if problem := machineProblem(vm.Machine); problem != "" {
			errors = append(errors, ValidationError{Field: prefix + ".machine", Message: problem})
		}
	}
	for _, value := range []struct {
		field, text string
		accepted    []string
	}{
		{"ostype", vm.OSType, pveOSTypes},
		{"bios", vm.BIOS, pveBIOS},
		{"scsihw", vm.SCSIHW, pveSCSIHW},
	} {
		if value.text == "" {
			continue
		}
		if problem := pveEnumProblem(value.accepted, value.text); problem != "" {
			errors = append(errors, ValidationError{Field: prefix + "." + value.field, Message: problem})
		}
	}
	return errors
}
