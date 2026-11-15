// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"fmt"

	"github.com/cliftcloud/certistack/internal/vmlimits"
)

// vmNumberErrors checks a VM's IDs and hardware overrides. The sandbox VM's
// ID must be a Proxmox VM ID, the range init allocates from: the plan used to
// require only a positive number, then PVE refused the rest late.
func vmNumberErrors(prefix string, vm VM) []ValidationError {
	var errors []ValidationError
	idRange := fmt.Sprintf("between %d and %d", vmlimits.MinVMID, vmlimits.MaxVMID)
	if vm.VMID == 0 {
		errors = append(errors, ValidationError{Field: prefix + ".vmid", Message: "must be set to the sandbox VM's ID, " + idRange})
	} else if !vmlimits.ValidVMID(vm.VMID) {
		errors = append(errors, ValidationError{Field: prefix + ".vmid", Message: "must be a Proxmox VM ID " + idRange})
	}
	if vm.TargetVMID != 0 && !vmlimits.ValidVMID(vm.TargetVMID) {
		errors = append(errors, ValidationError{Field: prefix + ".target_vmid", Message: "must be a Proxmox VM ID " + idRange})
	}
	if vm.SourceVMID < 0 || vm.SourceVMID > vmlimits.MaxVMID {
		errors = append(errors, ValidationError{Field: prefix + ".source_vmid", Message: fmt.Sprintf("must be the protected VM's ID, at most %d", vmlimits.MaxVMID)})
	}
	return append(errors, hardwareOverrideErrors(prefix+".hardware_overrides", vm.HardwareOverrides)...)
}

// hardwareOverrideErrors checks a VM's hardware_overrides against the ranges
// the same hardware is held to when it is inherited from a backup's
// configuration (internal/vmlimits). Zero means the plan sets nothing and the
// backup's value, or the sandbox default, applies. A negative value used to
// count as "set", suppress the backup's value and then fall to a default, and
// a value above the maximum went to PVE unchecked.
func hardwareOverrideErrors(prefix string, h HardwareOverrides) []ValidationError {
	var errors []ValidationError
	check := func(key string, value, minimum, maximum int) {
		if value == 0 {
			return
		}
		if value < minimum || value > maximum {
			errors = append(errors, ValidationError{Field: prefix + "." + key, Message: fmt.Sprintf("must be between %d and %d, or 0 for the backup's value or the default", minimum, maximum)})
		}
	}
	check("cores", h.Cores, 1, vmlimits.MaxCores)
	check("sockets", h.Sockets, 1, vmlimits.MaxSockets)
	check("memory_mb", h.MemoryMB, vmlimits.MinMemoryMB, vmlimits.MaxMemoryMB)
	check("balloon_mb", h.BalloonMB, 1, vmlimits.MaxBalloonMB)
	check("cpu_weight", h.CPUWeight, 1, vmlimits.MaxCPUWeight)
	if h.MemoryMB > 0 && h.BalloonMB > h.MemoryMB {
		errors = append(errors, ValidationError{Field: prefix + ".balloon_mb", Message: fmt.Sprintf("must not exceed memory_mb (%d): the balloon target is part of the VM's memory", h.MemoryMB)})
	}
	return errors
}
