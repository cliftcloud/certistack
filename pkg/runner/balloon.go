// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"fmt"

	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/config"
)

// Where a sandbox VM's memory comes from, for the message of a balloon target
// that does not fit in it.
const (
	memoryFromPlan    = "the plan's memory_mb"
	memoryFromBackup  = "its backup's configuration, because the plan sets no memory_mb"
	memoryFromDefault = "the default for a VM whose memory is not set, because the plan sets no memory_mb and does not use the backup's configuration"
)

// checkBalloonWithinMemory refuses a balloon target above the VM's memory,
// before anything is created. The balloon target is part of the VM's memory, so
// PVE refuses it when the VM is created. validate compares the two only when
// the plan sets both; the memory a plan takes from its backup (or leaves to the
// default) is known only here, once the backup has been read. memoryFrom says
// where the memory came from.
func checkBalloonWithinMemory(vm *config.VM, memoryFrom string) error {
	balloon, memory := vm.HardwareOverrides.BalloonMB, vm.HardwareOverrides.MemoryMB
	if memory <= 0 {
		memory = admission.DefaultSandboxMemoryMB
	}
	if balloon <= memory {
		return nil
	}
	return fmt.Errorf("target VM %d (%s): hardware_overrides.balloon_mb is %d MiB, above the VM's memory of %d MiB, which comes from %s. The balloon target is part of the VM's memory. Set balloon_mb to at most %d, or memory_mb to at least %d", vm.VMID, vm.Name, balloon, memory, memoryFrom, memory, balloon)
}
