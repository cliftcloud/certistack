// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import (
	"errors"
	"fmt"

	"github.com/cliftcloud/certistack/pkg/config"
)

const (
	// DefaultSandboxMemoryMB is the explicit safe estimate used until backup
	// metadata supplies a VM's source memory setting. It matches the PVE
	// sandbox default, so early preflight and runtime admission use the same
	// accounting model.
	DefaultSandboxMemoryMB = 2048

	// SandboxVMHostOverheadMB reserves host-side QEMU, networking, and COW
	// bookkeeping in addition to the guest's configured memory.
	SandboxVMHostOverheadMB = 256
)

// RecoveryMemoryReservation returns the memory needed at the plan's peak:
// the sum of every tier's VMs. Tiers start in order, but the orchestrator
// keeps each verified tier running until the final teardown so dependent
// tiers can reach it, so the last tier boots while all earlier tiers are
// still resident. tierLevel is the highest tier level included. A VM without
// an explicit or backup-derived memory setting receives the same safe default
// that PVE will use when it is registered.
func RecoveryMemoryReservation(plan *config.Plan) (memoryMB, vmCount, tierLevel int, err error) {
	if plan == nil {
		return 0, 0, 0, errors.New("plan is required")
	}

	maxInt := int64(^uint(0) >> 1)
	var total int64
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			memory := vm.HardwareOverrides.MemoryMB
			if memory <= 0 {
				memory = DefaultSandboxMemoryMB
			}
			reservation := int64(memory) + SandboxVMHostOverheadMB
			if reservation <= 0 || total > maxInt-reservation {
				return 0, 0, 0, fmt.Errorf("tier %d recovery memory reservation overflows", tier.Level)
			}
			total += reservation
			vmCount++
		}
		if tier.Level > tierLevel {
			tierLevel = tier.Level
		}
	}
	return int(total), vmCount, tierLevel, nil
}
