// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import "github.com/cliftcloud/certistack/pkg/config"

// findPlanVM is the planned VM with the given sandbox VMID, or nil. The
// acceptance rules (pkg/acceptance) look planned VMs up the same way; the
// fixtures of these tests build reports from the plan the same way.
func findPlanVM(plan *config.Plan, vmid int) *config.VM {
	for tierIndex := range plan.Tiers {
		for vmIndex := range plan.Tiers[tierIndex].VMs {
			if plan.Tiers[tierIndex].VMs[vmIndex].VMID == vmid {
				return &plan.Tiers[tierIndex].VMs[vmIndex]
			}
		}
	}
	return nil
}

// planSoakSec is the soak_time_sec of the tier that holds the VM, or zero.
func planSoakSec(plan *config.Plan, vmid int) int {
	if plan == nil {
		return 0
	}
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			if vm.VMID == vmid {
				return tier.SoakTimeSec
			}
		}
	}
	return 0
}
