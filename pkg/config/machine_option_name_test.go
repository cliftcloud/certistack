// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"strings"
	"testing"
)

// An option of machine whose name is no option name at all ("=0", "q35,=1",
// "q35,-x=1") was accepted, though no Proxmox VE takes it and the schema
// refuses it: the VM would be refused when the run created it. An option PVE
// may add later (a name of letters, digits and "-") is still left to PVE.
func TestAMachineOptionWithoutAnOptionNameIsRefused(t *testing.T) {
	for value, refused := range map[string]bool{
		"=0":                    true,
		"q35,=1":                true,
		"q35,-x=1":              true,
		"q35,x.y=1":             true,
		"q35,x_y=1":             true,
		"q35,9x=1":              true,
		"q35":                   false,
		"type=q35,viommu=intel": false,
		"q35,new-option=1":      false,
		"viommu=virtio":         false,
	} {
		plan := validPlan()
		plan.Tiers[0].VMs[0].Machine = value
		var problems []string
		for _, problem := range Validate(plan) {
			if problem.Field == "tiers[0].vms[0].machine" {
				problems = append(problems, problem.Message)
			}
		}
		if (len(problems) > 0) != refused {
			t.Errorf("machine %q: refused = %v (%s), want %v", value, len(problems) > 0, strings.Join(problems, "; "), refused)
		}
	}
}
