// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cliftcloud/certistack/pkg/config"
)

// checkResolvedInputs holds the resolved plan to the rules that tie its VMs
// together, before the run creates anything. The loaders and the runner have
// checked them already (config.Validate, config.CheckNICIdentities); a plan
// reaches the orchestrator by other routes too, and these are what keep one
// VM's evidence from being another's, so the run does not take it on trust.
//
//   - No two NICs of the plan hold one MAC address. Every VM is on one isolated
//     VNet, and the earlier tiers stay up while the later ones start; two NICs
//     with one address make the bridge send frames for both guests to whichever
//     port spoke last, and a healthy guest becomes unreachable at random.
//   - No two VMs name one wire-probe address. A wire probe shows that its target
//     answered; the result is credited to the VM that names it, so an address
//     two VMs name could credit one guest's answer to both.
func (o *Orchestrator) checkResolvedInputs() error {
	if err := config.CheckNICIdentities(o.plan); err != nil {
		return err
	}
	if shared := config.SharedWireTargets(o.plan); len(shared) > 0 {
		return sharedWireTargetError(shared[0])
	}
	return nil
}

// checkWireTargetsOwned refuses to run a VM's probes while a wire target of
// theirs is one that another VM of the plan names too: the results would be
// credited to this VM on the strength of an answer that may be the other's.
// An Orchestrator without a plan (only unit tests build one) has no other VM
// to compare with.
func (o *Orchestrator) checkWireTargetsOwned(vm config.VM) error {
	if o.plan == nil {
		return nil
	}
	owners, _ := config.WireTargetOwners(o.plan)
	for _, probe := range vm.Probes {
		if !config.IsWireProbe(probe.Type) {
			continue
		}
		address := config.WireTargetAddress(probe.TargetIP)
		for _, id := range owners[address] {
			if id != vm.VMID {
				named := append(append([]int(nil), owners[address]...), vm.VMID)
				return sharedWireTargetError(config.SharedWireTarget{Address: address, VMIDs: uniqueSorted(named)})
			}
		}
	}
	return nil
}

func uniqueSorted(ids []int) []int {
	sort.Ints(ids)
	out := ids[:0]
	for i, id := range ids {
		if i == 0 || id != ids[i-1] {
			out = append(out, id)
		}
	}
	return out
}

func sharedWireTargetError(shared config.SharedWireTarget) error {
	ids := make([]string, len(shared.VMIDs))
	for i, id := range shared.VMIDs {
		ids[i] = fmt.Sprintf("%d", id)
	}
	return fmt.Errorf("wire probe target %s is named by VMs %s: a probe shows that its target answered, not which guest answered, so a pass would be credited to each of them on one answer; give every VM its own address (every wire-probe target must belong to exactly one VM)", shared.Address, strings.Join(ids, ", "))
}
