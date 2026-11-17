// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"net"
	"sort"
	"strings"
)

// WireTargetAddress is the address a wire probe's target_ip names, in one
// spelling, or "" when target_ip is not an IP literal.
func WireTargetAddress(targetIP string) string {
	key, _ := wireTargetKey(targetIP)
	return key
}

// wireTargetKey is the address a wire probe's target_ip names, in one spelling
// (an IPv4-mapped IPv6 address is its IPv4 address), or false when target_ip
// is not an IP literal (a malformed target is reported where it is checked).
func wireTargetKey(targetIP string) (string, bool) {
	target := net.ParseIP(strings.TrimSpace(targetIP))
	if target == nil {
		return "", false
	}
	if v4 := target.To4(); v4 != nil {
		target = v4
	}
	return target.String(), true
}

// SharedWireTarget is an address that the wire probes of several VMs name.
type SharedWireTarget struct {
	Address string
	// VMIDs are the VMs that name it, in ascending order, each once.
	VMIDs []int
}

// WireTargetOwners maps each address that a VM's wire probes name to the VMs
// that name it (ascending, each once), in the order the plan first names them.
// order lists the addresses in that order.
func WireTargetOwners(p *Plan) (owners map[string][]int, order []string) {
	if p == nil {
		return nil, nil
	}
	named := make(map[string]map[int]bool)
	for _, tier := range p.Tiers {
		for _, vm := range tier.VMs {
			for _, probe := range vm.Probes {
				if !isWireProbe(probe.Type) {
					continue
				}
				key, ok := wireTargetKey(probe.TargetIP)
				if !ok {
					continue
				}
				if named[key] == nil {
					named[key] = make(map[int]bool)
					order = append(order, key)
				}
				named[key][vm.VMID] = true
			}
		}
	}
	owners = make(map[string][]int, len(named))
	for key, set := range named {
		ids := make([]int, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		owners[key] = ids
	}
	return owners, order
}

// SharedWireTargets lists the addresses that wire probes of more than one VM
// name, in every network recovery mode. A wire probe shows that its target
// answered from the worker host; nothing in the answer says which guest sent
// it, so the result is credited to the VM that names the address. That is
// sound only while exactly one VM names it: with two, one guest or one shared
// listener can satisfy both records. Preserve mode, where a guest keeps its
// own addresses and no sandbox_ip declares them, is checked too: there a copied
// target is easiest to miss.
//
// The loaders refuse such a plan (Validate); the orchestrator asks again of the
// resolved plan before it creates anything, and again at the probes of each
// VM, and the verifier and the controller ask of a report's records
// (attest.SharedWireTargetProblems), so no layer relies on another having
// looked.
func SharedWireTargets(p *Plan) []SharedWireTarget {
	owners, order := WireTargetOwners(p)
	var shared []SharedWireTarget
	for _, key := range order {
		if len(owners[key]) >= 2 {
			shared = append(shared, SharedWireTarget{Address: key, VMIDs: owners[key]})
		}
	}
	return shared
}

// Names reports whether the VM with this ID is one of the VMs that name the
// address.
func (s SharedWireTarget) Names(vmid int) bool {
	for _, id := range s.VMIDs {
		if id == vmid {
			return true
		}
	}
	return false
}
