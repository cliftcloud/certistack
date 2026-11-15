// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// machineVersionID is a versioned machine type, such as pc-q35-9.2 or
// pc-i440fx-9.2+pve1 (family, major.minor, and PVE's optional revision of
// QEMU's machine).
var machineVersionID = regexp.MustCompile(`^pc-(q35|i440fx)-([0-9]+\.[0-9]+)(?:\+pve[0-9]+)?$`)

// nodeMachineOffers is how many of a node's newest machine versions a refusal
// names.
const nodeMachineOffers = 3

// pinnedMachine is a plan VM whose machine is a versioned type, which only a
// QEMU at least that new can run. q35, pc, i440fx and no setting are
// unversioned: PVE resolves them to a version the node can run at every
// start, so they are never refused here.
type pinnedMachine struct {
	vmid    int
	name    string
	machine string // the type, without its options
	family  string // q35 or i440fx
	base    string // major.minor
}

// versionedMachine reads a machine setting ("[type=]<type>[,option=value]...")
// and reports its family and base version when its type is a versioned one.
func versionedMachine(setting string) (machine, family, base string, ok bool) {
	machine, _, _ = strings.Cut(setting, ",")
	machine = strings.TrimPrefix(strings.TrimSpace(machine), "type=")
	m := machineVersionID.FindStringSubmatch(machine)
	if m == nil {
		return "", "", "", false
	}
	return machine, m[1], m[2], true
}

// pinnedMachines are the plan's VMs whose effective machine is a versioned
// type: the plan's own setting, else the backup's (the runner resolves it into
// the VM before the orchestrator sees it).
func (o *Orchestrator) pinnedMachines() []pinnedMachine {
	var pinned []pinnedMachine
	for _, tier := range o.plan.Tiers {
		for _, vm := range tier.VMs {
			if machine, family, base, ok := versionedMachine(vm.Machine); ok {
				pinned = append(pinned, pinnedMachine{vmid: vm.VMID, name: vm.Name, machine: machine, family: family, base: base})
			}
		}
	}
	return pinned
}

// machineOffers are the base versions (major.minor) a node's QEMU offers, per
// machine family, read from the machine IDs PVE lists.
//
// A pinned machine is compared on its base version only. PVE lists a base
// version with and without its +pveK revisions, and which revisions exist is
// qemu-server's business; a node that lists pc-q35-9.2+pve1 and a backup that
// asks for pc-q35-9.2+pve2 is not refused, because this check is meant to
// catch a machine the node's QEMU cannot run at all and must never refuse a
// restore that would have started. So a VM is refused only when its base
// version N.M is not offered by the node at all; an exact +pveK that is not
// offered while the base is, is let through.
func machineOffers(ids []string) map[string][]string {
	seen := map[string]map[string]bool{}
	for _, id := range ids {
		if m := machineVersionID.FindStringSubmatch(id); m != nil {
			if seen[m[1]] == nil {
				seen[m[1]] = map[string]bool{}
			}
			seen[m[1]][m[2]] = true
		}
	}
	offers := map[string][]string{}
	for family, bases := range seen {
		list := make([]string, 0, len(bases))
		for base := range bases {
			list = append(list, base)
		}
		sort.Slice(list, func(i, j int) bool { return versionLess(list[j], list[i]) }) // newest first
		offers[family] = list
	}
	return offers
}

// checkNodeMachines refuses a plan whose backups pin a QEMU machine version
// the node cannot run. PVE accepts such a machine on create (live on PVE 8.4
// with QEMU 9.2, `qm create --machine pc-q35-11.0+pve2` succeeds) and fails the
// start, after the guest has been prepared ("Installed QEMU version '9.2.0' is
// too old to run machine type 'pc-q35-11.0+pve2'"). The node's machine list is
// read once, and only when a VM pins a versioned machine. A list that cannot be
// read, or that offers nothing of a VM's family to compare with, is a warning
// and the run goes on: the check never refuses on what it could not see.
func (o *Orchestrator) checkNodeMachines(ctx context.Context) (warning string, err error) {
	pinned := o.pinnedMachines()
	if len(pinned) == 0 || o.pveClient == nil {
		return "", nil
	}
	node := o.opts.NodeName
	ids, readErr := o.pveClient.QEMUMachines(ctx, node)
	if readErr != nil {
		return fmt.Sprintf("Could not read node %s's QEMU machine versions, so %s was not checked against them; a machine newer than the node's QEMU fails when the VM starts, after its guest is prepared: %v", node, describePinned(pinned), readErr), nil
	}
	offers := machineOffers(ids)

	var problems []string
	var unchecked []pinnedMachine
	for _, vm := range pinned {
		offered := offers[vm.family]
		if len(offered) == 0 {
			unchecked = append(unchecked, vm)
			continue
		}
		have := false
		for _, base := range offered {
			have = have || base == vm.base
		}
		if have {
			continue
		}
		newest := make([]string, 0, nodeMachineOffers)
		for _, base := range offered {
			if len(newest) < nodeMachineOffers {
				newest = append(newest, "pc-"+vm.family+"-"+base)
			}
		}
		reason := "which node " + node + "'s QEMU does not offer"
		if versionLess(offered[0], vm.base) {
			reason = "which is newer than node " + node + "'s QEMU can run"
		}
		problems = append(problems, fmt.Sprintf("VM %d (%s) is pinned to machine %s, %s (the newest it offers: %s)", vm.vmid, vm.name, vm.machine, reason, strings.Join(newest, ", ")))
	}
	if len(unchecked) > 0 {
		warning = fmt.Sprintf("Node %s lists no QEMU machine versions to check %s against; a machine newer than the node's QEMU fails when the VM starts, after its guest is prepared.", node, describePinned(unchecked))
	}
	if len(problems) == 0 {
		return warning, nil
	}
	return warning, fmt.Errorf("machine versions: %s. PVE would create the VM and fail its start, after its guest is prepared. Restore on a node whose QEMU is as new as the one that made the backup, or set machine for that VM in the plan to an unversioned type (q35, or pc for i440fx), which replaces the backup's setting and starts the VM on the node's own machine version", strings.Join(problems, "; "))
}

// describePinned names VMs and the machines they pin.
func describePinned(pinned []pinnedMachine) string {
	parts := make([]string, 0, len(pinned))
	for _, vm := range pinned {
		parts = append(parts, fmt.Sprintf("VM %d (%s)", vm.vmid, vm.machine))
	}
	return strings.Join(parts, ", ")
}
