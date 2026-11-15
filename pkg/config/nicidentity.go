// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cliftcloud/certistack/internal/macaddr"
)

// nicIdentityErrors checks every MAC address the plan gives a sandbox NIC,
// by the one rule (internal/macaddr): each is six octets that can name one
// interface, and no two NICs of the plan hold the same address, whatever its
// spelling.
//
// The NICs are the plan's: net0 of each VM, from its mac field or, once the
// runner has resolved the plan's backups, from the backup; and the source's
// other NICs a VM attaches (network_recovery.attach_all_nics), which only the
// resolved plan has. Every VM is on one isolated VNet and the earlier tiers
// stay up while the later ones start, so the registry is the whole plan's, not
// a tier's. Two NICs with one address make the VNet's bridge send frames for
// both guests to whichever port spoke last, and the first guest becomes
// unreachable at random; the check is made before anything exists to be
// cleaned up.
//
// The loaders call it with the plan as written, where only the mac fields
// are set; the runner calls it again (CheckNICIdentities) with the backups
// resolved, when a MAC may have come from a source profile and a second one
// from a source's net1.
func nicIdentityErrors(p *Plan) []ValidationError {
	var errs []ValidationError
	var registry macaddr.Registry
	for i, tier := range p.Tiers {
		for j, vm := range tier.VMs {
			vmPrefix := fmt.Sprintf("tiers[%d].vms[%d]", i, j)
			claim := func(field, slot, mac string) {
				if mac == "" {
					return
				}
				if _, err := macaddr.Parse(mac); err != nil {
					errs = append(errs, ValidationError{Field: field, Message: fmt.Sprintf("%q (VM %d %s) is not a usable MAC address (%s): %v", mac, vm.VMID, slot, macaddr.Describe, err)})
					return
				}
				canonical, _ := macaddr.Canonical(mac)
				if prior, ok := registry.Claim(mac, fmt.Sprintf("VM %d %s", vm.VMID, slot)); !ok {
					errs = append(errs, ValidationError{Field: field, Message: fmt.Sprintf("must be unique across the plan's NICs; VM %d %s and %s both use %s, and two NICs of one sandbox network with one address make the bridge send frames for both guests to whichever spoke last (a VM's net0 address is the plan's mac or, if it sets none, its backup's; give one of them a distinct mac, or restore them in separate runs)", vm.VMID, slot, prior, canonical)})
				}
			}
			claim(vmPrefix+".mac", "net0", vm.MAC)
			for _, nic := range vm.AdditionalNICs {
				claim(vmPrefix+".network_recovery.attach_all_nics", nic.Slot, nic.MAC)
			}
		}
	}
	return errs
}

// CheckNICIdentities holds the plan's NIC MAC addresses to the one rule (see
// nicIdentityErrors) after its backups are resolved, and reports every
// problem at once. The runner calls it as soon as the last backup is read, and
// the orchestrator again before it creates anything.
func CheckNICIdentities(p *Plan) error {
	errs := nicIdentityErrors(p)
	if len(errs) == 0 {
		return nil
	}
	messages := make([]string, 0, len(errs))
	for _, err := range errs {
		messages = append(messages, err.Error())
	}
	return errors.New("sandbox NIC MAC addresses: " + strings.Join(messages, "; "))
}
