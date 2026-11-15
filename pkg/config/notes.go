// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"fmt"
	"net/netip"
	"regexp"
)

// documentationRanges are the three ranges RFC 5737 reserves for
// documentation. The examples and the plans init writes use the first; a node
// leaves them all unused.
var documentationRanges = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

// DocumentationRanges is the text of documentationRanges, for the notes and
// the error that suggest one.
const DocumentationRanges = "192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24"

// hostBridgeName is the name of a bridge a node usually has: PVE's own
// vmbr0, vmbr1, and the br0 of a hand-made setup. An SDN VNet of that name
// becomes a bridge of that name on the node.
var hostBridgeName = regexp.MustCompile(`(?i)^(vmbr|br)[0-9]+$`)

// maxSafeHostRAMPercent is the highest max_host_ram_percent that leaves the
// node some memory of its own.
const maxSafeHostRAMPercent = 95

// PlanNotes are what validate prints, beside a valid plan, as notes: things a
// plan may do on purpose, that validate cannot judge and a reader should
// check. None of them is an error, and none of them changes whether the plan
// is valid. They are in a fixed order, one sentence or two each.
func PlanNotes(p *Plan) []string {
	if p == nil {
		return nil
	}
	var notes []string
	if prefix, err := ParseSandboxRange(p.Network.IPRange); err == nil && !inDocumentationRange(prefix) {
		notes = append(notes, fmt.Sprintf("network.ip_range %s is not one of the documentation ranges (%s). validate cannot see the node's networks; plan checks the range against the node.", prefix, DocumentationRanges))
	}
	if hostBridgeName.MatchString(p.Network.ZoneID) {
		notes = append(notes, fmt.Sprintf("network.zone_id %s is a name a host bridge has. A zone ID names the zone, not a bridge, and a name like this invites mixing the two up. Use an ID such as csZone01.", p.Network.ZoneID))
	}
	if hostBridgeName.MatchString(p.Network.VNetID) {
		notes = append(notes, fmt.Sprintf("network.vnet_id %s is a name a host bridge has. A VNet becomes a bridge of its own name on the node, so an ID like this can clash with the node's own bridge. Use an ID such as csVnet01.", p.Network.VNetID))
	}
	switch p.Storage.OverlayStorage {
	case "local":
		notes = append(notes, "storage.overlay_storage local is Proxmox VE's default storage, on the node's system disk. Sandbox VMs write there; plan checks whether that disk also holds the cluster database, and a storage on a disk of its own is safer.")
	case "local-lvm":
		notes = append(notes, "storage.overlay_storage local-lvm is Proxmox VE's default LVM-thin storage, which is not file-based. Overlays need a file-based storage with images content; plan checks the storage on the node.")
	}
	if percent := p.AdmissionControl.MaxHostRAMPercent; percent > maxSafeHostRAMPercent {
		notes = append(notes, fmt.Sprintf("admission_control.max_host_ram_percent %g lets a run fill the node's memory to that point. Above %d the node's own services have little room, and when memory runs out the kernel ends a process, which can be a sandbox VM or a Proxmox VE service. init writes 85.0.", percent, maxSafeHostRAMPercent))
	}
	if note := SignKeyPathNote(p); note != "" {
		notes = append(notes, note)
	}
	return notes
}

// inDocumentationRange reports whether prefix is one of the documentation
// ranges or lies inside one.
func inDocumentationRange(prefix netip.Prefix) bool {
	for _, documentation := range documentationRanges {
		if documentation.Contains(prefix.Addr()) && prefix.Bits() >= documentation.Bits() {
			return true
		}
	}
	return false
}

// SuggestedDocumentationRange is a documentation range to name in a message,
// other than the plan's own: the first one that neither overlaps the plan's
// range nor holds one of the peers. It is "" when none is left.
func SuggestedDocumentationRange(planRange string, peers []string) string {
	own, _ := ParseSandboxRange(planRange)
candidates:
	for _, documentation := range documentationRanges {
		if own.IsValid() && documentation.Overlaps(own) {
			continue
		}
		for _, peer := range peers {
			if address, err := netip.ParseAddr(peer); err == nil && documentation.Contains(address) {
				continue candidates
			}
		}
		return documentation.String()
	}
	return ""
}
