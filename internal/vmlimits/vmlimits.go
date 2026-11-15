// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package vmlimits holds the ranges a sandbox VM's ID and virtual hardware
// may take, in one place, so that plan validation, backup-profile parsing,
// init and the PVE client agree on them: a value the product refuses from a
// backup or from init is refused from a handwritten plan too.
package vmlimits

import "fmt"

// Proxmox VE's VM ID range.
const (
	MinVMID = 100
	MaxVMID = 999999999
)

// The virtual hardware a backup's configuration may inherit and a plan's
// hardware_overrides may set. Memory and balloon are MiB; the CPU weight is
// the PVE cpuunits value.
const (
	MaxCores     = 256
	MaxSockets   = 16
	MinMemoryMB  = 16 // Proxmox VE's own minimum
	MaxMemoryMB  = 4 << 20
	MaxBalloonMB = 4 << 20
	MaxCPUWeight = 262144 // the maximum of PVE's cpuunits schema (1 - 262144)
)

// ValidVMID reports whether id is a Proxmox VE VM ID.
func ValidVMID(id int) bool {
	return id >= MinVMID && id <= MaxVMID
}

// CheckVMID returns nil for a Proxmox VE VM ID, else an error in the
// product's words.
func CheckVMID(id int) error {
	if !ValidVMID(id) {
		return fmt.Errorf("invalid VMID: %d is not a Proxmox VE VM ID, which is between %d and %d", id, MinVMID, MaxVMID)
	}
	return nil
}
