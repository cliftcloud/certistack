// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"strings"
	"testing"
)

// A container's backup group (ct/9912) in source_pbs.snapshot said only
// "must be latest, vm/<positive VMID>/latest, or vm/<positive VMID>/<RFC3339
// timestamp>" (lab chaos L8). It says containers are not supported, and what to
// give instead.
func TestValidation_ASnapshotOfAContainerSaysContainersAreNotSupported(t *testing.T) {
	for _, snapshot := range []string{"ct/9912/latest", "ct/9912/2026-09-27T03:00:09Z"} {
		p := validPlan()
		p.Tiers[0].VMs[0].SourcePBS.Snapshot = snapshot
		var message string
		for _, err := range Validate(p) {
			if err.Field == "tiers[0].vms[0].source_pbs.snapshot" {
				message = err.Message
			}
		}
		if !strings.Contains(message, "a container backup") || !strings.Contains(message, "containers are not supported") || !strings.Contains(message, "VMs only") {
			t.Errorf("%s: message = %q, want it to say containers are not supported", snapshot, message)
		}
	}
	// Any other malformed selector keeps the form it must have.
	p := validPlan()
	p.Tiers[0].VMs[0].SourcePBS.Snapshot = "host/pve1/latest"
	for _, err := range Validate(p) {
		if err.Field == "tiers[0].vms[0].source_pbs.snapshot" && !strings.Contains(err.Message, "must be latest, vm/<positive VMID>/latest") {
			t.Errorf("message = %q", err.Message)
		}
	}
}
