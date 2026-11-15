// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package vmlimits

import (
	"strings"
	"testing"
)

// Proxmox VE's own schema for the VM option cpuunits is "<integer> (1 -
// 262144)" (pvesh usage /nodes/<node>/qemu --command create --verbose, PVE
// 9.2.11; it notes the value is clamped to [1, 10000] in cgroup v2): the API
// refuses a larger value, so a larger weight must not be valid locally
// (audit F116).
func TestMaxCPUWeightIsTheProxmoxAPIMaximum(t *testing.T) {
	if MaxCPUWeight != 262144 {
		t.Errorf("MaxCPUWeight = %d, want 262144, the maximum of PVE's cpuunits schema", MaxCPUWeight)
	}
}

// 100 through 999999999 are Proxmox VE VM IDs.
func TestValidVMID(t *testing.T) {
	for id, want := range map[int]bool{-1: false, 0: false, 1: false, 99: false, 100: true, 9001: true, 999999999: true, 1000000000: false} {
		if got := ValidVMID(id); got != want {
			t.Errorf("ValidVMID(%d) = %v, want %v", id, got, want)
		}
		err := CheckVMID(id)
		if (err == nil) != want || (err != nil && !strings.Contains(err.Error(), "invalid VMID")) {
			t.Errorf("CheckVMID(%d) = %v", id, err)
		}
	}
}
