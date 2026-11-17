// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"strings"
	"testing"
)

// A value outside PVE's range in a backup's configuration is refused with the
// value, the range PVE allows, and the way out, not only "invalid source cores
// value "512"": the layout read ignores the hardware, so a plan that does not
// take it from the backup (use_backup_config: false) gives its own in
// hardware_overrides.
func TestAHardwareValueOutsidePVEsRangeNamesTheRangeAndTheWayOut(t *testing.T) {
	for _, tc := range []struct {
		line string
		want []string
	}{
		{"cores: 512", []string{"the backup's configuration has cores 512, more than PVE allows (1 to 256)", "hardware_overrides.cores"}},
		{"cores: 0", []string{"has cores 0, less than PVE allows (1 to 256)", "hardware_overrides.cores"}},
		{"cores: many", []string{`has cores "many", which is not a whole number (PVE allows 1 to 256)`, "hardware_overrides.cores"}},
		{"sockets: 17", []string{"has sockets 17, more than PVE allows (1 to 16)", "hardware_overrides.sockets"}},
		{"memory: 8388608", []string{"has memory 8388608 MiB, more than PVE allows (16 to 4194304 MiB)", "hardware_overrides.memory_mb"}},
		{"memory: 8", []string{"has memory 8 MiB, less than PVE allows (16 to 4194304 MiB)", "hardware_overrides.memory_mb"}},
		{"balloon: -1", []string{"has balloon -1 MiB, less than PVE allows (0 to 4194304 MiB)", "hardware_overrides.balloon_mb"}},
		{"cpuunits: 262145", []string{"has cpuunits 262145, more than PVE allows (1 to 262144)", "hardware_overrides.cpu_weight"}},
	} {
		_, err := ParseVMProfile([]byte(tc.line + "\n"))
		if err == nil {
			t.Errorf("%q: accepted", tc.line)
			continue
		}
		for _, want := range append(tc.want, "use_backup_config: false") {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q: err = %q, want it to contain %q", tc.line, err, want)
			}
		}
		// The layout read, which a plan without use_backup_config makes, does
		// not read the hardware: the way out the message names is open.
		if _, err := ParseVMLayout([]byte(tc.line + "\n")); err != nil {
			t.Errorf("%q: ParseVMLayout refuses what the message says use_backup_config: false avoids: %v", tc.line, err)
		}
	}
}
