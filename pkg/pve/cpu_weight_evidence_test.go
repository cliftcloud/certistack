// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import "testing"

// The hardware CreateVM requests, which signed evidence records,
// carries the CPU weight it sends as cpuunits. Two configurations that differ
// only in weight sent different create requests but had equal effective
// hardware, so their evidence could not tell them apart.
func TestEffectiveHardwareCarriesTheCPUWeightCreateSends(t *testing.T) {
	base := VMConfig{VMID: 9900, Name: "restore", Bridge: "csVn01", Cores: 4, Sockets: 2, MemoryMB: 8192,
		DiskOverlays: []DiskOverlay{{Slot: "scsi0", Path: "/tmp/delta.qcow2"}}}
	for _, weight := range []int{1, 50, 500, 262144} {
		cfg := base
		cfg.CPUWeight = weight
		params, err := cfg.CreateParams()
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.EffectiveHardware().CPUWeight; got != weight || params["cpuunits"] != weight {
			t.Errorf("CPUWeight %d: effective hardware records %d, create request sends cpuunits %v", weight, got, params["cpuunits"])
		}
	}

	// A configuration that sends no weight leaves PVE its default, so there is
	// no weight to record: the field stays zero rather than name a guess.
	params, err := base.CreateParams()
	if err != nil {
		t.Fatal(err)
	}
	if _, sent := params["cpuunits"]; sent || base.EffectiveHardware().CPUWeight != 0 {
		t.Errorf("no weight requested: cpuunits sent=%v, recorded weight %d, want neither", sent, base.EffectiveHardware().CPUWeight)
	}
	// A weight outside PVE's range is refused before anything is sent, so no
	// invalid value can reach the evidence.
	negative := base
	negative.CPUWeight = -5
	if _, err := negative.CreateParams(); err == nil {
		t.Error("a negative CPU weight was accepted")
	}
}
