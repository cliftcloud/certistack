// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import "testing"

// HasWireProbes is IsWireProbe over every probe of every VM.
func TestPlanHasWireProbes(t *testing.T) {
	plan := func(types ...string) *Plan {
		var probes []Probe
		for _, probeType := range types {
			probes = append(probes, Probe{Type: probeType})
		}
		return &Plan{Tiers: []Tier{{VMs: []VM{{Probes: []Probe{{Type: "qga"}}}, {Probes: probes}}}}}
	}
	for name, tc := range map[string]struct {
		plan *Plan
		want bool
	}{
		"no plan":            {nil, false},
		"no tiers":           {&Plan{}, false},
		"agent probe only":   {plan(), false},
		"ssh and agent":      {plan("ssh", "qga"), false},
		"a tcp probe":        {plan("tcp"), true},
		"upper-case http":    {plan("HTTP"), true},
		"dns after an agent": {plan("qga", "dns"), true},
	} {
		if got := tc.plan.HasWireProbes(); got != tc.want {
			t.Errorf("%s: HasWireProbes = %v, want %v", name, got, tc.want)
		}
	}
}
