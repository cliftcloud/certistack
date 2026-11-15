// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// The VNet a run creates carries the run's marker in its alias, which
// is the one free-text field PVE lets a VNet have, and the marker fits PVE's
// alias pattern.
func TestCreateVNetCarriesTheOwnerMarker(t *testing.T) {
	fake := sdntest.New()
	m := holding(NewManager(fake.Serve(t)), "tok")
	marker := OwnerMarker("run-20260930T120000Z-abc123")
	m.SetOwnerMarker(marker)
	netCfg := config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24"}
	if err := m.CreateVNet(context.Background(), netCfg); err != nil {
		t.Fatal(err)
	}
	var alias string
	fake.Do(func(p *sdntest.PVE) { alias = p.Aliases["csVn01"] })
	if alias != marker {
		t.Fatalf("alias %q, want the marker %q", alias, marker)
	}
	// PVE's pattern for a VNet's alias: [\(\)-_.\w\d\s]{0,256}
	if !regexp.MustCompile(`^[()\-_.\w\d\s]{0,256}$`).MatchString(marker) {
		t.Fatalf("marker %q does not fit PVE's alias pattern", marker)
	}
}

// A VNet is deleted only while it carries the run's marker.
func TestDestroyVNetDeletesOnlyTheRunsOwnVNet(t *testing.T) {
	const marker = "certistack run-a"
	for name, tc := range map[string]struct {
		alias, marker string
		refused       bool
	}{
		"its own marker":                   {alias: marker, marker: marker},
		"another run's marker":             {alias: "certistack run-b", marker: marker, refused: true},
		"no alias where a marker is named": {alias: "", marker: marker, refused: true},
		"an administrator's alias":         {alias: "payroll", marker: marker, refused: true},
		// A journal of an earlier version names no marker, and its VNet had no
		// alias: nothing separates it from a VNet made by hand since.
		"no marker named, no alias (legacy)": {alias: "", marker: "", refused: true},
		"no marker named, an alias":          {alias: "certistack run-b", marker: "", refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			fake := sdntest.New().Applied("csSb01", "csVn01", "csSb01-10.100.0.0-24")
			if tc.alias != "" {
				fake.Aliases["csVn01"] = tc.alias
			}
			m := holding(NewManager(fake.Serve(t)), "tok")
			m.SetOwnerMarker(tc.marker)
			err := m.DestroyVNet(context.Background(), "csVn01")
			var notOwned *NotOwnedError
			switch {
			case tc.refused && !errors.As(err, &notOwned):
				t.Fatalf("DestroyVNet = %v, want a NotOwnedError", err)
			case !tc.refused && err != nil:
				t.Fatalf("DestroyVNet = %v, want the VNet deleted", err)
			}
			var vnet string
			var subnets int
			fake.Do(func(p *sdntest.PVE) { vnet, subnets = p.VNets["csVn01"], len(p.Subnets["csVn01"]) })
			if tc.refused && (vnet == "" || subnets != 1 || m.Mutated() || len(fake.Writes()) != 0) {
				t.Fatalf("a refused VNet was changed: vnet %q, subnets %d, writes %v", vnet, subnets, fake.Writes())
			}
			if !tc.refused && vnet != "" {
				t.Fatalf("VNet %q left after its deletion", vnet)
			}
			if tc.refused && !strings.Contains(err.Error(), "cannot show that it is the interrupted run's") {
				t.Fatalf("error %q lacks its instruction", err)
			}
		})
	}
}

// An absent VNet has nothing to prove: its deletion is the idempotent no-op.
func TestDestroyVNetOfAnAbsentVNetNeedsNoMarker(t *testing.T) {
	m := holding(NewManager(sdntest.New().Serve(t)), "tok")
	m.SetOwnerMarker("certistack run-a")
	if err := m.DestroyVNet(context.Background(), "csVn01"); err != nil {
		t.Fatalf("DestroyVNet of an absent VNet = %v", err)
	}
}

// An answer to the ownership read that is not a list (null, an object)
// is not "the VNet is not listed": nothing is deleted on it.
func TestDestroyVNetRefusesANonListOwnershipRead(t *testing.T) {
	for _, answer := range []string{"null", `"OK"`, `{"vnet":"csVn01"}`} {
		fake := sdntest.New().Applied("csSb01", "csVn01", "csSb01-10.100.0.0-24")
		fake.Aliases["csVn01"] = "the payroll network"
		fake.Fault("GET cluster/sdn/vnets", sdntest.Fault{Answer: answer})
		m := holding(NewManager(fake.Serve(t)), "tok")
		m.SetOwnerMarker("certistack run-a")
		if err := m.DestroyVNet(context.Background(), "csVn01"); err == nil {
			t.Fatalf("answer %s: DestroyVNet succeeded on a read that was not a list", answer)
		}
		if writes := fake.Writes(); len(writes) != 0 {
			t.Fatalf("answer %s: wrote %v", answer, writes)
		}
	}
}

// The exception's check reads the pending changes as they are now.
func TestOwnUnappliedOnly(t *testing.T) {
	const marker = "certistack run-a"
	setup := func() (*sdntest.PVE, *Manager) {
		fake := sdntest.New()
		fake.Zones["csSb01"], fake.VNets["csVn01"] = true, "csSb01"
		fake.Aliases["csVn01"] = marker
		m := NewManager(fake.Serve(t))
		m.SetOwnObjects([]string{"csSb01"}, []string{"csVn01"})
		return fake, m
	}
	check := func(t *testing.T, m *Manager, want bool) {
		t.Helper()
		got, err := m.OwnUnappliedOnly(context.Background(), []string{"csSb01"}, []string{"csVn01"})
		if err != nil || got != want {
			t.Fatalf("OwnUnappliedOnly = %v, %v; want %v", got, err, want)
		}
	}
	t.Run("only the run's new objects", func(t *testing.T) {
		_, m := setup()
		check(t, m, true)
	})
	t.Run("an administrator's change beside them", func(t *testing.T) {
		fake, m := setup()
		fake.Zones["prodZ"] = true
		check(t, m, false)
	})
	t.Run("the objects were applied since", func(t *testing.T) {
		fake, m := setup()
		fake.Do(func(p *sdntest.PVE) {
			p.RunningZones, p.RunningVNets = map[string]bool{"csSb01": true}, map[string]string{"csVn01": "csSb01"}
		})
		check(t, m, false)
	})
	t.Run("the run's own deletion is pending", func(t *testing.T) {
		fake, m := setup()
		fake.Do(func(p *sdntest.PVE) {
			p.RunningZones, p.RunningVNets = map[string]bool{"csSb01": true, "csGone": true}, map[string]string{"csVn01": "csSb01"}
		})
		m.SetOwnObjects([]string{"csSb01", "csGone"}, []string{"csVn01"})
		check(t, m, false)
	})
}
