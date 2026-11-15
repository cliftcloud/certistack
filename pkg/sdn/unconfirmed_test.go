// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

const runMarker = "certistack run-a"

func marked(m *Manager) *Manager {
	m.SetOwnerMarker(runMarker)
	return m
}

// A zone whose creation was never confirmed is the run's only while PVE
// shows it as a creation that was never applied. Absent, there is nothing to
// delete and no request is made; one PVE runs is someone else's, and is left.
func TestDestroyUnconfirmedZone(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		fake := sdntest.New()
		created, err := holding(marked(NewManager(fake.Serve(t))), "tok").DestroyUnconfirmedZone(context.Background(), "csSb01")
		if err != nil || created || len(fake.Writes()) != 0 {
			t.Fatalf("created %v, err %v, writes %v; want a creation that made nothing, and no write", created, err, fake.Writes())
		}
	})
	t.Run("configured and never applied", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csSb01"] = true
		m := holding(marked(NewManager(fake.Serve(t))), "tok")
		created, err := m.DestroyUnconfirmedZone(context.Background(), "csSb01")
		if err != nil || !created || fake.Zones["csSb01"] || !m.Mutated() {
			t.Fatalf("created %v, err %v, zone left %v; want the run's never-applied zone deleted", created, err, fake.Zones["csSb01"])
		}
	})
	t.Run("running, which the run never applied", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csSb01"], fake.RunningZones["csSb01"] = true, true
		m := holding(marked(NewManager(fake.Serve(t))), "tok")
		created, err := m.DestroyUnconfirmedZone(context.Background(), "csSb01")
		var notOwned *NotOwnedError
		if !errors.As(err, &notOwned) || !created || m.Mutated() || len(fake.Writes()) != 0 || !fake.Zones["csSb01"] {
			t.Fatalf("created %v, err %v, writes %v; want a zone someone else applied left alone", created, err, fake.Writes())
		}
	})
	t.Run("a read that fails is not absence", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csSb01"] = true
		fake.Fault("GET cluster/sdn/zones", sdntest.Fault{Refuse: "Permission check failed (/sdn/zones, SDN.Audit)", Status: 403})
		m := holding(marked(NewManager(fake.Serve(t))), "tok")
		if created, err := m.DestroyUnconfirmedZone(context.Background(), "csSb01"); err == nil || created || len(fake.Writes()) != 0 {
			t.Fatalf("created %v, err %v, writes %v; want an error and no write", created, err, fake.Writes())
		}
	})
	t.Run("a journal that names no marker", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csSb01"] = true
		m := holding(NewManager(fake.Serve(t)), "tok")
		_, err := m.DestroyUnconfirmedZone(context.Background(), "csSb01")
		var notOwned *NotOwnedError
		if !errors.As(err, &notOwned) || len(fake.Writes()) != 0 || !fake.Zones["csSb01"] {
			t.Fatalf("err %v, writes %v; want the zone refused", err, fake.Writes())
		}
	})
}

// A VNet whose creation was never confirmed carries the run's marker if
// PVE made it, which DestroyVNet demands; absent, nothing is requested.
func TestDestroyUnconfirmedVNet(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		fake := sdntest.New()
		created, err := holding(marked(NewManager(fake.Serve(t))), "tok").DestroyUnconfirmedVNet(context.Background(), "csVn01")
		if err != nil || created || len(fake.Writes()) != 0 {
			t.Fatalf("created %v, err %v, writes %v; want a creation that made nothing, and no write", created, err, fake.Writes())
		}
	})
	t.Run("the run's own", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csSb01"], fake.VNets["csVn01"], fake.Aliases["csVn01"] = true, "csSb01", runMarker
		created, err := holding(marked(NewManager(fake.Serve(t))), "tok").DestroyUnconfirmedVNet(context.Background(), "csVn01")
		if err != nil || !created || fake.VNets["csVn01"] != "" {
			t.Fatalf("created %v, err %v; want the run's VNet deleted", created, err)
		}
	})
	t.Run("another's", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csSb01"], fake.VNets["csVn01"], fake.Aliases["csVn01"] = true, "csSb01", "the payroll network"
		created, err := holding(marked(NewManager(fake.Serve(t))), "tok").DestroyUnconfirmedVNet(context.Background(), "csVn01")
		var notOwned *NotOwnedError
		if !errors.As(err, &notOwned) || !created || len(fake.Writes()) != 0 {
			t.Fatalf("created %v, err %v, writes %v; want another's VNet left alone", created, err, fake.Writes())
		}
	})
}

// A zone has no marker of its own. A manager with no marker (a journal of an
// earlier version) deletes no zone PVE lists. With a marker it deletes a listed
// zone only when the zone is shown to be the run's: a VNet in it carries the
// marker (here one whose deletion is pending, as at teardown), or it was never
// applied and the run's lock stands. An applied zone that nothing shows to be
// the run's (an empty zone made later under the same name) is left (RO-133).
// An absent zone is the idempotent no-op.
func TestDestroyZoneNeedsProofThatTheZoneIsTheRuns(t *testing.T) {
	for name, tc := range map[string]struct {
		marker          string
		listed, applied bool
		markedVNet      bool // a VNet of the zone, its deletion pending, carries the run's marker
		otherVNet       bool // ... carries another alias
		refused         bool
	}{
		"a marker, the zone absent":                           {marker: runMarker},
		"a marker, a marked VNet's deletion pending in it":    {marker: runMarker, listed: true, applied: true, markedVNet: true},
		"a marker, never applied, under the run's lock":       {marker: runMarker, listed: true},
		"a marker, applied, no VNet shows it (a replacement)": {marker: runMarker, listed: true, applied: true, refused: true},
		"a marker, applied, only another's VNet was in it":    {marker: runMarker, listed: true, applied: true, otherVNet: true, refused: true},
		"no marker, the zone absent":                          {},
		"no marker, the zone listed":                          {listed: true, applied: true, refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			fake := sdntest.New()
			fake.Lock = "tok"
			if tc.listed {
				fake.Zones["csSb01"] = true
				fake.RunningZones["csSb01"] = tc.applied
				if !tc.applied {
					delete(fake.RunningZones, "csSb01")
				}
			}
			if tc.markedVNet || tc.otherVNet {
				fake.RunningVNets["csVn01"] = "csSb01"
				fake.RunningAliases["csVn01"] = runMarker
				if tc.otherVNet {
					fake.RunningAliases["csVn01"] = "lab bridge"
				}
			}
			m := holding(NewManager(fake.Serve(t)), "tok")
			m.SetOwnerMarker(tc.marker)
			err := m.DestroyZone(context.Background(), "csSb01")
			var notOwned *NotOwnedError
			switch {
			case tc.refused && !errors.As(err, &notOwned):
				t.Fatalf("DestroyZone = %v, want a NotOwnedError", err)
			case !tc.refused && err != nil:
				t.Fatalf("DestroyZone = %v", err)
			}
			if tc.refused && (len(fake.Writes()) != 0 || !fake.Zones["csSb01"]) {
				t.Fatalf("a refused zone was changed: writes %v", fake.Writes())
			}
			if !tc.refused && tc.listed && fake.Zones["csSb01"] {
				t.Fatal("the run's zone was not deleted")
			}
		})
	}
}

// A zone the manager itself created, PVE confirming it, is the run's: teardown
// in the same process deletes it even with no VNet left to show it.
func TestDestroyZoneDeletesTheZoneItCreated(t *testing.T) {
	fake := sdntest.New()
	fake.Lock = "tok"
	m := holding(NewManager(fake.Serve(t)), "tok")
	m.SetOwnerMarker(runMarker)
	if err := m.CreateZone(context.Background(), config.Network{ZoneID: "csSb01", Mode: "simple"}, "node1"); err != nil {
		t.Fatal(err)
	}
	fake.Do(func(p *sdntest.PVE) { p.RunningZones["csSb01"] = true })
	if err := m.DestroyZone(context.Background(), "csSb01"); err != nil || fake.Zones["csSb01"] {
		t.Fatalf("DestroyZone = %v, zone still configured %v", err, fake.Zones["csSb01"])
	}
}

// Recovery reads which zones are the run's before it deletes the run's VNets:
// once the marked VNet is gone, nothing in PVE would show it.
func TestProveZonesBeforeTheVNetGoes(t *testing.T) {
	fake := sdntest.New().Applied("csSb01", "csVn01", "s1")
	fake.Aliases["csVn01"] = runMarker
	fake.Lock = "tok"
	m := holding(NewManager(fake.Serve(t)), "tok")
	m.SetOwnerMarker(runMarker)
	if err := m.ProveZones(context.Background(), []string{"csSb01"}); err != nil {
		t.Fatal(err)
	}
	if err := m.DestroyVNet(context.Background(), "csVn01"); err != nil {
		t.Fatal(err)
	}
	// An apply in between commits the VNet's deletion: PVE no longer shows it.
	fake.Do(func(p *sdntest.PVE) {
		p.RunningVNets, p.RunningAliases = map[string]string{}, map[string]string{}
		p.RunningSubnets = map[string][]string{}
	})
	if err := m.DestroyZone(context.Background(), "csSb01"); err != nil || fake.Zones["csSb01"] {
		t.Fatalf("DestroyZone = %v, zone still configured %v", err, fake.Zones["csSb01"])
	}
}

// The preview's view of what recovery would leave: a VNet that is not
// provably the run's, the zone that goes with it, and everything PVE lists when
// the journal names no marker.
func TestRecoveryRefusals(t *testing.T) {
	setup := func(alias string) *sdntest.PVE {
		fake := sdntest.New().Applied("csSb01", "csVn01", "s1")
		if alias != "" {
			fake.Aliases["csVn01"] = alias
		}
		return fake
	}
	refusals := func(t *testing.T, fake *sdntest.PVE, marker string) []string {
		t.Helper()
		m := NewManager(fake.Serve(t))
		m.SetOwnerMarker(marker)
		refused, err := m.RecoveryRefusals(context.Background(), []string{"csSb01"}, []string{"csVn01"})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range refused {
			out = append(out, r.Resource+" "+r.ID)
		}
		return out
	}
	if got := refusals(t, setup(runMarker), runMarker); len(got) != 0 {
		t.Fatalf("refusals %v; want none for the run's own VNet and zone", got)
	}
	if got := strings.Join(refusals(t, setup("an administrator's"), runMarker), ","); got != "VNet csVn01,zone csSb01" {
		t.Fatalf("refusals %q; want the replacement VNet and the zone with it", got)
	}
	if got := strings.Join(refusals(t, setup(""), ""), ","); got != "VNet csVn01,zone csSb01" {
		t.Fatalf("refusals %q; want both refused for a journal that names no marker", got)
	}
	if got := refusals(t, sdntest.New(), ""); len(got) != 0 {
		t.Fatalf("refusals %v; want none where PVE lists nothing", got)
	}
}
