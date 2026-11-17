// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// A zone whose creation was never confirmed is the run's only while PVE's SDN
// lock kept every other client's creation out. PVE 8 has no lock, so a zone
// that is merely configured and never applied ("new") may be another client's,
// created under the same name after the availability read: nothing shows
// whose it is (a zone has no marker), and it is left in place, reported as not
// confirmed as the run's. The run's marker does not change that: it is on the
// VNet, which does not exist yet while the zone's creation is unconfirmed.
func TestDestroyUnconfirmedZoneWithoutAnSDNLockLeavesAZoneThatIsOnlyNew(t *testing.T) {
	t.Run("a never-applied zone", func(t *testing.T) {
		m, fake, _ := pve8(t, 0)
		ctx := context.Background()
		if err := m.Lock(ctx); err != nil || !m.NoLockAPI() {
			t.Fatalf("Lock = %v, NoLockAPI %v; want a manager that knows PVE has no lock", err, m.NoLockAPI())
		}
		// Another client's zone: configured, never applied.
		fake.Do(func(p *sdntest.PVE) { p.Zones["csSb01"] = true })
		before := len(fake.Writes())

		created, err := m.DestroyUnconfirmedZone(ctx, "csSb01")
		var notOwned *NotOwnedError
		if !errors.As(err, &notOwned) || !created {
			t.Fatalf("created %v, err %v; want the zone reported as not confirmed as the run's", created, err)
		}
		if notOwned.Resource != "zone" || notOwned.ID != "csSb01" || !strings.Contains(notOwned.Reason, "no SDN lock") {
			t.Fatalf("refusal %+v; want a zone refusal that says why (this PVE has no SDN lock)", notOwned)
		}
		if writes := fake.Writes()[before:]; len(writes) != 0 || !fake.Zones["csSb01"] || m.Mutated() {
			t.Fatalf("writes %v, zone left %v, mutated %v; want the zone untouched", writes, fake.Zones["csSb01"], m.Mutated())
		}
	})
	t.Run("absent: the creation made nothing", func(t *testing.T) {
		m, fake, _ := pve8(t, 0)
		ctx := context.Background()
		if err := m.Lock(ctx); err != nil {
			t.Fatal(err)
		}
		before := len(fake.Writes())
		created, err := m.DestroyUnconfirmedZone(ctx, "csSb01")
		if err != nil || created || len(fake.Writes()) != before {
			t.Fatalf("created %v, err %v, writes %v; want nothing made and nothing written", created, err, fake.Writes()[before:])
		}
	})
	t.Run("running, which the run never applied", func(t *testing.T) {
		m, fake, _ := pve8(t, 0)
		ctx := context.Background()
		if err := m.Lock(ctx); err != nil {
			t.Fatal(err)
		}
		fake.Do(func(p *sdntest.PVE) { p.Zones["csSb01"], p.RunningZones["csSb01"] = true, true })
		before := len(fake.Writes())
		created, err := m.DestroyUnconfirmedZone(ctx, "csSb01")
		var notOwned *NotOwnedError
		if !errors.As(err, &notOwned) || !created || len(fake.Writes()) != before || !fake.Zones["csSb01"] {
			t.Fatalf("created %v, err %v; want a zone someone else applied left alone", created, err)
		}
	})
}

// With PVE's lock the unchanged rule stands: the run holds the lock while it
// makes its creations, so a zone that is new is its own (TestDestroyUnconfirmedZone).
func TestDestroyUnconfirmedZoneUnderAnSDNLockStillDeletesANewZone(t *testing.T) {
	fake := sdntest.New()
	fake.Zones["csSb01"] = true
	m := holding(marked(NewManager(fake.Serve(t))), "tok")
	if created, err := m.DestroyUnconfirmedZone(context.Background(), "csSb01"); err != nil || !created || fake.Zones["csSb01"] {
		t.Fatalf("created %v, err %v, zone left %v; want the run's never-applied zone deleted under the lock", created, err, fake.Zones["csSb01"])
	}
}
