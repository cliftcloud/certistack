//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// unconfirmed is a journal of the version that records the zone and VNet before
// it sends their creation: the run died after sending the request whose name is
// in allocation_pending, holding its lock.
func unconfirmed(runID, pending string, zones, vnets []string, token string) journal.Record {
	return journal.Record{
		RunID: runID, Phase: "running", UpdatedAt: time.Now().UTC(),
		SDNZones: zones, SDNVNets: vnets, SDNOwner: testOwner, AllocationPending: pending, SDNLockToken: token,
	}
}

func onlyLockWrites(fake *sdntest.PVE) bool {
	for _, w := range fake.Writes() {
		if !strings.HasPrefix(w, "POST cluster/sdn/lock") && !strings.HasPrefix(w, "DELETE cluster/sdn/lock") {
			return false
		}
	}
	return true
}

// The run died after sending a zone's creation, holding the SDN lock
// its journal records. The request may have been made or not; recovery reads
// PVE, deletes what it made under the run's own lock, and settles the
// allocation once PVE's lists show nothing of it is left.
func TestRecoverSettlesAnUnconfirmedZoneCreation(t *testing.T) {
	t.Run("PVE never made it", func(t *testing.T) {
		fake := sdntest.New()
		fake.Lock = "tok-dead"
		recoverAgainst(t, fake)
		dir := writeRecord(t, unconfirmed("recover-zone-never-made", "SDN zone csZone77", []string{"csZone77"}, nil, "tok-dead"))
		if err := RecoverLocked(dir); err != nil {
			t.Fatalf("RecoverLocked: %v", err)
		}
		if got := loadRecord(t, dir); got.Phase != "cleaned" || got.AllocationPending != "" || got.SDNLockToken != "" || fake.Lock != "" || fake.Applies != 0 || !onlyLockWrites(fake) {
			t.Fatalf("journal %+v, lock %q, writes %v; want cleaned, the lock released, nothing else written", got, fake.Lock, fake.Writes())
		}
	})
	t.Run("PVE made it and the reply was lost", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csZone77"] = true // pending: never applied
		fake.Lock = "tok-dead"
		recoverAgainst(t, fake)
		dir := writeRecord(t, unconfirmed("recover-zone-made", "SDN zone csZone77", []string{"csZone77"}, nil, "tok-dead"))
		if err := RecoverLocked(dir); err != nil {
			t.Fatalf("RecoverLocked: %v", err)
		}
		if zone, _ := sandboxState(fake); zone || fake.Pending() || fake.Lock != "" || fake.Applies != 0 {
			t.Fatalf("zone %v, pending %v, lock %q, applies %d; want it deleted under the run's lock with nothing left to apply", zone, fake.Pending(), fake.Lock, fake.Applies)
		}
		for _, w := range deletesMade(fake) {
			if !strings.Contains(w, "lock-token=tok-dead") {
				t.Fatalf("a deletion without the run's lock: %s", w)
			}
		}
		if got := loadRecord(t, dir); got.Phase != "cleaned" || got.AllocationPending != "" || got.SDNLockToken != "" {
			t.Fatalf("journal %+v; want cleaned with the allocation settled", got)
		}
	})
	t.Run("a zone of that name someone else applied", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csZone77"], fake.RunningZones["csZone77"] = true, true
		fake.Lock = "tok-dead"
		recoverAgainst(t, fake)
		dir := writeRecord(t, unconfirmed("recover-zone-theirs", "SDN zone csZone77", []string{"csZone77"}, nil, "tok-dead"))
		err := RecoverLocked(dir)
		if err == nil || !strings.Contains(err.Error(), "cannot show that it is the interrupted run's") {
			t.Fatalf("RecoverLocked = %v, want the zone refused", err)
		}
		if got := deletesMade(fake); len(got) != 0 {
			t.Fatalf("recovery deleted a zone the run never applied: %v", got)
		}
		if got := loadRecord(t, dir); got.Phase == "cleaned" || got.AllocationPending != "SDN zone csZone77" {
			t.Fatalf("journal %+v; want the allocation still pending for the operator", got)
		}
	})
	t.Run("PVE's reply to the deletion is not proof", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csZone77"] = true
		fake.Lock = "tok-dead"
		fake.Fault("DELETE cluster/sdn/zones/csZone77", sdntest.Fault{Skip: true})
		recoverAgainst(t, fake)
		dir := writeRecord(t, unconfirmed("recover-zone-skip", "SDN zone csZone77", []string{"csZone77"}, nil, "tok-dead"))
		err := RecoverLocked(dir)
		if err == nil || !strings.Contains(err.Error(), "still lists") {
			t.Fatalf("RecoverLocked = %v, want the zone PVE still lists reported", err)
		}
		if got := loadRecord(t, dir); got.Phase == "cleaned" || got.AllocationPending != "SDN zone csZone77" {
			t.Fatalf("journal %+v; the allocation is settled only once PVE's lists show nothing left", got)
		}
	})
}

// The same for a VNet whose creation was sent (the zone is there, never
// applied): the VNet carries the run's marker if PVE made it.
func TestRecoverSettlesAnUnconfirmedVNetCreation(t *testing.T) {
	record := func(runID string) journal.Record {
		return unconfirmed(runID, "SDN VNet csVn77", []string{"csZone77"}, []string{"csVn77"}, "tok-dead")
	}
	t.Run("PVE made it", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csZone77"], fake.VNets["csVn77"], fake.Aliases["csVn77"] = true, "csZone77", testOwner
		fake.Lock = "tok-dead"
		recoverAgainst(t, fake)
		dir := writeRecord(t, record("recover-vnet-made"))
		if err := RecoverLocked(dir); err != nil {
			t.Fatalf("RecoverLocked: %v", err)
		}
		if zone, vnet := sandboxState(fake); zone || vnet || fake.Pending() || fake.Lock != "" || fake.Applies != 0 {
			t.Fatalf("zone %v, vnet %v, pending %v, lock %q, applies %d; want both deleted under the run's lock, nothing to apply", zone, vnet, fake.Pending(), fake.Lock, fake.Applies)
		}
		if got := loadRecord(t, dir); got.Phase != "cleaned" || got.AllocationPending != "" {
			t.Fatalf("journal %+v; want cleaned with the allocation settled", got)
		}
	})
	t.Run("PVE never made it", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csZone77"] = true
		fake.Lock = "tok-dead"
		recoverAgainst(t, fake)
		dir := writeRecord(t, record("recover-vnet-never-made"))
		if err := RecoverLocked(dir); err != nil {
			t.Fatalf("RecoverLocked: %v", err)
		}
		if zone, vnet := sandboxState(fake); zone || vnet || fake.Pending() || fake.Lock != "" {
			t.Fatalf("zone %v, vnet %v, pending %v, lock %q; want the zone deleted and nothing else", zone, vnet, fake.Pending(), fake.Lock)
		}
		if got := loadRecord(t, dir); got.Phase != "cleaned" || got.AllocationPending != "" {
			t.Fatalf("journal %+v; want cleaned with the allocation settled", got)
		}
	})
	t.Run("a VNet of that name that is not the run's", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csZone77"], fake.VNets["csVn77"], fake.Aliases["csVn77"] = true, "csZone77", "the payroll network"
		fake.Lock = "tok-dead"
		recoverAgainst(t, fake)
		dir := writeRecord(t, record("recover-vnet-theirs"))
		err := RecoverLocked(dir)
		if err == nil || !strings.Contains(err.Error(), "cannot show that it is the interrupted run's") {
			t.Fatalf("RecoverLocked = %v, want the VNet refused", err)
		}
		if got := deletesMade(fake); len(got) != 0 {
			t.Fatalf("recovery deleted after the VNet was refused: %v", got)
		}
		if got := loadRecord(t, dir); got.Phase == "cleaned" || got.AllocationPending != "SDN VNet csVn77" {
			t.Fatalf("journal %+v; want the allocation still pending", got)
		}
	})
}

// A run whose CreateVNet reply was lost leaves the zone and the VNet pending,
// the lock released, and the VNet only in allocation_pending. Recovery finds
// it by name (it carries the journaled marker), deletes both without a lock
// since they are the only pending changes, and clears the allocation after
// PVE's lists show them gone.
func TestRecoverSettlesThePendingObjectsOfALostVNetReply(t *testing.T) {
	fake := sdntest.New()
	fake.Zones["csZone77"], fake.VNets["csVn77"], fake.Aliases["csVn77"] = true, "csZone77", testOwner
	recoverAgainst(t, fake)
	wedged := unconfirmed("recover-wedged-vnet", "SDN VNet csVn77", []string{"csZone77"}, nil, "")
	wedged.Phase = "cleanup_failed"
	dir := writeRecord(t, wedged)
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked: %v", err)
	}
	if zone, vnet := sandboxState(fake); zone || vnet || fake.Pending() || fake.Applies != 0 {
		t.Fatalf("zone %v, vnet %v, pending %v, applies %d; want both deleted with nothing pending", zone, vnet, fake.Pending(), fake.Applies)
	}
	if got := loadRecord(t, dir); got.Phase != "cleaned" || got.AllocationPending != "" {
		t.Fatalf("journal %+v; want cleaned with the allocation settled", got)
	}
	// Beside an administrator's pending change nothing is written.
	fake = sdntest.New()
	fake.Zones["csZone77"], fake.VNets["csVn77"], fake.Aliases["csVn77"] = true, "csZone77", testOwner
	fake.Zones["prodZ"] = true
	recoverAgainst(t, fake)
	dir = writeRecord(t, wedged)
	if err := RecoverLocked(dir); err == nil {
		t.Fatal("recovery reported success over an administrator's pending change")
	}
	if got := deletesMade(fake); len(got) != 0 {
		t.Fatalf("recovery deleted over an administrator's pending change: %v", got)
	}
	if got := loadRecord(t, dir); got.AllocationPending != "SDN VNet csVn77" {
		t.Fatalf("journal %+v; want the allocation pending still", got)
	}
}

// Journals already written: a lost CreateZone reply left a zone that only
// allocation_pending names. Such a journal has no marker (the run journaled it
// with the VNet), so nothing shows the pending zone is the run's and recovery
// leaves it, with what the operator does next; a journal with the marker is
// settled as above.
func TestRecoverSettlesThePendingZoneOfALostZoneReply(t *testing.T) {
	pending := func() *sdntest.PVE {
		fake := sdntest.New()
		fake.Zones["csZone77"] = true
		return fake
	}
	t.Run("a journal with no marker", func(t *testing.T) {
		fake := pending()
		recoverAgainst(t, fake)
		wedged := unconfirmed("recover-wedged-zone-old", "SDN zone csZone77", nil, nil, "")
		wedged.SDNOwner = ""
		dir := writeRecord(t, wedged)
		err := RecoverLocked(dir)
		if err == nil || !strings.Contains(err.Error(), `sandbox zone "csZone77" exists, but CertiStack cannot show`) ||
			!strings.Contains(err.Error(), "delete it there") || !strings.Contains(err.Error(), recoverhint.Again) {
			t.Fatalf("RecoverLocked = %v, want the zone refused, with what the operator does next", err)
		}
		if got := deletesMade(fake); len(got) != 0 {
			t.Fatalf("recovery deleted a zone nothing shows is the run's: %v", got)
		}
		if got := loadRecord(t, dir); got.Phase == "cleaned" || got.AllocationPending != "SDN zone csZone77" {
			t.Fatalf("journal %+v; want the allocation pending still", got)
		}
		// The operator deletes the pending zone in PVE.
		fake.Do(func(p *sdntest.PVE) { p.Zones = map[string]bool{} })
		if err := RecoverLocked(dir); err != nil || loadRecord(t, dir).Phase != "cleaned" || loadRecord(t, dir).AllocationPending != "" {
			t.Fatalf("RecoverLocked after the operator's deletion = %v, journal %+v", err, loadRecord(t, dir))
		}
	})
	t.Run("a journal with the marker", func(t *testing.T) {
		fake := pending()
		recoverAgainst(t, fake)
		wedged := unconfirmed("recover-wedged-zone", "SDN zone csZone77", nil, nil, "")
		dir := writeRecord(t, wedged)
		if err := RecoverLocked(dir); err != nil {
			t.Fatalf("RecoverLocked: %v", err)
		}
		if zone, _ := sandboxState(fake); zone || fake.Pending() || fake.Applies != 0 {
			t.Fatalf("zone %v, pending %v, applies %d; want it deleted with nothing pending", zone, fake.Pending(), fake.Applies)
		}
		if got := loadRecord(t, dir); got.Phase != "cleaned" || got.AllocationPending != "" {
			t.Fatalf("journal %+v; want cleaned with the allocation settled", got)
		}
	})
}

// An allocation that is neither an SDN zone or VNet (settled from PVE's lists)
// nor a host probe address (settled from the host, see
// TestRecoverySettlesAHostAddressTheRunWasAddingWhenItStopped) still stops for
// an operator.
func TestRecoverKeepsAnAllocationItCannotSettle(t *testing.T) {
	fake := sdntest.New()
	recoverAgainst(t, fake)
	dir := writeRecord(t, journal.Record{RunID: "recover-other-allocation", Phase: "running", UpdatedAt: time.Now().UTC(), AllocationPending: "VM 9123 creation"})
	err := RecoverLocked(dir)
	if err == nil || !strings.Contains(err.Error(), "cannot safely reconcile unconfirmed allocation") {
		t.Fatalf("RecoverLocked = %v, want the allocation kept for an operator", err)
	}
	if got := loadRecord(t, dir); got.Phase == "cleaned" || got.AllocationPending == "" {
		t.Fatalf("journal %+v", got)
	}
}
