//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// deletesMade lists the DELETE writes the fake saw, the SDN lock's own release
// apart.
func deletesMade(fake *sdntest.PVE) []string {
	var out []string
	for _, w := range fake.Writes() {
		if strings.HasPrefix(w, "DELETE ") && !strings.HasPrefix(w, "DELETE cluster/sdn/lock") {
			out = append(out, w)
		}
	}
	return out
}

func sandboxState(fake *sdntest.PVE) (zone, vnet bool) {
	fake.Do(func(p *sdntest.PVE) {
		zone = p.Zones["csZone77"] || p.RunningZones["csZone77"]
		vnet = p.VNets["csVn77"] != "" || p.RunningVNets["csVn77"] != ""
	})
	return zone, vnet
}

// A delete answered with an HTTP 500 whose text says "does not exist"
// is not absence unless PVE says the object recovery deleted is the one that
// does not exist. Any other message of that kind (here the zone's deletion
// answered for a different object) leaves the journal unclean.
func TestRecoverDoesNotCountAnUnrelatedDoesNotExistAsAbsence(t *testing.T) {
	fake := appliedSandbox()
	fake.Fault("DELETE cluster/sdn/zones/csZone77", sdntest.Fault{Refuse: "sdn vnet 'someOtherVnet' does not exist"})
	recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-unrelated-missing"))
	err := RecoverLocked(dir)
	if err == nil {
		t.Fatal("an unrelated \"does not exist\" cleaned the journal")
	}
	if got := loadRecord(t, dir); got.Phase == "cleaned" || len(got.SDNZones) != 1 {
		t.Fatalf("journal %+v; want the zone kept for the next attempt", got)
	}
	if zone, _ := sandboxState(fake); !zone {
		t.Fatal("the zone is gone; the fault refused its deletion")
	}
}

// PVE answering a delete with success is not proof either. The
// journal is cleaned only when PVE's own lists no longer show the zone and
// VNet: here the zone's deletion is answered and not made.
func TestRecoverConfirmsTheDeletionsInPVEsLists(t *testing.T) {
	fake := appliedSandbox()
	fake.Fault("DELETE cluster/sdn/zones/csZone77", sdntest.Fault{Skip: true})
	recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-reply-not-proof"))
	err := RecoverLocked(dir)
	if err == nil || !strings.Contains(err.Error(), "still lists") {
		t.Fatalf("RecoverLocked = %v, want the zone PVE still lists reported", err)
	}
	if got := loadRecord(t, dir); got.Phase == "cleaned" || len(got.SDNZones) != 1 {
		t.Fatalf("journal %+v; want the zone kept", got)
	}
	if fake.Lock != "" {
		t.Fatalf("lock %q kept after the apply", fake.Lock)
	}
}

// The journal names a VNet, and PVE has a VNet of that name that does
// not carry the run's marker: another run's, or one an administrator created
// afterwards. Recovery deletes nothing of it, and says so.
func TestRecoverLeavesAReplacementVNetAlone(t *testing.T) {
	for name, alias := range map[string]string{
		"an administrator's VNet, no alias": "",
		"an administrator's VNet, aliased":  "the payroll network",
		"another run's VNet":                "certistack some-other-run",
	} {
		t.Run(name, func(t *testing.T) {
			fake := appliedSandbox()
			delete(fake.Aliases, "csVn77")
			if alias != "" {
				fake.Aliases["csVn77"] = alias
			}
			recoverAgainst(t, fake)
			dir := writeRecord(t, sandboxRecord("recover-replacement"))
			err := RecoverLocked(dir)
			if err == nil || !strings.Contains(err.Error(), "cannot show that it is the interrupted run's") {
				t.Fatalf("RecoverLocked = %v, want the VNet reported as not provably the run's", err)
			}
			for _, w := range deletesMade(fake) {
				if strings.Contains(w, "vnets/csVn77") {
					t.Fatalf("recovery deleted from a VNet that is not the run's: %s", w)
				}
			}
			if _, vnet := sandboxState(fake); !vnet {
				t.Fatal("the replacement VNet is gone")
			}
			var subnets int
			fake.Do(func(p *sdntest.PVE) { subnets = len(p.Subnets["csVn77"]) })
			if subnets != 1 {
				t.Fatalf("the replacement VNet has %d subnets; want its one left", subnets)
			}
			if got := loadRecord(t, dir); got.Phase == "cleaned" {
				t.Fatalf("journal %+v; a VNet left alone was marked cleaned", got)
			}
			if fake.Lock != "" || fake.Applies != 0 {
				t.Fatalf("lock %q, applies %d; want the lock released and nothing applied", fake.Lock, fake.Applies)
			}
		})
	}
}

// The journals of earlier versions (including builds from before the marker was
// journaled with the zone) carry no marker, and nothing in PVE shows that an
// object of a recorded name is the one the run made: a VNet it created had no
// alias, and neither has one an administrator makes by hand, and a zone has no
// field for one. Recovery fails closed: it deletes nothing of what PVE lists,
// releases the lock the journal holds, and tells the operator what to do.
// Objects PVE no longer lists are the desired end state, and clean the journal.
func TestRecoverALegacyJournalDeletesNothingItCannotShowIsTheRuns(t *testing.T) {
	legacy := func(runID string) string {
		record := sandboxRecord(runID)
		record.SDNOwner = ""
		return writeRecord(t, record)
	}
	for name, prepare := range map[string]func(*sdntest.PVE){
		"a VNet with no alias (what the earlier version made)": func(p *sdntest.PVE) { delete(p.Aliases, "csVn77") },
		"a VNet with another run's alias":                      func(p *sdntest.PVE) { p.Aliases["csVn77"] = "certistack some-other-run" },
	} {
		t.Run(name, func(t *testing.T) {
			fake := appliedSandbox()
			prepare(fake)
			recoverAgainst(t, fake)
			dir := legacy("recover-legacy")
			err := RecoverLocked(dir)
			if err == nil || !strings.Contains(err.Error(), "cannot show that it is the interrupted run's") ||
				!strings.Contains(err.Error(), "delete it there") || !strings.Contains(err.Error(), recoverhint.Again) {
				t.Fatalf("RecoverLocked = %v, want the VNet refused, with what the operator does next", err)
			}
			if got := deletesMade(fake); len(got) != 0 {
				t.Fatalf("recovery deleted on a journal that names no marker: %v", got)
			}
			if zone, vnet := sandboxState(fake); !zone || !vnet {
				t.Fatalf("zone %v, vnet %v; want both left as they were", zone, vnet)
			}
			if got := loadRecord(t, dir); got.Phase == "cleaned" || len(got.SDNZones) != 1 || len(got.SDNVNets) != 1 {
				t.Fatalf("journal %+v; want the objects kept for the operator's deletion", got)
			}
			if fake.Lock != "" || fake.Applies != 0 {
				t.Fatalf("lock %q, applies %d; want no lock kept and nothing applied", fake.Lock, fake.Applies)
			}
			// The operator deletes them in PVE, and recovery finishes.
			fake.Do(func(p *sdntest.PVE) {
				p.Zones, p.RunningZones = map[string]bool{}, map[string]bool{}
				p.VNets, p.RunningVNets = map[string]string{}, map[string]string{}
				p.Subnets, p.RunningSubnets = map[string][]string{}, map[string][]string{}
			})
			if err := RecoverLocked(dir); err != nil || loadRecord(t, dir).Phase != "cleaned" {
				t.Fatalf("RecoverLocked after the operator's deletion = %v, journal %+v", err, loadRecord(t, dir))
			}
		})
	}
	t.Run("a zone alone", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["csZone77"], fake.RunningZones["csZone77"] = true, true
		recoverAgainst(t, fake)
		record := sandboxRecord("recover-legacy-zone")
		record.SDNOwner, record.SDNVNets = "", nil
		dir := writeRecord(t, record)
		err := RecoverLocked(dir)
		if err == nil || !strings.Contains(err.Error(), `sandbox zone "csZone77" exists, but CertiStack cannot show`) {
			t.Fatalf("RecoverLocked = %v, want the zone refused", err)
		}
		if got := deletesMade(fake); len(got) != 0 {
			t.Fatalf("recovery deleted a zone on a journal that names no marker: %v", got)
		}
	})
	t.Run("nothing left in PVE", func(t *testing.T) {
		fake := sdntest.New()
		recoverAgainst(t, fake)
		dir := legacy("recover-legacy-gone")
		if err := RecoverLocked(dir); err != nil || loadRecord(t, dir).Phase != "cleaned" {
			t.Fatalf("RecoverLocked = %v, journal %+v; want the journal of objects long gone cleaned", err, loadRecord(t, dir))
		}
	})
}

// The VNet is refused (another run's, or an administrator's), and its
// zone is left with it. Recovery used to go on to delete the zone, leaving only
// PVE's "zone is used by vnet" check between a replacement zone and deletion.
func TestRecoverLeavesTheZoneWhenItsVNetIsRefused(t *testing.T) {
	fake := appliedSandbox()
	fake.Aliases["csVn77"] = "an administrator's VNet"
	recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-zone-with-refused-vnet"))
	err := RecoverLocked(dir)
	if err == nil || !strings.Contains(err.Error(), "left SDN zone csZone77 in place") {
		t.Fatalf("RecoverLocked = %v, want the zone reported as left in place", err)
	}
	for _, w := range deletesMade(fake) {
		if strings.Contains(w, "zones/") || strings.Contains(w, "vnets/") {
			t.Fatalf("recovery deleted after the VNet was refused: %s", w)
		}
	}
	if zone, vnet := sandboxState(fake); !zone || !vnet {
		t.Fatalf("zone %v, vnet %v; want both left", zone, vnet)
	}
	if fake.Lock != "" || fake.Applies != 0 {
		t.Fatalf("lock %q, applies %d; want the lock released and nothing applied", fake.Lock, fake.Applies)
	}

	// The same over the lock-less exception: both objects are the run's
	// never-applied creations, and the VNet's marker is not the run's.
	fake = sdntest.New()
	fake.Zones["csZone77"], fake.VNets["csVn77"] = true, "csZone77"
	fake.Aliases["csVn77"] = "an administrator's VNet"
	recoverAgainst(t, fake)
	dir = writeRecord(t, sandboxRecord("recover-never-applied-refused-vnet"))
	if err := RecoverLocked(dir); err == nil || !strings.Contains(err.Error(), "left SDN zone csZone77 in place") {
		t.Fatalf("RecoverLocked = %v, want the zone reported as left in place", err)
	}
	if got := deletesMade(fake); len(got) != 0 {
		t.Fatalf("the lock-less exception deleted after the VNet was refused: %v", got)
	}
}

// PVE's SDN lock is refused for a reason other than the run's own
// pending changes (here another lock stands), so recovery writes nothing
// to SDN: every lock refusal is a barrier.
func TestRecoverWritesNothingWhenTheLockIsRefused(t *testing.T) {
	for name, prepare := range map[string]func(*sdntest.PVE){
		"another lock stands": func(p *sdntest.PVE) { p.Lock = "someone-elses" },
		"the lock request fails": func(p *sdntest.PVE) {
			p.Fault("POST cluster/sdn/lock", sdntest.Fault{Refuse: "Service Unavailable", Status: 500})
		},
		"an administrator's change is pending": func(p *sdntest.PVE) { p.Zones["prodZ"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			fake := appliedSandbox()
			prepare(fake)
			recoverAgainst(t, fake)
			dir := writeRecord(t, sandboxRecord("recover-lock-refused"))
			if err := RecoverLocked(dir); err == nil {
				t.Fatal("recovery reported success with the lock refused")
			}
			for _, w := range fake.Writes() {
				if !strings.HasPrefix(w, "POST cluster/sdn/lock") {
					t.Fatalf("recovery wrote to SDN with the lock refused: %v", fake.Writes())
				}
			}
			if zone, vnet := sandboxState(fake); !zone || !vnet {
				t.Fatalf("zone %v, vnet %v; want both left as they were", zone, vnet)
			}
			if got := loadRecord(t, dir); got.Phase == "cleaned" || len(got.SDNZones) != 1 || len(got.SDNVNets) != 1 {
				t.Fatalf("journal %+v; want the run's objects kept", got)
			}
		})
	}
}

// One exception: the run's own never-applied creations are the ONLY
// pending changes. PVE refuses the lock over them, and nothing of an
// administrator's is at stake, so recovery deletes them without a lock, which
// leaves nothing pending and nothing to apply. With an administrator's change
// beside them it writes nothing at all.
func TestRecoverRemovesTheRunsNeverAppliedObjectsOnlyWhenTheyAreAllThatIsPending(t *testing.T) {
	neverApplied := func() *sdntest.PVE {
		fake := sdntest.New()
		fake.Zones["csZone77"], fake.VNets["csVn77"] = true, "csZone77"
		fake.Subnets["csVn77"] = []string{"csZone77-10.89.0.0-24"}
		fake.Aliases["csVn77"] = testOwner
		return fake
	}
	t.Run("alone", func(t *testing.T) {
		fake := neverApplied()
		recoverAgainst(t, fake)
		dir := writeRecord(t, sandboxRecord("recover-never-applied"))
		if err := RecoverLocked(dir); err != nil {
			t.Fatalf("RecoverLocked: %v", err)
		}
		if zone, vnet := sandboxState(fake); zone || vnet || fake.Pending() || fake.Applies != 0 || loadRecord(t, dir).Phase != "cleaned" {
			t.Fatalf("zone %v, vnet %v, pending %v, applies %d, journal %+v", zone, vnet, fake.Pending(), fake.Applies, loadRecord(t, dir))
		}
	})
	t.Run("beside an administrator's change", func(t *testing.T) {
		fake := neverApplied()
		fake.Zones["prodZ"] = true
		recoverAgainst(t, fake)
		dir := writeRecord(t, sandboxRecord("recover-never-applied-beside"))
		if err := RecoverLocked(dir); err == nil {
			t.Fatal("recovery reported success over an administrator's pending change")
		}
		if got := deletesMade(fake); len(got) != 0 {
			t.Fatalf("recovery deleted over an administrator's pending change: %v", got)
		}
		if zone, vnet := sandboxState(fake); !zone || !vnet {
			t.Fatalf("zone %v, vnet %v; want both left", zone, vnet)
		}
	})
}

// The lock-less exception decides on what is pending NOW. The run's
// objects were never applied when recovery first looked, and an administrator
// applies SDN between PVE's refusal of the lock and the exception's read: the
// run's objects are running then, and deleting them without the lock would
// leave a deletion pending that nobody applies.
func TestRecoverExceptionDoesNotActOnStatesAnApplyHasOvertaken(t *testing.T) {
	fake := sdntest.New()
	fake.Zones["csZone77"], fake.VNets["csVn77"] = true, "csZone77"
	fake.Subnets["csVn77"] = []string{"csZone77-10.89.0.0-24"}
	fake.Aliases["csVn77"] = testOwner
	applied := false
	fake.Fault("GET cluster/sdn/controllers", sdntest.Fault{Before: func() {
		if applied {
			return
		}
		applied = true
		fake.Do(func(p *sdntest.PVE) {
			p.RunningZones, p.RunningVNets, p.RunningSubnets = map[string]bool{"csZone77": true}, map[string]string{"csVn77": "csZone77"}, map[string][]string{"csVn77": {"csZone77-10.89.0.0-24"}}
		})
	}})
	recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-overtaken"))
	err := RecoverLocked(dir)
	if err == nil {
		t.Fatal("recovery reported success over a state it did not settle")
	}
	for _, w := range deletesMade(fake) {
		if strings.Contains(w, "lock-token") {
			continue
		}
		t.Fatalf("recovery deleted without the lock after the objects were applied: %v", fake.Writes())
	}
	if fake.Pending() {
		t.Fatalf("recovery left a deletion pending: writes %v", fake.Writes())
	}
}

// The run's own deletions are the only pending change and no lock
// stands: PVE refuses the lock, and the message says so instead of blaming
// someone else's change.
func TestRecoverSaysWhenTheOnlyPendingChangesAreTheRunsOwnDeletions(t *testing.T) {
	fake := deletedNotApplied()
	recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-own-deletions"))
	err := RecoverLocked(dir)
	if err == nil || !strings.Contains(err.Error(), "the only pending SDN changes are the interrupted run's own") || strings.Contains(err.Error(), "that are not the interrupted run's") {
		t.Fatalf("RecoverLocked = %v, want it to say the pending changes are the run's own", err)
	}
	if got := fake.Writes(); len(got) != 0 {
		for _, w := range got {
			if !strings.HasPrefix(w, "POST cluster/sdn/lock") {
				t.Fatalf("recovery wrote %v over its own pending deletions without a lock", got)
			}
		}
	}
}

// A journal that also carries an unknown-apply marker is cleaned by the
// exception without keeping the marker: no apply follows from it.
func TestRecoverExceptionClearsTheUnknownApplyMarker(t *testing.T) {
	fake := sdntest.New()
	fake.Zones["csZone77"], fake.VNets["csVn77"] = true, "csZone77"
	fake.Aliases["csVn77"] = testOwner
	recoverAgainst(t, fake)
	record := sandboxRecord("recover-exception-unknown")
	record.SDNApplyUnknown = "2026-09-30T04:00:00Z"
	dir := writeRecord(t, record)
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked: %v", err)
	}
	if got := loadRecord(t, dir); got.Phase != "cleaned" || got.SDNApplyUnknown != "" {
		t.Fatalf("journal %+v; want cleaned with no unknown-apply marker", got)
	}
}
