//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// PVE 8.4.0 has no /cluster/sdn/lock: recovery of an interrupted run on a
// PVE 8 settles the SDN with no lock. It asks PVE for one at most once, takes
// nothing and releases nothing, sends no lock parameter (the fake refuses one),
// and does not clean a journal over a pending change that is not the run's.

func pve8(fake *sdntest.PVE) *sdntest.PVE {
	fake.NoLockAPI = true
	return fake
}

func lockRequests(fake *sdntest.PVE) (calls []string) {
	fake.Do(func(p *sdntest.PVE) {
		for _, r := range p.Requests {
			if _, path, _ := strings.Cut(r, " "); strings.HasPrefix(path, "cluster/sdn/lock") {
				calls = append(calls, r)
			}
		}
	})
	return calls
}

func TestRecoverOnAPVEWithoutALockDeletesAndAppliesWithoutOne(t *testing.T) {
	fake := pve8(appliedSandbox())
	recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-pve8"))
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked: %v", err)
	}
	want := strings.Join([]string{
		"POST cluster/sdn/lock",
		"DELETE cluster/sdn/vnets/csVn77/subnets/csZone77-10.89.0.0-24",
		"DELETE cluster/sdn/vnets/csVn77",
		"DELETE cluster/sdn/zones/csZone77",
		"PUT cluster/sdn",
	}, "\n")
	if got := strings.Join(fake.Writes(), "\n"); got != want {
		t.Fatalf("writes:\n%s\nwant:\n%s", got, want)
	}
	record := loadRecord(t, dir)
	if record.Phase != "cleaned" || record.SDNLockToken != "" || record.SDNLockRequested != "" || !strings.HasPrefix(record.SDNApplyTask, "UPID:node1:") || fake.Pending() {
		t.Fatalf("journal %+v, pending %v", record, fake.Pending())
	}
}

// A run that died while its lock request was in flight journals the request;
// on a PVE that has no lock, PVE's answer to recovery's own request says none
// can stand, and the mark is taken back with nothing released.
func TestRecoverSettlesALockRequestOnAPVEWithoutALock(t *testing.T) {
	for name, pending := range map[string]bool{"nothing pending": false, "an administrator's change pending": true} {
		t.Run(name, func(t *testing.T) {
			fake := pve8(sdntest.New())
			if pending {
				fake.Zones["prodZ"] = true
			}
			recoverAgainst(t, fake)
			record := sandboxRecord("recover-pve8-request")
			record.SDNLockRequested = "2026-09-29T20:00:00Z"
			dir := writeRecord(t, record)
			if err := RecoverLocked(dir); err != nil {
				t.Fatalf("RecoverLocked: %v", err)
			}
			if got := strings.Join(fake.Writes(), "\n"); got != "POST cluster/sdn/lock" {
				t.Fatalf("writes:\n%s\nwant the one probe", got)
			}
			if got := loadRecord(t, dir); got.Phase != "cleaned" || got.SDNLockRequested != "" || got.SDNLockToken != "" {
				t.Fatalf("journal %+v; want cleaned, the lock request taken back", got)
			}
			if pending && !fake.Pending() {
				t.Fatal("the administrator's change was applied")
			}
		})
	}
}

// A token the journal holds belongs to another PVE's lock: there is none to
// release here, and it is not sent.
func TestRecoverDropsATokenJournaledForAnotherPVE(t *testing.T) {
	fake := pve8(appliedSandbox())
	recoverAgainst(t, fake)
	record := sandboxRecord("recover-pve8-token")
	record.SDNLockToken = "tok-dead"
	dir := writeRecord(t, record)
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked: %v", err)
	}
	if calls := lockRequests(fake); len(calls) != 1 || calls[0] != "POST cluster/sdn/lock" {
		t.Fatalf("lock calls %v; want the one probe and no release", calls)
	}
	for _, w := range fake.Writes() {
		if strings.Contains(w, "tok-dead") {
			t.Fatalf("the journal's token reached PVE: %s", w)
		}
	}
	if got := loadRecord(t, dir); got.Phase != "cleaned" || got.SDNLockToken != "" || fake.Pending() {
		t.Fatalf("journal %+v, pending %v", got, fake.Pending())
	}
}

// Without a lock: an administrator's pending change keeps recovery from
// writing anything, as PVE's refusal of the lock does on a PVE 9; once it is
// applied, a second recovery finishes.
func TestRecoverOnAPVEWithoutALockWritesNothingOverPendingChanges(t *testing.T) {
	fake := pve8(appliedSandbox())
	fake.Zones["prodZ"] = true
	recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-pve8-pending"))
	err := RecoverLocked(dir)
	if err == nil || !strings.Contains(err.Error(), "not the interrupted run's") || !strings.Contains(err.Error(), "zone prodZ (new)") {
		t.Fatalf("RecoverLocked = %v; want the foreign change named", err)
	}
	if got := strings.Join(fake.Writes(), "\n"); got != "POST cluster/sdn/lock" {
		t.Fatalf("writes:\n%s\nwant the probe and nothing else", got)
	}
	if got := loadRecord(t, dir); got.Phase == "cleaned" || len(got.SDNVNets) != 1 || got.SDNLockToken != "" {
		t.Fatalf("journal %+v; want the run's VNet kept and no lock claimed", got)
	}

	// The administrator applies their change.
	fake.Do(func(p *sdntest.PVE) { p.RunningZones["prodZ"] = true })
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("second RecoverLocked: %v", err)
	}
	if got := loadRecord(t, dir); got.Phase != "cleaned" || fake.Pending() || !fake.Zones["prodZ"] {
		t.Fatalf("journal %+v, pending %v, zones %v", got, fake.Pending(), fake.Zones)
	}
}

// On a PVE without an SDN lock, a zone that only allocation_pending names and
// that PVE has configured and never applied is not provably the run's: no lock
// kept another client's creation of that name out. Recovery leaves it, reports
// it as not confirmed as the run's, and keeps the allocation pending, where a
// PVE with a lock deletes it as the run's own.
func TestRecoverOnAPVEWithoutALockLeavesAnUnconfirmedZoneThatIsOnlyNew(t *testing.T) {
	fake := pve8(sdntest.New())
	fake.Zones["csZone77"] = true
	recoverAgainst(t, fake)
	dir := writeRecord(t, unconfirmed("recover-pve8-zone-theirs", "SDN zone csZone77", []string{"csZone77"}, nil, ""))
	err := RecoverLocked(dir)
	if err == nil || !strings.Contains(err.Error(), "cannot show that it is the interrupted run's") {
		t.Fatalf("RecoverLocked = %v, want the zone refused as not confirmed as the run's", err)
	}
	if got := deletesMade(fake); len(got) != 0 {
		t.Fatalf("recovery deleted a zone that is only new, on a PVE with no lock: %v", got)
	}
	if zone, _ := sandboxState(fake); !zone {
		t.Fatal("the zone is gone")
	}
	if got := loadRecord(t, dir); got.Phase == "cleaned" || got.AllocationPending != "SDN zone csZone77" {
		t.Fatalf("journal %+v; want the allocation pending for the operator", got)
	}
}
