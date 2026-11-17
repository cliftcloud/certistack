//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// running is a reloadnetworkall task PVE still runs.
func running() map[string]interface{} {
	return map[string]interface{}{"type": "reloadnetworkall", "endtime": 0, "upid": "UPID:node1:00000001:1:1:reloadnetworkall::root@pam:"}
}

// deletedNotApplied is a cluster where the run's zone and VNet are gone from the
// configuration but still run: its own deletion is pending.
func deletedNotApplied() *sdntest.PVE {
	fake := appliedSandbox()
	fake.Zones, fake.VNets, fake.Subnets = map[string]bool{}, map[string]string{}, map[string][]string{}
	return fake
}

// The run's setup apply was lost while its task ran, and teardown took a
// new lock and deleted. Recovery does not apply over the running task, keeps the
// lock and the unknown marker, and applies once no apply runs.
func TestRecoverWaitsForARunningApplyWhoseOutcomeWasLost(t *testing.T) {
	fake := deletedNotApplied()
	fake.Lock = "tok-2"
	fake.Tasks = []map[string]interface{}{running()}
	recoverAgainst(t, fake)
	record := sandboxRecord("recover-lost-apply")
	record.SDNLockToken = "tok-2"
	record.SDNApplyUnknown = "2026-09-30T04:00:00Z"
	dir := writeRecord(t, record)

	if err := RecoverLocked(dir); err == nil || !strings.Contains(err.Error(), "has not ended") {
		t.Fatalf("RecoverLocked = %v, want the running apply waited for", err)
	}
	if fake.Applies != 0 {
		t.Fatalf("recovery applied over a running apply (%d applies)", fake.Applies)
	}
	if got := loadRecord(t, dir); got.Phase == "cleaned" || got.SDNLockToken != "tok-2" || got.SDNApplyUnknown == "" {
		t.Fatalf("journal %+v; want the lock and the unknown apply kept", got)
	}

	fake.Do(func(p *sdntest.PVE) { p.Tasks = nil })
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked once no apply runs: %v", err)
	}
	if got := loadRecord(t, dir); got.Phase != "cleaned" || got.SDNLockToken != "" || got.SDNApplyUnknown != "" || fake.Applies != 1 || fake.Pending() {
		t.Fatalf("journal %+v, applies %d, pending %v", got, fake.Applies, fake.Pending())
	}
}

// A recovery that applies nothing does not wait for, or need, the run's
// last apply: an unreadable old task must not keep a journaled token held.
func TestRecoverThatAppliesNothingIgnoresTheRunsLastApply(t *testing.T) {
	fake := sdntest.New()
	fake.Lock = "tok-dead"
	fake.TaskStatus.Status = "running"
	recoverAgainst(t, fake)
	record := sandboxRecord("recover-old-apply")
	record.SDNLockToken = "tok-dead"
	record.SDNApplyTask = "UPID:node9:00000001:1:1:reloadnetworkall::root@pam:"
	record.SDNApplyUnknown = "2026-09-30T04:00:00Z"
	dir := writeRecord(t, record)
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked: %v", err)
	}
	if got := loadRecord(t, dir); got.Phase != "cleaned" || got.SDNLockToken != "" || got.SDNApplyUnknown != "" || fake.Lock != "" {
		t.Fatalf("journal %+v, lock %q; want the token released and the marker cleared", got, fake.Lock)
	}
}

// One failed read under the run's own standing lock does not release
// that lock over the run's pending deletion (no lock would then stand, and PVE
// would refuse every SDN lock over the pending change).
func TestRecoverKeepsTheRunsStandingLockWhenAReadFails(t *testing.T) {
	fake := deletedNotApplied()
	fake.Lock = "tok-dead"
	fake.Fault("GET cluster/sdn/zones", sdntest.Fault{})                            // the read before the lock
	fake.Fault("GET cluster/sdn/zones", sdntest.Fault{Refuse: "temporary failure"}) // HTTP 500: never retried
	recoverAgainst(t, fake)
	record := sandboxRecord("recover-read-fails")
	record.SDNLockToken = "tok-dead"
	dir := writeRecord(t, record)
	if err := RecoverLocked(dir); err == nil {
		t.Fatal("a failed read was not reported")
	}
	if got := loadRecord(t, dir); fake.Lock != "tok-dead" || got.SDNLockToken != "tok-dead" || got.Phase == "cleaned" {
		t.Fatalf("lock %q, journal %+v; want the run's lock kept over its pending deletion", fake.Lock, got)
	}
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("second RecoverLocked: %v", err)
	}
	if got := loadRecord(t, dir); got.Phase != "cleaned" || fake.Lock != "" || fake.Pending() {
		t.Fatalf("journal %+v, lock %q, pending %v", got, fake.Lock, fake.Pending())
	}
}

// A subnet deleted and the VNet's own deletion refused is a pending
// change of a running VNet. Recovery applies it under its lock instead of
// releasing the lock over it (the VNet and zone stay, and are reported).
func TestRecoverAppliesAPartialVNetDeletion(t *testing.T) {
	fake := appliedSandbox()
	fake.Fault("DELETE cluster/sdn/vnets/csVn77", sdntest.Fault{Refuse: "delete sdn vnet object failed: cfs-lock 'domain-sdn' error: got lock request timeout"})
	recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-partial"))
	if err := RecoverLocked(dir); err == nil {
		t.Fatal("a refused VNet deletion was not reported")
	}
	if fake.Lock != "" || fake.Pending() || fake.Applies != 1 {
		t.Fatalf("lock %q, pending %v, applies %d; want the subnet's deletion applied and no lock kept", fake.Lock, fake.Pending(), fake.Applies)
	}
	if got := loadRecord(t, dir); got.Phase == "cleaned" || len(got.SDNVNets) != 1 || got.SDNLockToken != "" {
		t.Fatalf("journal %+v; want the VNet kept for the next attempt, no lock", got)
	}
}

// A lock request whose answer was lost, beside a standing lock that is
// the journaled token's: a delete PVE accepts under it proves the standing lock
// is that token's, so the lost request left none, and the cleaned journal does
// not keep the request.
func TestRecoverSettlesALostRequestWhenTheJournaledLockStands(t *testing.T) {
	fake := sdntest.New()
	fake.Zones["csZone77"], fake.VNets["csVn77"] = true, "csZone77"
	fake.Subnets["csVn77"] = []string{"csZone77-10.89.0.0-24"}
	fake.Aliases["csVn77"] = testOwner
	fake.Lock = "tok-dead"
	recoverAgainst(t, fake)
	record := sandboxRecord("recover-requested-and-token")
	record.SDNLockToken = "tok-dead"
	record.SDNLockRequested = "2026-09-29T20:00:00Z"
	dir := writeRecord(t, record)
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked: %v", err)
	}
	got := loadRecord(t, dir)
	if got.Phase != "cleaned" || got.SDNLockRequested != "" || got.SDNLockToken != "" || fake.Lock != "" {
		t.Fatalf("journal %+v, lock %q; want cleaned with the request settled", got, fake.Lock)
	}
}

// The journal fields are optional: a journal may have none of them, and one
// that is only a lock or an unknown apply is still a journal with something to
// recover.
func TestJournalWithOnlyAnUnknownApplyIsRecoveredAndCleared(t *testing.T) {
	fake := sdntest.New()
	recoverAgainst(t, fake)
	dir := writeRecord(t, journal.Record{RunID: "recover-marker-only", Phase: "cleanup_failed", UpdatedAt: time.Now().UTC(), SDNApplyUnknown: "2026-09-30T04:00:00Z"})
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked: %v", err)
	}
	if got := loadRecord(t, dir); got.Phase != "cleaned" || got.SDNApplyUnknown != "" || len(fake.Writes()) != 0 {
		t.Fatalf("journal %+v, writes %v", got, fake.Writes())
	}
}
