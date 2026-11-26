// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// running is a reloadnetworkall task PVE still runs.
func running() map[string]interface{} {
	return map[string]interface{}{"type": "reloadnetworkall", "endtime": 0, "upid": "UPID:node1:00000001:1:1:reloadnetworkall::root@pam:"}
}

// An apply whose reply was lost (or named no task) has an outcome
// nobody knows: PVE may be reloading the nodes for it. The journal says so, and
// no apply starts until PVE lists no running reloadnetworkall task.
func TestApplyWhoseReplyWasLostBlocksTheNextApplyUntilNoneRuns(t *testing.T) {
	fake := sdntest.New()
	fake.Fault("PUT cluster/sdn", sdntest.Fault{Lose: true})
	journal := &journalOf{}
	m := NewManager(fake.Serve(t))
	m.SetPersist(journal.persist)
	m.SetApplyWait(time.Millisecond)
	if err := holding(m, "tok-a").Reload(context.Background()); err == nil {
		t.Fatal("a lost reply was reported as an apply")
	}
	if !journal.last().ApplyUnknown {
		t.Fatalf("journaled %+v; want the lost apply recorded", journal.last())
	}
	// The lost apply's task is still running.
	fake.Do(func(p *sdntest.PVE) { p.Tasks = []map[string]interface{}{running()} })
	applies := fake.Applies
	if err := holding(m, "tok-b").Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "has not ended") || fake.Applies != applies {
		t.Fatalf("Reload = %v with %d applies (was %d); want a refusal while an apply runs", err, fake.Applies, applies)
	}
	if !journal.last().ApplyUnknown {
		t.Fatal("the marker was cleared while an apply still ran")
	}
	// It ends: the next apply goes ahead, and the marker goes.
	fake.Do(func(p *sdntest.PVE) { p.Tasks = nil })
	if err := holding(m, "tok-b").Reload(context.Background()); err != nil || fake.Applies != applies+1 {
		t.Fatalf("Reload = %v with %d applies; want the apply after the running one ended", err, fake.Applies)
	}
	if journal.last().ApplyUnknown {
		t.Fatalf("journaled %+v after the apply; want the marker cleared", journal.last())
	}
}

// An unknown apply is never waited past when PVE's task list cannot be
// read or is not a list: nothing is applied over it.
func TestUnknownApplyNeedsAReadableTaskList(t *testing.T) {
	for name, fault := range map[string]sdntest.Fault{
		"unreadable": {Refuse: "permission denied", Status: 403},
		"not a list": {Answer: `null`},
	} {
		t.Run(name, func(t *testing.T) {
			fake := sdntest.New()
			fake.Fault("GET cluster/tasks", fault)
			m := NewManager(fake.Serve(t))
			m.AdoptApplyUnknown()
			if err := holding(m, "tok").Reload(context.Background()); err == nil || fake.Applies != 0 {
				t.Fatalf("Reload = %v with %d applies; want a refusal", err, fake.Applies)
			}
			if !m.ApplyUnknown() {
				t.Fatal("the marker was dropped without knowing the apply ended")
			}
		})
	}
}

// A lock token PVE may no longer honor (adopted, or spent by an
// apply whose reply was lost) is used only while a lock stands, and then only
// when every pending change is the run's own: PVE offers no apply that checks
// the lock and commits in one step, so a lock another client releases in
// between would leave PVE taking the token for anything.
func TestStaleTokenAppliesOnlyTheRunsOwnPendingChanges(t *testing.T) {
	t.Run("an administrator's change is pending", func(t *testing.T) {
		fake := sdntest.New().Applied("csSb01", "csVn01", "s1")
		fake.Zones["prodZ"] = true // pending, and made under the lock now standing
		fake.Lock = "tok-theirs"
		m := NewManager(fake.Serve(t))
		m.SetOwnObjects([]string{"csSb01"}, []string{"csVn01"})
		m.AdoptLock("tok-dead")
		err := m.Reload(context.Background())
		if !errors.Is(err, ErrPendingSDNChanges) || !strings.Contains(err.Error(), "zone prodZ (new)") || fake.Applies != 0 {
			t.Fatalf("Reload = %v with %d applies; want the foreign change refused", err, fake.Applies)
		}
		for _, w := range fake.Writes() {
			if strings.HasPrefix(w, "PUT") {
				t.Fatalf("a PUT was sent over a foreign pending change: %v", fake.Writes())
			}
		}
	})
	t.Run("only the run's own deletion is pending", func(t *testing.T) {
		fake := sdntest.New().Applied("csSb01", "csVn01", "s1")
		fake.Zones = map[string]bool{}
		fake.VNets, fake.Subnets = map[string]string{}, map[string][]string{}
		fake.Lock = "tok-dead"
		m := NewManager(fake.Serve(t))
		m.SetOwnObjects([]string{"csSb01"}, []string{"csVn01"})
		m.AdoptLock("tok-dead")
		if err := m.Reload(context.Background()); err != nil || fake.Applies != 1 || fake.Pending() {
			t.Fatalf("Reload = %v with %d applies, pending %v; want the run's own change applied", err, fake.Applies, fake.Pending())
		}
	})
}

// A lock request that provably never reached PVE (the call was
// canceled before it was sent, no connection was ever made, the client is not
// configured) left no lock behind: it is not recorded as unresolved.
func TestLockRequestThatNeverReachedPVEIsNotUnknown(t *testing.T) {
	t.Run("canceled before it was sent", func(t *testing.T) {
		fake := sdntest.New()
		journal := &journalOf{}
		m := NewManager(fake.Serve(t))
		m.SetPersist(journal.persist)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := m.Lock(ctx); err == nil || errors.Is(err, ErrSDNLockUnknown) {
			t.Fatalf("Lock = %v; want a plain failure", err)
		}
		if m.LockRequestUnresolved() || journal.last().Requested || len(fake.Requests) != 0 {
			t.Fatalf("unresolved %v, journal %+v, requests %v", m.LockRequestUnresolved(), journal.last(), fake.Requests)
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		server := httptest.NewServer(nil)
		url := server.URL
		server.Close()
		journal := &journalOf{}
		m := NewManager(pve.NewClient(pve.Config{BaseURL: url}))
		m.SetPersist(journal.persist)
		// The client retries a refused connection over seconds; the call gives
		// up after the first attempt.
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		if err := m.Lock(ctx); err == nil || errors.Is(err, ErrSDNLockUnknown) {
			t.Fatalf("Lock = %v; want a plain failure", err)
		}
		if m.LockRequestUnresolved() || journal.last().Requested {
			t.Fatalf("unresolved %v, journal %+v", m.LockRequestUnresolved(), journal.last())
		}
	})
	t.Run("client not configured", func(t *testing.T) {
		journal := &journalOf{}
		m := NewManager(pve.NewClient(pve.Config{BaseURL: "ftp://not-pve.example"}))
		m.SetPersist(journal.persist)
		if err := m.Lock(context.Background()); err == nil || errors.Is(err, ErrSDNLockUnknown) {
			t.Fatalf("Lock = %v; want a plain failure", err)
		}
		if m.LockRequestUnresolved() || journal.last().Requested {
			t.Fatalf("unresolved %v, journal %+v", m.LockRequestUnresolved(), journal.last())
		}
	})
	t.Run("an earlier lost request stays unresolved", func(t *testing.T) {
		fake := sdntest.New()
		m := NewManager(fake.Serve(t))
		m.AdoptLockRequest()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = m.Lock(ctx)
		if !m.LockRequestUnresolved() {
			t.Fatal("a never-sent request resolved an earlier lost one")
		}
	})
}

// A write PVE accepts with an adopted token while a lock is known to
// stand proves that lock is the token's, so a request whose answer was lost
// earlier cannot have left a lock: it is settled, not kept in a cleaned journal.
func TestAcceptedWriteUnderTheStandingLockSettlesALostRequest(t *testing.T) {
	fake := sdntest.New().Applied("csSb01", "csVn01", "s1")
	fake.Lock = "tok-dead"
	fake.Aliases["csVn01"] = "certistack run-a"
	journal := &journalOf{}
	m := NewManager(fake.Serve(t))
	m.SetOwnerMarker("certistack run-a")
	m.SetPersist(journal.persist)
	m.AdoptLock("tok-dead")
	m.AdoptLockRequest()
	if err := m.EnsureLock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.DestroyVNet(context.Background(), "csVn01"); err != nil {
		t.Fatal(err)
	}
	if m.LockRequestUnresolved() {
		t.Fatal("a delete accepted under the standing lock left the lost request unresolved")
	}
	if err := m.Unlock(context.Background()); err != nil || journal.last().Requested {
		t.Fatalf("Unlock = %v, journal %+v; want the request gone from the journal", err, journal.last())
	}
}

// Deletes PVE accepted are counted, so that a caller does not release
// the lock over a pending deletion (a subnet, with its VNet's own deletion
// refused, is still a change).
func TestMutationsCountAcceptedDeletesEvenWhenTheVNetIsRefused(t *testing.T) {
	fake := sdntest.New().Applied("csSb01", "csVn01", "csSb01-10.100.0.0-24")
	fake.Fault("DELETE cluster/sdn/vnets/csVn01", sdntest.Fault{Refuse: "delete sdn vnet object failed: cfs-lock 'domain-sdn' error: got lock request timeout"})
	fake.Aliases["csVn01"] = "certistack run-a"
	m := holding(NewManager(fake.Serve(t)), "tok")
	m.SetOwnerMarker("certistack run-a")
	err := m.DestroyVNet(context.Background(), "csVn01")
	if err == nil || m.Mutations() != 1 || !m.Mutated() {
		t.Fatalf("DestroyVNet = %v, mutations %d; want the subnet's deletion counted and the VNet's error", err, m.Mutations())
	}
}
