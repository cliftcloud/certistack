// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// PVE 8.4.0, checked live: PVE 8 has no /cluster/sdn/lock ("no such
// resource"), and answers a request for it "Method 'POST /cluster/sdn/lock' not
// implemented" with HTTP 501. The product took any refusal that mentioned
// "lock" for a lock held elsewhere and waited out its whole lock timeout, then
// failed: an ephemeral sandbox could not be made on PVE 8. These tests run it
// against sdntest's PVE 8 mode, whose writes and applies refuse a lock-token or
// release-lock parameter as PVE 8's schema does.

var h1Net = config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24"}

// pve8 is a manager against a PVE 8 fake that answers the lock path with
// status (501 when 0). Its lock waits are short and bounded, so that a manager
// that retries the missing lock fails its test instead of idling through it.
func pve8(t *testing.T, status int) (*Manager, *sdntest.PVE, *journalOf) {
	t.Helper()
	shortLockWaits(t)
	fake := sdntest.New()
	fake.NoLockAPI, fake.NoLockStatus = true, status
	m := NewManager(fake.Serve(t))
	m.SetLockWait(300 * time.Millisecond)
	m.SetOwnObjects([]string{h1Net.ZoneID}, []string{h1Net.VNetID})
	m.SetOwnerMarker(OwnerMarker("run-h1"))
	journal := &journalOf{}
	m.SetPersist(journal.persist)
	return m, fake, journal
}

// lockCalls are the fake's requests for the SDN lock, whatever their method.
func lockCalls(fake *sdntest.PVE) (calls []string) {
	fake.Do(func(p *sdntest.PVE) {
		for _, r := range p.Requests {
			if _, path, _ := strings.Cut(r, " "); strings.HasPrefix(path, "cluster/sdn/lock") {
				calls = append(calls, r)
			}
		}
	})
	return calls
}

// requestsWith are the requests whose text carries s.
func requestsWith(fake *sdntest.PVE, s string) (found []string) {
	fake.Do(func(p *sdntest.PVE) {
		for _, r := range p.Requests {
			if strings.Contains(r, s) {
				found = append(found, r)
			}
		}
	})
	return found
}

func sandboxCreated(t *testing.T, m *Manager) {
	t.Helper()
	ctx := context.Background()
	if err := m.CreateZone(ctx, h1Net, "node1"); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	if err := m.CreateVNet(ctx, h1Net); err != nil {
		t.Fatalf("CreateVNet: %v", err)
	}
	if err := m.CreateSubnet(ctx, h1Net); err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
}

// On a PVE without an SDN lock the sandbox is created, applied, deleted and
// applied again with no lock at all: PVE is asked for one exactly once, nothing
// waits, and no request carries a lock parameter (the fake refuses one).
func TestNoLockAPICreateApplyAndCleanupWithoutALock(t *testing.T) {
	for _, status := range []int{http.StatusNotImplemented, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			m, fake, journal := pve8(t, status)
			ctx := context.Background()
			started := time.Now()

			if err := m.Lock(ctx); err != nil {
				t.Fatalf("Lock on a PVE without the SDN lock = %v; want it to carry on without one", err)
			}
			if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
				t.Fatalf("Lock took %v: the missing lock was waited for", elapsed)
			}
			if !m.NoLockAPI() || m.LockToken() != "" || m.LockRequestUnresolved() {
				t.Fatalf("NoLockAPI %v, token %q, unresolved %v", m.NoLockAPI(), m.LockToken(), m.LockRequestUnresolved())
			}
			sandboxCreated(t, m)
			if err := m.Reload(ctx); err != nil {
				t.Fatalf("Reload: %v", err)
			}
			// Teardown: the lock is asked for again, as the orchestrator does,
			// and is not an error.
			if err := m.EnsureLock(ctx); err != nil {
				t.Fatalf("EnsureLock: %v", err)
			}
			if err := m.DestroyVNet(ctx, h1Net.VNetID); err != nil {
				t.Fatalf("DestroyVNet: %v", err)
			}
			if err := m.DestroyZone(ctx, h1Net.ZoneID); err != nil {
				t.Fatalf("DestroyZone: %v", err)
			}
			if err := m.Reload(ctx); err != nil {
				t.Fatalf("Reload after the deletions: %v", err)
			}
			if err := m.Unlock(ctx); err != nil {
				t.Fatalf("Unlock = %v; there is nothing to release", err)
			}

			if calls := lockCalls(fake); len(calls) != 1 || calls[0] != "POST cluster/sdn/lock" {
				t.Fatalf("lock calls %v; want the one probe", calls)
			}
			if found := requestsWith(fake, "lock-token"); len(found) != 0 {
				t.Fatalf("requests with a lock token: %v", found)
			}
			if found := requestsWith(fake, "release-lock"); len(found) != 0 {
				t.Fatalf("requests with release-lock: %v", found)
			}
			want := strings.Join([]string{
				"POST cluster/sdn/lock",
				`POST cluster/sdn/zones {"ipam":"pve","nodes":"node1","type":"simple","zone":"csSb01"}`,
				`POST cluster/sdn/vnets {"alias":"certistack run-h1","vnet":"csVn01","zone":"csSb01"}`,
				`POST cluster/sdn/vnets/csVn01/subnets {"subnet":"10.100.0.0/24","type":"subnet"}`,
				"PUT cluster/sdn",
				"DELETE cluster/sdn/vnets/csVn01/subnets/csSb01-10.100.0.0-24",
				"DELETE cluster/sdn/vnets/csVn01",
				"DELETE cluster/sdn/zones/csSb01",
				"PUT cluster/sdn",
			}, "\n")
			if got := strings.Join(fake.Writes(), "\n"); got != want {
				t.Fatalf("writes:\n%s\nwant:\n%s", got, want)
			}
			if fake.Applies != 2 || fake.Pending() || len(fake.Zones)+len(fake.VNets)+len(fake.RunningZones)+len(fake.RunningVNets) != 0 {
				t.Fatalf("applies %d, pending %v, zones %v, vnets %v: want the sandbox applied and removed", fake.Applies, fake.Pending(), fake.Zones, fake.VNets)
			}
			// The journal said the request was made before it was sent, and said
			// no lock was requested or held from PVE's answer on.
			if len(journal.states) < 2 || !journal.states[0].Requested {
				t.Fatalf("journal %+v; want the request journaled before it was sent", journal.states)
			}
			for i, state := range journal.states[1:] {
				if state.Token != "" || state.Requested {
					t.Fatalf("journal entry %d claims a lock that was never granted: %+v", i+1, state)
				}
			}
		})
	}
}

// PVE is asked for the lock once per manager, however often the lock is
// taken again.
func TestNoLockAPIIsProbedOnce(t *testing.T) {
	m, fake, _ := pve8(t, 0)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := m.Lock(ctx); err != nil {
			t.Fatal(err)
		}
		if err := m.EnsureLock(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if calls := lockCalls(fake); len(calls) != 1 {
		t.Fatalf("lock calls %v; want one", calls)
	}
}

// The missing lock is not waited for: with the default waits (2 s between
// tries, 2 minutes in all) the answer comes at once.
func TestNoLockAPIIsNotWaitedFor(t *testing.T) {
	fake := sdntest.New()
	fake.NoLockAPI = true
	m := NewManager(fake.Serve(t))
	m.SetLockWait(3 * time.Second) // a manager that retries gives up after its first 2 s sleep
	started := time.Now()
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Lock took %v on a PVE without a lock", elapsed)
	}
	if calls := lockCalls(fake); len(calls) != 1 {
		t.Fatalf("lock calls %v; want one", calls)
	}
}

// Only the answer to the lock request itself says the lock does not exist.
// A 501 or 404 anywhere else is an error, on a PVE 9 or a PVE 8, and
// does not make the manager drop its lock.
func TestMissingEndpointElsewhereIsStillAnError(t *testing.T) {
	for _, status := range []int{http.StatusNotImplemented, http.StatusNotFound} {
		t.Run(http.StatusText(status)+" on a zone, with a lock", func(t *testing.T) {
			fake := sdntest.New()
			fake.Fault("POST cluster/sdn/zones", sdntest.Fault{Refuse: "Method 'POST /cluster/sdn/zones' not implemented", Status: status})
			m := NewManager(fake.Serve(t))
			ctx := context.Background()
			if err := m.Lock(ctx); err != nil {
				t.Fatal(err)
			}
			if err := m.CreateZone(ctx, h1Net, "node1"); err == nil {
				t.Fatal("a missing zones endpoint was not an error")
			}
			if m.NoLockAPI() || m.LockToken() != "tok-1" {
				t.Fatalf("NoLockAPI %v, token %q; the lock was dropped over another path's answer", m.NoLockAPI(), m.LockToken())
			}
			if err := m.CreateZone(ctx, h1Net, "node1"); err != nil {
				t.Fatal(err)
			}
			if found := requestsWith(fake, `"lock-token":"tok-1"`); len(found) != 2 {
				t.Fatalf("writes with the token: %v; want the failed and the repeated zone", found)
			}
		})
		t.Run(http.StatusText(status)+" on a zone, on a PVE 8", func(t *testing.T) {
			m, fake, _ := pve8(t, 0)
			fake.Fault("POST cluster/sdn/zones", sdntest.Fault{Refuse: "Method 'POST /cluster/sdn/zones' not implemented", Status: status})
			ctx := context.Background()
			if err := m.Lock(ctx); err != nil {
				t.Fatal(err)
			}
			if err := m.CreateZone(ctx, h1Net, "node1"); err == nil {
				t.Fatal("a missing zones endpoint was not an error")
			}
		})
		t.Run(http.StatusText(status)+" on a read", func(t *testing.T) {
			fake := sdntest.New()
			fake.Fault("GET cluster/sdn/zones", sdntest.Fault{Refuse: "Method 'GET /cluster/sdn/zones' not implemented", Status: status})
			m := NewManager(fake.Serve(t))
			if err := m.EnsureSandboxAvailable(context.Background(), h1Net); err == nil {
				t.Fatal("a missing zones list was not an error")
			}
			if m.NoLockAPI() {
				t.Fatal("a read's 404 or 501 made the manager give up its lock")
			}
		})
		t.Run(http.StatusText(status)+" on the release of a held lock", func(t *testing.T) {
			// The release is not the lock request: a lock PVE granted is not
			// let go of on its word, and stays journaled for a later release.
			fake := sdntest.New()
			fake.Fault("DELETE cluster/sdn/lock", sdntest.Fault{Refuse: "Method 'DELETE /cluster/sdn/lock' not implemented", Status: status})
			m := NewManager(fake.Serve(t))
			if err := m.Lock(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := m.Unlock(context.Background()); err == nil || m.LockToken() != "tok-1" || m.NoLockAPI() {
				t.Fatalf("Unlock = %v, token %q, NoLockAPI %v; want the failure and the token kept", err, m.LockToken(), m.NoLockAPI())
			}
		})
	}
	t.Run("another refusal of the lock request", func(t *testing.T) {
		// 403, 500 and 400 are not a missing endpoint.
		for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError, http.StatusBadRequest} {
			fake := sdntest.New()
			fake.Fault("POST cluster/sdn/lock", sdntest.Fault{Refuse: "Permission check failed (/sdn, SDN.Allocate)", Status: status})
			m := NewManager(fake.Serve(t))
			if err := m.Lock(context.Background()); err == nil || m.NoLockAPI() {
				t.Fatalf("status %d: Lock = %v, NoLockAPI %v; want an error and a manager that still needs the lock", status, err, m.NoLockAPI())
			}
		}
	})
}

// PVE offers no refusal over an administrator's unapplied change there, so
// the manager reads the pending changes itself: it creates nothing over one,
// and applies nothing over one that appears later.
func TestNoLockAPIRefusesToApplyAdministratorsPendingChanges(t *testing.T) {
	t.Run("pending before the run", func(t *testing.T) {
		m, fake, journal := pve8(t, 0)
		fake.Zones["prodZ"] = true
		err := m.Lock(context.Background())
		if !errors.Is(err, ErrPendingSDNChanges) || !strings.Contains(err.Error(), "zone prodZ (new)") {
			t.Fatalf("Lock = %v; want the refusal over the pending change, naming it", err)
		}
		// The change is someone else's: the message sends the reader to them, and
		// does not tell them to apply it.
		if !strings.Contains(err.Error(), PendingChangesAdvice) || strings.Contains(err.Error(), "Apply or discard them") {
			t.Fatalf("Lock = %v; want the advice to ask whoever changed SDN", err)
		}
		if got := strings.Join(fake.Writes(), "\n"); got != "POST cluster/sdn/lock" {
			t.Fatalf("writes:\n%s", got)
		}
		if journal.last().Requested || journal.last().Token != "" {
			t.Fatalf("journal %+v", journal.last())
		}
	})
	t.Run("pending before an apply", func(t *testing.T) {
		m, fake, _ := pve8(t, 0)
		ctx := context.Background()
		if err := m.Lock(ctx); err != nil {
			t.Fatal(err)
		}
		sandboxCreated(t, m)
		fake.Do(func(p *sdntest.PVE) { p.Zones["prodZ"] = true }) // an administrator's change
		err := m.Reload(ctx)
		if !errors.Is(err, ErrPendingSDNChanges) || !strings.Contains(err.Error(), "zone prodZ (new)") {
			t.Fatalf("Reload = %v; want the foreign change refused", err)
		}
		if fake.Applies != 0 || strings.Contains(strings.Join(fake.Writes(), "\n"), "PUT") {
			t.Fatalf("applies %d, writes %v: the administrator's change was applied", fake.Applies, fake.Writes())
		}
	})
	t.Run("pending before a deletion pass", func(t *testing.T) {
		m, fake, _ := pve8(t, 0)
		ctx := context.Background()
		if err := m.Lock(ctx); err != nil {
			t.Fatal(err)
		}
		sandboxCreated(t, m)
		if err := m.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		fake.Do(func(p *sdntest.PVE) { p.Zones["prodZ"] = true })
		if err := m.EnsureLock(ctx); !errors.Is(err, ErrPendingSDNChanges) {
			t.Fatalf("EnsureLock = %v; want the teardown refused over the foreign change", err)
		}
	})
	t.Run("the run's own changes are not foreign", func(t *testing.T) {
		m, _, _ := pve8(t, 0)
		ctx := context.Background()
		if err := m.Lock(ctx); err != nil {
			t.Fatal(err)
		}
		sandboxCreated(t, m)
		if err := m.EnsureLock(ctx); err != nil {
			t.Fatalf("EnsureLock over the run's own creations = %v", err)
		}
	})
	t.Run("a pending list that cannot be read applies nothing", func(t *testing.T) {
		m, fake, _ := pve8(t, 0)
		ctx := context.Background()
		if err := m.Lock(ctx); err != nil {
			t.Fatal(err)
		}
		sandboxCreated(t, m)
		fake.Fault("GET cluster/sdn/controllers", sdntest.Fault{Refuse: "boom"})
		if err := m.Reload(ctx); err == nil || fake.Applies != 0 {
			t.Fatalf("Reload = %v, applies %d; want nothing applied over a pending list nobody could read", err, fake.Applies)
		}
	})
}

// The journal must not claim a lock that was never granted, and recovery
// must not look for one: a request journaled before the probe, a token adopted
// from a journal and a lost request's mark are all settled by PVE's answer.
func TestNoLockAPISettlesWhatTheJournalClaimed(t *testing.T) {
	m, fake, journal := pve8(t, 0)
	m.AdoptLock("tok-dead")
	m.AdoptLockRequest()
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if last := journal.last(); last.Token != "" || last.Requested || m.LockToken() != "" || m.LockRequestUnresolved() {
		t.Fatalf("journal %+v, token %q, unresolved %v", last, m.LockToken(), m.LockRequestUnresolved())
	}
	// Nothing adopted afterwards is believed either.
	m.AdoptLock("tok-late")
	m.AdoptLockRequest()
	if m.LockToken() != "" || m.LockRequestUnresolved() {
		t.Fatalf("token %q, unresolved %v after an adoption on a PVE without a lock", m.LockToken(), m.LockRequestUnresolved())
	}
	sandboxCreated(t, m)
	if err := m.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if found := requestsWith(fake, "tok-"); len(found) != 0 {
		t.Fatalf("a token reached PVE: %v", found)
	}
}

// A journal that cannot be written when PVE says it has no lock leaves the
// request journaled, which only asks recovery to look; the run still goes on.
func TestNoLockAPIWithAJournalThatFails(t *testing.T) {
	fake := sdntest.New()
	fake.NoLockAPI = true
	m := NewManager(fake.Serve(t))
	writes := 0
	m.SetPersist(func(LockState) error {
		writes++
		if writes > 1 {
			return errors.New("disk full")
		}
		return nil
	})
	if err := m.Lock(context.Background()); err != nil {
		t.Fatalf("Lock = %v; the journal's failure to take the request back changes nothing", err)
	}
	if !m.NoLockAPI() {
		t.Fatal("PVE's answer was not taken")
	}
}

// Releasing nothing is not an error, and a manager that never asked PVE for
// a lock still refuses to apply (the callers take the lock first).
func TestNoLockAPIUnlockAndFreshReload(t *testing.T) {
	m, fake, _ := pve8(t, 0)
	if err := m.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "holds none") || len(fake.Requests) != 0 {
		t.Fatalf("Reload before any lock request = %v with requests %v", err, fake.Requests)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(lockCalls(fake))
	for i := 0; i < 2; i++ {
		if err := m.Unlock(context.Background()); err != nil {
			t.Fatalf("Unlock = %v", err)
		}
	}
	if len(lockCalls(fake)) != before {
		t.Fatalf("lock calls %v after Unlock", lockCalls(fake))
	}
}

// PVE 8 does not serialize clients. Two managers (two controllers on two
// nodes of one cluster) both go on, with no lock to hold the second off; the
// only protection is what each reads of the other's unapplied objects, and a
// second run's objects pending when the first applies are the window the docs
// state. This test pins what the product does and does not do, so that nobody
// takes it for a lock.
func TestNoLockAPIDoesNotHoldASecondClientOff(t *testing.T) {
	fake := sdntest.New()
	fake.NoLockAPI = true
	a := NewManager(fake.Serve(t))
	b := NewManager(fake.Serve(t))
	a.SetOwnObjects([]string{"csZoneA"}, []string{"csVnetA"})
	b.SetOwnObjects([]string{"csZoneB"}, []string{"csVnetB"})
	ctx := context.Background()
	if err := a.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Lock(ctx); err != nil {
		t.Fatalf("the second client was held off by a lock PVE 8 does not have: %v", err)
	}
	if err := a.CreateZone(ctx, config.Network{Mode: "simple", ZoneID: "csZoneA"}, "node1"); err != nil {
		t.Fatal(err)
	}
	// B reads A's unapplied zone before it applies: it is not B's, so B applies
	// nothing, as it would not apply an administrator's.
	if err := b.EnsureLock(ctx); !errors.Is(err, ErrPendingSDNChanges) || !strings.Contains(err.Error(), "zone csZoneA (new)") {
		t.Fatalf("EnsureLock = %v; want the other run's pending zone read as foreign", err)
	}
	if err := b.Reload(ctx); err == nil || fake.Applies != 0 {
		t.Fatalf("Reload = %v, applies %d; want B's apply refused over A's pending zone", err, fake.Applies)
	}
}

// On a PVE without an SDN lock the manager's own read of the pending changes
// stands in for the lock's refusal. An answer that carries no list, or an
// entry that cannot be read in full, is not "nothing pending": the apply it
// would allow commits an administrator's unapplied changes on every node.
func TestNoLockAPIAppliesNothingOverAPendingReadThatIsNotComplete(t *testing.T) {
	for _, tc := range []struct {
		name, key, answer string
		wantApply         bool
	}{
		{"zones: data is null", "GET cluster/sdn/zones", `null`, false},
		{"zones: data is not a list", "GET cluster/sdn/zones", `"<html>Bad Gateway</html>"`, false},
		{"zones: an entry's state is not a string", "GET cluster/sdn/zones", `[{"zone":"prodZ","state":5}]`, false},
		{"zones: an entry names no zone", "GET cluster/sdn/zones", `[{"state":"new"}]`, false},
		{"VNets: data is null", "GET cluster/sdn/vnets", `null`, false},
		{"VNets: an entry names no VNet", "GET cluster/sdn/vnets", `[{"zone":"prodZ","state":"new"}]`, false},
		{"controllers: data is null", "GET cluster/sdn/controllers", `null`, false},
		{"subnets: data is null", "GET cluster/sdn/vnets/csVn01/subnets", `null`, false},
		{"subnets: an entry names no subnet", "GET cluster/sdn/vnets/csVn01/subnets", `[{"state":"new"}]`, false},
		{"subnets: an entry's state is malformed", "GET cluster/sdn/vnets/csVn01/subnets", `[{"subnet":"10.9.0.0/24","state":["new"]}]`, false},
		// What PVE really answers stays a pass: nothing listed, and unchanged entries (no state).
		{"zones: a genuine empty list", "GET cluster/sdn/zones", `[]`, true},
		{"zones: an unchanged entry carries no state", "GET cluster/sdn/zones", `[{"zone":"prodZ"}]`, true},
		{"zones: an unchanged entry's state is null", "GET cluster/sdn/zones", `[{"zone":"prodZ","state":null}]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fake, _ := pve8(t, 0)
			ctx := context.Background()
			if err := m.Lock(ctx); err != nil {
				t.Fatal(err)
			}
			sandboxCreated(t, m)
			fake.Fault(tc.key, sdntest.Fault{Answer: tc.answer})
			err := m.Reload(ctx)
			if tc.wantApply && (err != nil || fake.Applies != 1) {
				t.Fatalf("Reload = %v with %d applies; want the apply (a complete read with nothing foreign pending)", err, fake.Applies)
			}
			if !tc.wantApply && (err == nil || fake.Applies != 0) {
				t.Fatalf("Reload = %v with %d applies; want nothing applied over a read that is not complete", err, fake.Applies)
			}
		})
	}
}
