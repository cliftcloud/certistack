// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// A token adopted from a journal that a PVE with an SDN lock wrote, released
// against a PVE without one. The release is answered 501 (or 404); only PVE's
// answer to a request for the lock says whether the lock API exists, so the
// manager asks once, and drops the token on a PVE that has none.

func adoptedManager(t *testing.T, fake *sdntest.PVE, token string) (*Manager, *journalOf) {
	t.Helper()
	shortLockWaits(t)
	m := NewManager(fake.Serve(t))
	journal := &journalOf{}
	m.SetPersist(journal.persist)
	m.AdoptLock(token)
	return m, journal
}

func TestReleaseAdoptedTokenOnAPVEWithoutALockDropsIt(t *testing.T) {
	for _, status := range []int{http.StatusNotImplemented, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fake := sdntest.New()
			fake.NoLockAPI, fake.NoLockStatus = true, status
			m, journal := adoptedManager(t, fake, "tok-pve9")
			noLockAPI, err := m.ReleaseAdoptedToken(context.Background())
			if err != nil || !noLockAPI || !m.NoLockAPI() || m.LockToken() != "" {
				t.Fatalf("ReleaseAdoptedToken = %v, %v; NoLockAPI %v, token %q", noLockAPI, err, m.NoLockAPI(), m.LockToken())
			}
			if last := journal.last(); last.Token != "" || last.Requested {
				t.Fatalf("journal %+v; want no token and no request", last)
			}
			want := []string{"DELETE cluster/sdn/lock?lock-token=tok-pve9", "POST cluster/sdn/lock"}
			if calls := lockCalls(fake); strings.Join(calls, "\n") != strings.Join(want, "\n") {
				t.Fatalf("lock calls %v, want %v", calls, want)
			}
			// The mode holds: nothing asks again.
			if err := m.Lock(context.Background()); err != nil || len(lockCalls(fake)) != 2 {
				t.Fatalf("Lock = %v after the drop, lock calls %v", err, lockCalls(fake))
			}
		})
	}
}

// PVE 9: a held lock that cannot be released stays an error with the token kept,
// whatever the release was answered.
func TestReleaseAdoptedTokenKeepsAHeldLock(t *testing.T) {
	for _, status := range []int{http.StatusNotImplemented, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fake := sdntest.New()
			fake.Lock = "tok-held"
			fake.Fault("DELETE cluster/sdn/lock", sdntest.Fault{Refuse: "Method 'DELETE /cluster/sdn/lock' not implemented", Status: status})
			m, journal := adoptedManager(t, fake, "tok-held")
			noLockAPI, err := m.ReleaseAdoptedToken(context.Background())
			if err == nil || noLockAPI || m.NoLockAPI() || m.LockToken() != "tok-held" {
				t.Fatalf("ReleaseAdoptedToken = %v, %v; NoLockAPI %v, token %q", noLockAPI, err, m.NoLockAPI(), m.LockToken())
			}
			if !strings.Contains(err.Error(), "release PVE's SDN configuration lock") || !strings.Contains(err.Error(), "invalid lock token") {
				t.Fatalf("error %q lacks the release's failure or the probe's answer", err)
			}
			if last := journal.last(); last.Token != "tok-held" {
				t.Fatalf("journal %+v; want the token kept", last)
			}
			if fake.Lock != "tok-held" {
				t.Fatalf("the held lock was disturbed: %q", fake.Lock)
			}
		})
	}
}

// No lock stands on a PVE 9 whose release was answered as missing: PVE grants
// the request, or refuses it over pending changes, which it does only while none
// stands. Nothing held the token; the probe's own lock is given back.
func TestReleaseAdoptedTokenDropsATokenNoLockStandsFor(t *testing.T) {
	for name, pending := range map[string]bool{"granted": false, "refused over pending changes": true} {
		t.Run(name, func(t *testing.T) {
			fake := sdntest.New()
			if pending {
				fake.Zones["prodZ"] = true
			}
			fake.Fault("DELETE cluster/sdn/lock", sdntest.Fault{Refuse: "Method 'DELETE /cluster/sdn/lock' not implemented", Status: http.StatusNotFound})
			m, journal := adoptedManager(t, fake, "tok-gone")
			noLockAPI, err := m.ReleaseAdoptedToken(context.Background())
			if err != nil || noLockAPI || m.NoLockAPI() || m.LockToken() != "" || !m.UnlockedForeign() {
				t.Fatalf("ReleaseAdoptedToken = %v, %v; NoLockAPI %v, token %q, foreign %v", noLockAPI, err, m.NoLockAPI(), m.LockToken(), m.UnlockedForeign())
			}
			if last := journal.last(); last.Token != "" || last.Requested {
				t.Fatalf("journal %+v", last)
			}
			if fake.Lock != "" {
				t.Fatalf("lock %q left standing", fake.Lock)
			}
		})
	}
}

// A release that fails for any other reason is Unlock's error, with no probe.
func TestReleaseAdoptedTokenLeavesOtherFailuresAlone(t *testing.T) {
	fake := sdntest.New()
	fake.Lock = "tok-held"
	fake.Fault("DELETE cluster/sdn/lock", sdntest.Fault{Refuse: "temporary failure"})
	m, _ := adoptedManager(t, fake, "tok-held")
	if noLockAPI, err := m.ReleaseAdoptedToken(context.Background()); err == nil || noLockAPI || m.LockToken() != "tok-held" {
		t.Fatalf("ReleaseAdoptedToken = %v, %v; token %q", noLockAPI, err, m.LockToken())
	}
	if calls := lockCalls(fake); len(calls) != 1 {
		t.Fatalf("lock calls %v; no probe is sent for an answer that is not a missing endpoint", calls)
	}
}

// And the plain release works as Unlock does.
func TestReleaseAdoptedTokenReleasesAHeldLock(t *testing.T) {
	fake := sdntest.New()
	fake.Lock = "tok-held"
	m, _ := adoptedManager(t, fake, "tok-held")
	if noLockAPI, err := m.ReleaseAdoptedToken(context.Background()); err != nil || noLockAPI || m.LockToken() != "" || fake.Lock != "" {
		t.Fatalf("ReleaseAdoptedToken = %v, %v; token %q, lock %q", noLockAPI, err, m.LockToken(), fake.Lock)
	}
}
