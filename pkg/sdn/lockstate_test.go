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

	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// holding makes m hold a lock it took itself, with token tok.
func holding(m *Manager, tok string) *Manager {
	m.lockToken, m.lockHeld = tok, true
	return m
}

// journalOf records every lock state the manager journals.
type journalOf struct{ states []LockState }

func (j *journalOf) persist(state LockState) error {
	j.states = append(j.states, state)
	return nil
}

func (j *journalOf) last() LockState {
	if len(j.states) == 0 {
		return LockState{}
	}
	return j.states[len(j.states)-1]
}

// An apply commits everything pending on every node, so a manager that holds no
// lock applies nothing.
func TestReloadWithoutALockAppliesNothing(t *testing.T) {
	fake := sdntest.New()
	fake.Zones["prodZ"] = true // an administrator's pending change
	m := NewManager(fake.Serve(t))
	if err := m.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "holds none") {
		t.Fatalf("Reload without a lock = %v, want a refusal", err)
	}
	if len(fake.Requests) != 0 || fake.Applies != 0 {
		t.Fatalf("requests %v, applies %d; want none", fake.Requests, fake.Applies)
	}
}

// A token adopted from a journal, or spent by an apply whose answer
// was lost, is stale once no lock stands, and PVE takes any token while
// none stands: the manager applies with it only while a lock stands.
func TestReloadWithATokenThatMayBeStaleAppliesOnlyWhileALockStands(t *testing.T) {
	t.Run("the token's lock stands", func(t *testing.T) {
		fake := sdntest.New()
		fake.Lock = "tok-dead"
		fake.RunningZones["csSb01"] = true // the run's unapplied deletion
		m := NewManager(fake.Serve(t))
		m.SetOwnObjects([]string{"csSb01"}, nil)
		m.AdoptLock("tok-dead")
		if err := m.Reload(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(fake.Writes(), "\n"); got != "POST cluster/sdn/lock\nPUT cluster/sdn {\"lock-token\":\"tok-dead\",\"release-lock\":1}" {
			t.Fatalf("writes:\n%s", got)
		}
		if fake.Applies != 1 || fake.Lock != "" || m.LockToken() != "" {
			t.Fatalf("applies %d, lock %q, token %q", fake.Applies, fake.Lock, m.LockToken())
		}
	})
	t.Run("no lock stands, and an administrator's change is pending", func(t *testing.T) {
		fake := sdntest.New()
		fake.Zones["prodZ"] = true
		m := NewManager(fake.Serve(t))
		m.AdoptLock("tok-dead")
		err := m.Reload(context.Background())
		if !errors.Is(err, ErrPendingSDNChanges) || fake.Applies != 0 || m.LockToken() != "" {
			t.Fatalf("Reload = %v, applies %d, token %q; want nothing applied and the stale token dropped", err, fake.Applies, m.LockToken())
		}
		if !fake.Pending() {
			t.Fatal("the administrator's change was committed")
		}
	})
	t.Run("no lock stands, and nothing is pending", func(t *testing.T) {
		fake := sdntest.New()
		m := NewManager(fake.Serve(t))
		m.AdoptLock("tok-dead")
		err := m.Reload(context.Background())
		if !errors.Is(err, ErrSDNLockLost) || fake.Applies != 0 || fake.Lock != "" || m.LockToken() != "" {
			t.Fatalf("Reload = %v, applies %d, lock %q, token %q; want nothing applied, the probe's lock released", err, fake.Applies, fake.Lock, m.LockToken())
		}
	})
	t.Run("another client's lock stands over its pending change", func(t *testing.T) {
		fake := sdntest.New()
		fake.Lock = "tok-theirs"
		fake.Zones["prodZ"] = true
		m := NewManager(fake.Serve(t))
		m.AdoptLock("tok-dead")
		err := m.Reload(context.Background())
		if !errors.Is(err, ErrPendingSDNChanges) || fake.Applies != 0 || fake.Lock != "tok-theirs" {
			t.Fatalf("Reload = %v, applies %d, lock %q; want the foreign change refused before any PUT", err, fake.Applies, fake.Lock)
		}
	})
	t.Run("another client's lock stands, with nothing pending", func(t *testing.T) {
		fake := sdntest.New()
		fake.Lock = "tok-theirs"
		m := NewManager(fake.Serve(t))
		m.AdoptLock("tok-dead")
		err := m.Reload(context.Background())
		if err == nil || fake.Applies != 0 || fake.Lock != "tok-theirs" || m.LockToken() != "" {
			t.Fatalf("Reload = %v, applies %d, lock %q, token %q; want PVE's refusal and the token dropped", err, fake.Applies, fake.Lock, m.LockToken())
		}
	})
}

// The lock request is journaled before it is sent. When no answer
// comes, whatever the way, PVE may hold the lock for it: the journal keeps
// saying so, and only a later answer of PVE's settles it.
func TestLockRequestWhoseAnswerIsLostStaysUnresolved(t *testing.T) {
	for name, fault := range map[string]sdntest.Fault{
		"connection closed after the lock was made": {Lose: true},
		"truncated reply":                  {Truncate: true},
		"reply after the client's timeout": {Delay: 300 * time.Millisecond},
		"caller canceled":                  {Delay: 300 * time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			fake := sdntest.New()
			fake.Fault("POST cluster/sdn/lock", fault)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timeout := time.Minute
			switch name {
			case "reply after the client's timeout":
				timeout = 100 * time.Millisecond
			case "caller canceled":
				fake.OnRequest = func(string, string, map[string]string) {
					go func() { time.Sleep(100 * time.Millisecond); cancel() }()
				}
			}
			journal := &journalOf{}
			m := NewManager(pve.NewClient(pve.Config{BaseURL: fake.Start(t).URL, Timeout: timeout}))
			m.SetPersist(journal.persist)
			err := m.Lock(ctx)
			if !errors.Is(err, ErrSDNLockUnknown) {
				t.Fatalf("Lock = %v, want the outcome unknown", err)
			}
			if len(journal.states) == 0 || !journal.states[0].Requested || !journal.last().Requested || journal.last().Token != "" {
				t.Fatalf("journaled %+v; want the request before it was sent, and still unresolved", journal.states)
			}
			// The manager itself knows the request is unresolved, not only the
			// journal it wrote: a later note keeps saying so (the journal's
			// Requested flag comes from it), and a caller asks it.
			if !m.LockRequestUnresolved() {
				t.Fatal("the manager that lost a lock request's answer does not report it unresolved")
			}
			if err := m.note(false); err != nil || !journal.last().Requested {
				t.Fatalf("note after the lost answer = %v, journal %+v; want the request still journaled", err, journal.last())
			}
			time.Sleep(350 * time.Millisecond) // the fake's delayed reply
			var held string
			fake.Do(func(p *sdntest.PVE) { held = p.Lock })
			if held == "" {
				t.Fatal("the fixture made no lock")
			}

			// Recovery: the lock stands, so it may be the lost request's.
			shortLockWaits(t)
			next := NewManager(fake.Serve(t))
			next.AdoptLockRequest()
			after := &journalOf{}
			next.SetPersist(after.persist)
			if err := next.Lock(context.Background()); !errors.Is(err, ErrSDNLockHeld) || !next.LockRequestUnresolved() || !after.last().Requested {
				t.Fatalf("recovery's Lock = %v, unresolved %v, journal %+v", err, next.LockRequestUnresolved(), after.last())
			}
			// An operator releases it by force: PVE's next answer settles it.
			fake.Do(func(p *sdntest.PVE) { p.Lock = "" })
			if err := next.Lock(context.Background()); err != nil || next.LockRequestUnresolved() || after.last().Requested || after.last().Token == "" {
				t.Fatalf("Lock after the release = %v, unresolved %v, journal %+v", err, next.LockRequestUnresolved(), after.last())
			}
		})
	}
}

// Controls: a refusal is PVE's own answer, and settles the request.
func TestLockRefusalSettlesTheRequest(t *testing.T) {
	fake := sdntest.New()
	fake.Zones["prodZ"] = true
	journal := &journalOf{}
	m := NewManager(fake.Serve(t))
	m.AdoptLockRequest() // an earlier request's answer was lost
	m.SetPersist(journal.persist)
	if err := m.Lock(context.Background()); !errors.Is(err, ErrPendingSDNChanges) {
		t.Fatalf("Lock = %v", err)
	}
	// Refused over pending changes: no lock stands, the lost one's neither.
	if m.LockRequestUnresolved() || journal.last().Requested {
		t.Fatalf("unresolved %v, journal %+v; a refusal over pending changes proves no lock stands", m.LockRequestUnresolved(), journal.last())
	}
}

// A token is journaled before it is used; one that cannot be is
// released at once, and a request that cannot be journaled is not sent.
func TestLockTokenThatCannotBeJournaledIsNeverUsed(t *testing.T) {
	fake := sdntest.New()
	m := NewManager(fake.Serve(t))
	m.SetPersist(func(state LockState) error {
		if state.Token != "" {
			return errors.New("disk full")
		}
		return nil
	})
	if err := m.Lock(context.Background()); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("Lock = %v, want the journal failure", err)
	}
	if got := strings.Join(fake.Writes(), "\n"); got != "POST cluster/sdn/lock\nDELETE cluster/sdn/lock?lock-token=tok-1" || fake.Lock != "" || m.LockToken() != "" {
		t.Fatalf("writes:\n%s\nlock %q, token %q; want the token released at once", got, fake.Lock, m.LockToken())
	}

	fake = sdntest.New()
	m = NewManager(fake.Serve(t))
	m.SetPersist(func(LockState) error { return errors.New("disk full") })
	if err := m.Lock(context.Background()); err == nil || len(fake.Requests) != 0 {
		t.Fatalf("Lock = %v with requests %v; want no request unjournaled", err, fake.Requests)
	}
}

// Only a release PVE confirms, or PVE's word that another lock
// stands, ends the manager's hold; any other failure keeps the token.
func TestUnlockKeepsTheTokenUnlessTheReleaseIsEstablished(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fault     sdntest.Fault
		lock      string
		wantErr   bool
		wantToken string
	}{
		{"released", sdntest.Fault{}, "tok-1", false, ""},
		{"backend failure", sdntest.Fault{Refuse: "could not release lock: cfs-lock 'domain-sdn' error: got lock request timeout"}, "tok-1", true, "tok-1"},
		{"authorization failure", sdntest.Fault{Refuse: "Permission check failed (/sdn, SDN.Allocate)", Status: http.StatusForbidden}, "tok-1", true, "tok-1"},
		{"lost reply", sdntest.Fault{Lose: true}, "tok-1", true, "tok-1"},
		{"gateway error", sdntest.Fault{Refuse: "Bad Gateway", Status: http.StatusBadGateway}, "tok-1", true, "tok-1"},
		{"redirected release", sdntest.Fault{Refuse: "Temporary Redirect", Status: http.StatusTemporaryRedirect}, "tok-1", true, "tok-1"},
		{"another client's lock", sdntest.Fault{}, "tok-theirs", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := sdntest.New()
			fake.Lock = tc.lock
			fake.Fault("DELETE cluster/sdn/lock", tc.fault)
			journal := &journalOf{}
			m := holding(NewManager(fake.Serve(t)), "tok-1")
			m.SetPersist(journal.persist)
			err := m.Unlock(context.Background())
			if (err != nil) != tc.wantErr || m.LockToken() != tc.wantToken {
				t.Fatalf("Unlock = %v, token %q; want error %v, token %q", err, m.LockToken(), tc.wantErr, tc.wantToken)
			}
			if !tc.wantErr && journal.last().Token != "" {
				t.Fatalf("journal %+v after the release", journal.last())
			}
		})
	}
}

// An apply whose task has not ended, or cannot be read, stops the
// next; a task that ended in failure has ended.
func TestReloadAppliesNothingWhileThePreviousApplyMayRun(t *testing.T) {
	wait := reloadTaskWait
	reloadTaskWait = 50 * time.Millisecond
	t.Cleanup(func() { reloadTaskWait = wait })
	for _, tc := range []struct {
		name       string
		status     pve.TaskStatus
		unreadable bool
		wantApply  bool
	}{
		{"still running", pve.TaskStatus{Status: "running"}, false, false},
		{"state unreadable", pve.TaskStatus{}, true, false},
		{"ended in failure", pve.TaskStatus{Status: "stopped", ExitStatus: "command 'pvesh set /nodes/pve3/network' failed"}, false, true},
		{"ended", pve.TaskStatus{Status: "stopped", ExitStatus: "OK"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := sdntest.New()
			m := NewManager(fake.Serve(t))
			if err := holding(m, "tok-a").Reload(context.Background()); err != nil {
				t.Fatal(err)
			}
			fake.Do(func(p *sdntest.PVE) { p.TaskStatus = tc.status })
			if tc.unreadable {
				for i := 0; i < 8; i++ {
					fake.Fault("GET nodes/node1/tasks/"+m.reloadTask+"/status", sdntest.Fault{Refuse: "unable to read task status"})
				}
			}
			err := holding(m, "tok-b").Reload(context.Background())
			if applied := fake.Applies == 2; applied != tc.wantApply || (err == nil) != tc.wantApply {
				t.Fatalf("second Reload = %v with %d applies; want applied %v", err, fake.Applies, tc.wantApply)
			}
			if !tc.wantApply && m.LockToken() != "tok-b" {
				t.Fatalf("token %q; a refused apply keeps the lock", m.LockToken())
			}
		})
	}
}

// An apply whose task PVE does not identify cannot be waited for by
// name: the next apply looks for a running reloadnetworkall task instead, and
// is refused while one runs.
func TestReloadAfterAnUnidentifiedApplyTaskAppliesNothingWhileOneRuns(t *testing.T) {
	fake := sdntest.New()
	fake.Fault("PUT cluster/sdn", sdntest.Fault{Answer: `"OK"`})
	m := NewManager(fake.Serve(t))
	m.SetApplyWait(time.Millisecond)
	if err := holding(m, "tok-a").Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid task identifier") {
		t.Fatalf("Reload = %v, want the task identifier refused", err)
	}
	fake.Do(func(p *sdntest.PVE) { p.Tasks = []map[string]interface{}{running()} })
	if err := holding(m, "tok-b").Reload(context.Background()); err == nil || fake.Applies != 1 {
		t.Fatalf("second Reload = %v with %d applies; want a refusal while an apply runs", err, fake.Applies)
	}
	fake.Do(func(p *sdntest.PVE) { p.Tasks = nil })
	if err := holding(m, "tok-b").Reload(context.Background()); err != nil || fake.Applies != 2 {
		t.Fatalf("third Reload = %v with %d applies; want the apply once none runs", err, fake.Applies)
	}
}

// EnsureLock keeps a lock it took, takes one when it has none, and keeps
// an adopted token only while a lock stands.
func TestEnsureLock(t *testing.T) {
	fake := sdntest.New()
	m := holding(NewManager(fake.Serve(t)), "tok-own")
	if err := m.EnsureLock(context.Background()); err != nil || len(fake.Requests) != 0 {
		t.Fatalf("EnsureLock with its own lock = %v, requests %v", err, fake.Requests)
	}
	m = NewManager(fake.Serve(t))
	m.AdoptLock("tok-stale")
	if err := m.EnsureLock(context.Background()); err != nil || m.LockToken() != "tok-1" || !m.lockHeld {
		t.Fatalf("EnsureLock with a stale token = %v, token %q; want a new lock", err, m.LockToken())
	}
	m = NewManager(fake.Serve(t))
	m.AdoptLock("tok-1")
	if err := m.EnsureLock(context.Background()); err != nil || m.LockToken() != "tok-1" || m.lockHeld {
		t.Fatalf("EnsureLock with the standing lock's token = %v, token %q, held %v", err, m.LockToken(), m.lockHeld)
	}
}

// Where each object stands, from PVE's pending view.
func TestObjectStates(t *testing.T) {
	fake := sdntest.New().Applied("zApplied", "vApplied", "s1")
	fake.Zones["zNew"] = true
	fake.RunningZones["zDeleted"] = true
	m := NewManager(fake.Serve(t))
	zones, vnets, err := m.ObjectStates(context.Background(), []string{"zApplied", "zNew", "zDeleted", "zAbsent"}, []string{"vApplied"})
	if err != nil {
		t.Fatal(err)
	}
	if zones["zApplied"] != Applied || zones["zNew"] != New || zones["zDeleted"] != Deleted || zones["zAbsent"] != Absent || vnets["vApplied"] != Applied {
		t.Fatalf("zones %v, vnets %v", zones, vnets)
	}
	// An answer that is not a list is not an empty cluster.
	fake.Fault("GET cluster/sdn/zones", sdntest.Fault{Answer: `null`})
	if _, _, err := m.ObjectStates(context.Background(), []string{"zApplied"}, nil); err == nil {
		t.Fatal("a null list read as absent objects")
	}
}
