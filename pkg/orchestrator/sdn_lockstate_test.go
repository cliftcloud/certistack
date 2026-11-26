// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// failingBridges is the host fake with the sandbox bridge failing once the
// first apply is made: it never settles, or its forwarding cannot be turned
// off. onFail runs first.
type failingBridges struct {
	fakeHostAddressManager
	failAt string
	onFail func()
}

func (h *failingBridges) SettleBridge(ctx context.Context, bridge string, present bool, timeout time.Duration) error {
	_ = h.fakeHostAddressManager.SettleBridge(ctx, bridge, present, timeout)
	if present && h.failAt == "settle" {
		h.fail()
		return errors.New("the bridge never became ready")
	}
	return nil
}

func (h *failingBridges) DisableForwarding(ctx context.Context, bridge string) error {
	_ = h.fakeHostAddressManager.DisableForwarding(ctx, bridge)
	if h.failAt == "forwarding" {
		h.fail()
		return errors.New("forwarding cannot be turned off")
	}
	return nil
}

func (h *failingBridges) fail() {
	if h.onFail != nil {
		h.onFail()
	}
}

// ownerMarker matches the alias the run gives its VNet: it carries the
// run's ID, so a comparison of the writes sees it as MARKER.
var ownerMarker = regexp.MustCompile(`"alias":"certistack [^"]+"`)

// writesOf are the fake's SDN writes, the owner marker replaced by MARKER.
func writesOf(fake *sdntest.PVE) []string {
	writes := fake.Writes()
	for i, w := range writes {
		writes[i] = ownerMarker.ReplaceAllString(w, `"alias":"MARKER"`)
	}
	return writes
}

// setupWrites are the run's SDN writes up to and including its first apply.
var setupWrites = []string{
	`POST cluster/sdn/lock`,
	`POST cluster/sdn/zones {"ipam":"pve","lock-token":"tok-1","nodes":"localhost","type":"simple","zone":"csSb01"}`,
	`POST cluster/sdn/vnets {"alias":"MARKER","lock-token":"tok-1","vnet":"csVn01","zone":"csSb01"}`,
	`POST cluster/sdn/vnets/csVn01/subnets {"lock-token":"tok-1","subnet":"10.100.0.0/24","type":"subnet"}`,
	`PUT cluster/sdn {"lock-token":"tok-1","release-lock":1}`,
}

// teardownWrites are the deletions and the apply under token tok.
func teardownWrites(tok string) []string {
	return []string{
		`DELETE cluster/sdn/vnets/csVn01/subnets/csSb01-10.100.0.0-24?lock-token=` + tok,
		`DELETE cluster/sdn/vnets/csVn01?lock-token=` + tok,
		`DELETE cluster/sdn/zones/csSb01?lock-token=` + tok,
		`PUT cluster/sdn {"lock-token":"` + tok + `","release-lock":1}`,
	}
}

func sandboxLeft(fake *sdntest.PVE) (left []string) {
	fake.Do(func(p *sdntest.PVE) {
		for _, m := range []map[string]bool{p.Zones, p.RunningZones} {
			if m["csSb01"] {
				left = append(left, "zone")
			}
		}
		for _, m := range []map[string]string{p.VNets, p.RunningVNets} {
			if m["csVn01"] != "" {
				left = append(left, "vnet")
			}
		}
		if p.Lock != "" {
			left = append(left, "lock "+p.Lock)
		}
	})
	return left
}

// The first apply releases the lock. A startup failure after it
// (the bridge never settling, forwarding not turned off) tears down under
// a new lock: deletions and apply carry its token, and nothing an
// administrator has pending is applied.
func TestStartupFailureAfterTheFirstApplyTearsDownUnderANewLock(t *testing.T) {
	for _, failAt := range []string{"settle", "forwarding"} {
		t.Run(failAt, func(t *testing.T) {
			fake := sdntest.New()
			stateDir := t.TempDir()
			orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
			orch.hostAddresses = &failingBridges{failAt: failAt}
			res, err := orch.Run(context.Background())
			if err == nil {
				t.Fatal("the startup failure was not reported")
			}
			want := strings.Join(append(append(append([]string(nil), setupWrites...), "POST cluster/sdn/lock"), teardownWrites("tok-2")...), "\n")
			if got := strings.Join(writesOf(fake), "\n"); got != want {
				t.Fatalf("SDN writes:\n%s\nwant:\n%s", got, want)
			}
			if res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned || !res.TeardownEvidence.SDNClusterReloaded || len(sandboxLeft(fake)) > 0 {
				t.Fatalf("evidence %+v, left %v; want a clean teardown", res.TeardownEvidence, sandboxLeft(fake))
			}
		})
		t.Run(failAt+" with a change pending meanwhile", func(t *testing.T) {
			fake := sdntest.New()
			stateDir := t.TempDir()
			orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
			orch.sdnMgr.SetLockWait(time.Millisecond)
			orch.hostAddresses = &failingBridges{failAt: failAt, onFail: func() {
				fake.Do(func(p *sdntest.PVE) { p.Zones["prodZ"] = true })
			}}
			res, _ := orch.Run(context.Background())
			var applies int
			var committed bool
			fake.Do(func(p *sdntest.PVE) { applies, committed = p.Applies, p.RunningZones["prodZ"] })
			if applies != 1 || committed {
				t.Fatalf("applies %d, administrator's zone committed %v; want no apply after the first", applies, committed)
			}
			// PVE refuses the lock over the administrator's change, so
			// nothing is written to SDN: a deletion made without the lock would
			// mix with the change and be enacted by its apply.
			for _, w := range writesOf(fake)[len(setupWrites):] {
				if !strings.HasPrefix(w, "POST cluster/sdn/lock") {
					t.Fatalf("teardown wrote to SDN over an administrator's pending change: %s", w)
				}
			}
			if left := strings.Join(sandboxLeft(fake), " "); !strings.Contains(left, "zone") || !strings.Contains(left, "vnet") {
				t.Fatalf("SDN left %q; want the zone and VNet still there", left)
			}
			if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned || res.TeardownEvidence.SDNClusterReloaded ||
				!strings.Contains(strings.Join(res.TeardownEvidence.CleanupErrors, "\n"), "left in place") {
				t.Fatalf("evidence %+v; want the objects reported left in place", res.TeardownEvidence)
			}
			record, err := journal.Load(stateDir + "/active.json")
			if err != nil || record.Phase != "cleanup_failed" || record.SDNLockToken != "" || record.SDNLockRequested != "" ||
				len(record.SDNZones) != 1 || len(record.SDNVNets) != 1 || record.SDNOwner == "" {
				t.Fatalf("journal %+v, %v; want the zone, VNet and owner marker kept for recovery", record, err)
			}
		})
	}
}

// The first apply's own failure. Refused by PVE, the lock still
// stands and teardown uses it; answered with a lost reply, the apply may
// have been made, with a task nobody can wait for, so teardown takes a new
// lock, deletes, and leaves the apply to recover rather than start a
// second one over it.
func TestFirstApplyFailureTearsDownUnderALock(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		fake := sdntest.New()
		fake.Fault("PUT cluster/sdn", sdntest.Fault{Refuse: "could not commit SDN config: cfs-lock 'domain-sdn' error: got lock request timeout"})
		orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), fake.Serve(t))
		orch.hostAddresses = &fakeHostAddressManager{}
		res, err := orch.Run(context.Background())
		if err == nil || res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned || len(sandboxLeft(fake)) > 0 {
			t.Fatalf("Run = %v, evidence %+v, left %v", err, res.TeardownEvidence, sandboxLeft(fake))
		}
		for _, write := range fake.Writes() {
			if (strings.HasPrefix(write, "DELETE cluster/sdn/v") || strings.HasPrefix(write, "DELETE cluster/sdn/z") || strings.HasPrefix(write, "PUT")) && !strings.Contains(write, "tok-1") {
				t.Fatalf("a teardown write without the run's lock: %s", write)
			}
		}
	})
	// The first apply may have been made with its reply lost: teardown takes
	// a new lock, deletes under it, and (PVE listing no running apply) applies
	// the deletion, so the run ends clean with the lost apply settled.
	t.Run("reply lost", func(t *testing.T) {
		fake := sdntest.New()
		fake.Fault("PUT cluster/sdn", sdntest.Fault{Lose: true})
		stateDir := t.TempDir()
		orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
		orch.hostAddresses = &fakeHostAddressManager{}
		res, err := orch.Run(context.Background())
		want := strings.Join(append(append(append([]string(nil), setupWrites...), "POST cluster/sdn/lock"), teardownWrites("tok-2")...), "\n")
		if got := strings.Join(writesOf(fake), "\n"); err == nil || got != want {
			t.Fatalf("Run = %v, SDN writes:\n%s\nwant:\n%s", err, got, want)
		}
		if res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned || len(sandboxLeft(fake)) > 0 {
			t.Fatalf("evidence %+v, left %v; want a clean teardown", res.TeardownEvidence, sandboxLeft(fake))
		}
		record, _ := journal.Load(stateDir + "/active.json")
		if record.Phase != "cleaned" || record.SDNLockToken != "" || record.SDNApplyUnknown != "" {
			t.Fatalf("journal %+v; want cleaned with the lost apply settled", record)
		}
	})
}

// A lock request is journaled before it is sent. When PVE takes the
// lock but its answer never arrives (the connection closed, a truncated
// reply, the client's timeout, the caller canceling), the run is not
// clean, and its journal says the lock may be held; PVE's own refusal, or a
// known token, is settled.
func TestLostLockReplyLeavesTheRunUnclean(t *testing.T) {
	for _, scenario := range []string{"closed", "truncated", "timeout", "canceled", "refused", "known token, zone refused"} {
		t.Run(scenario, func(t *testing.T) {
			fake := sdntest.New()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timeout := time.Minute
			switch scenario {
			case "closed":
				fake.Fault("POST cluster/sdn/lock", sdntest.Fault{Lose: true})
			case "truncated":
				fake.Fault("POST cluster/sdn/lock", sdntest.Fault{Truncate: true})
			case "timeout":
				timeout = 100 * time.Millisecond
				fake.Fault("POST cluster/sdn/lock", sdntest.Fault{Delay: 300 * time.Millisecond})
			case "canceled":
				fake.Fault("POST cluster/sdn/lock", sdntest.Fault{Delay: 300 * time.Millisecond, Before: func() {
					go func() { time.Sleep(100 * time.Millisecond); cancel() }()
				}})
			case "refused":
				fake.Fault("POST cluster/sdn/lock", sdntest.Fault{Refuse: "Permission check failed (/sdn, SDN.Allocate)", Status: http.StatusForbidden})
			case "known token, zone refused":
				fake.Fault("POST cluster/sdn/zones", sdntest.Fault{Refuse: "controlled zone allocation refusal", Status: http.StatusForbidden})
			}
			stateDir := t.TempDir()
			client := pve.NewClient(pve.Config{BaseURL: fake.Start(t).URL, Timeout: timeout})
			orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), client)
			orch.hostAddresses = &fakeHostAddressManager{}
			res, runErr := orch.Run(ctx)
			time.Sleep(350 * time.Millisecond) // the fake's delayed replies
			record, err := journal.Load(stateDir + "/active.json")
			if err != nil || runErr == nil || res.TeardownEvidence == nil {
				t.Fatalf("Run = %v, journal %v", runErr, err)
			}
			var lock string
			fake.Do(func(p *sdntest.PVE) { lock = p.Lock })
			switch scenario {
			case "refused":
				if !res.TeardownEvidence.AllCleaned || record.Phase != "cleaned" || record.SDNLockRequested != "" || lock != "" {
					t.Fatalf("evidence %+v, journal %+v, lock %q; a refusal is settled", res.TeardownEvidence, record, lock)
				}
			case "known token, zone refused":
				// PVE refused the zone (403), and its own lists show nothing
				// of it: the creation made nothing, so the allocation is
				// settled by reading PVE, not left for an operator.
				// The report does not claim a zone was removed that never was.
				if !res.TeardownEvidence.AllCleaned || res.TeardownEvidence.SDNZoneRemoved != "" || record.Phase != "cleaned" ||
					record.AllocationPending != "" || record.SDNLockToken != "" || record.SDNLockRequested != "" || lock != "" {
					t.Fatalf("evidence %+v, journal %+v, lock %q; want a clean run: the lock released and the refused zone's allocation settled", res.TeardownEvidence, record, lock)
				}
			default:
				if lock == "" {
					t.Fatal("the fixture made no lock")
				}
				if res.TeardownEvidence.AllCleaned || res.TeardownEvidence.OrphanSweepClean || record.Phase != "cleanup_failed" || record.SDNLockRequested == "" ||
					!strings.Contains(strings.Join(res.TeardownEvidence.CleanupErrors, "\n"), "got no definite answer") {
					t.Fatalf("evidence %+v, journal %+v; want the possible lock reported and journaled", res.TeardownEvidence, record)
				}
			}
		})
	}
}
