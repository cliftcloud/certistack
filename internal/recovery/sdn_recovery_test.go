//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// sdnRecovery points recovery at fake, with no waits, and records the
// bridges it checks; bridgeErr fails those checks.
type sdnRecovery struct {
	mu        sync.Mutex
	bridges   []string
	bridgeErr error
}

func recoverAgainst(t *testing.T, fake *sdntest.PVE) *sdnRecovery {
	t.Helper()
	server := fake.Start(t)
	t.Setenv("PVE_URL", server.URL)
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "test-secret")
	t.Setenv("PVE_TLS_INSECURE", "")
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", "")
	rec := &sdnRecovery{}
	previousSettle, previousWait, previousApply := settleBridge, sdnLockWait, sdnApplyWait
	settleBridge = func(_ context.Context, iface string, present bool, _ time.Duration) error {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.bridges = append(rec.bridges, iface)
		if present {
			return errors.New("recovery waited for a bridge to appear")
		}
		return rec.bridgeErr
	}
	sdnLockWait, sdnApplyWait = time.Millisecond, time.Millisecond
	t.Cleanup(func() { settleBridge, sdnLockWait, sdnApplyWait = previousSettle, previousWait, previousApply })
	return rec
}

func writeRecord(t *testing.T, record journal.Record) string {
	t.Helper()
	dir := t.TempDir()
	if err := journal.Write(filepath.Join(dir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	return dir
}

func loadRecord(t *testing.T, dir string) journal.Record {
	t.Helper()
	record, err := journal.Load(filepath.Join(dir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// testOwner is the marker the journals of these tests carry and their VNet
// has.
const testOwner = "certistack run-under-test"

func sandboxRecord(runID string) journal.Record {
	return journal.Record{RunID: runID, Phase: "cleanup_failed", UpdatedAt: time.Now().UTC(), SDNZones: []string{"csZone77"}, SDNVNets: []string{"csVn77"}, SDNOwner: testOwner}
}

// appliedSandbox is the run's zone and VNet, applied and running, the VNet
// carrying the run's marker.
func appliedSandbox() *sdntest.PVE {
	fake := sdntest.New().Applied("csZone77", "csVn77", "csZone77-10.89.0.0-24")
	fake.Aliases["csVn77"] = testOwner
	return fake
}

// The journal still names a zone and VNet that PVE has neither configured
// nor running, and an administrator has a
// change pending. Recovery takes no lock and applies nothing, and checks
// the bridge is gone from the node.
func TestRecoverAbsentSDNObjectsAppliesNothing(t *testing.T) {
	fake := sdntest.New()
	fake.Zones["prodZ"] = true
	rec := recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-absent"))
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked: %v", err)
	}
	if writes := fake.Writes(); len(writes) != 0 || fake.Applies != 0 {
		t.Fatalf("writes %v; want none", writes)
	}
	if !fake.Pending() {
		t.Fatal("the administrator's change was applied")
	}
	if loadRecord(t, dir).Phase != "cleaned" || strings.Join(rec.bridges, ",") != "csVn77" {
		t.Fatalf("journal %+v, bridges checked %v", loadRecord(t, dir), rec.bridges)
	}

	// PVE's configuration no longer having the VNet does not prove the
	// node's bridge is gone.
	fake = sdntest.New()
	rec = recoverAgainst(t, fake)
	rec.bridgeErr = errors.New("csVn77 still up")
	dir = writeRecord(t, sandboxRecord("recover-absent-bridge-up"))
	if err := RecoverLocked(dir); err == nil || !strings.Contains(err.Error(), "its bridge is still on this node") {
		t.Fatalf("RecoverLocked = %v, want the leftover bridge reported", err)
	}
	if loadRecord(t, dir).Phase == "cleaned" {
		t.Fatal("a leftover bridge was marked cleaned")
	}
}

// The run's zone and VNet are running. Recovery takes the lock and journals its
// token before it deletes anything, then deletes and applies under it.
func TestRecoverRunningSDNObjectsUnderAJournaledLock(t *testing.T) {
	fake := appliedSandbox()
	recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-running"))
	var journaledAtDelete []string
	fake.OnRequest = func(method, path string, _ map[string]string) {
		if method == "DELETE" && !strings.HasSuffix(path, "/lock") {
			record, _ := journal.Load(filepath.Join(dir, "active.json"))
			journaledAtDelete = append(journaledAtDelete, record.SDNLockToken)
		}
	}
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked: %v", err)
	}
	want := strings.Join([]string{
		"POST cluster/sdn/lock",
		"DELETE cluster/sdn/vnets/csVn77/subnets/csZone77-10.89.0.0-24?lock-token=tok-1",
		"DELETE cluster/sdn/vnets/csVn77?lock-token=tok-1",
		"DELETE cluster/sdn/zones/csZone77?lock-token=tok-1",
		`PUT cluster/sdn {"lock-token":"tok-1","release-lock":1}`,
	}, "\n")
	if got := strings.Join(fake.Writes(), "\n"); got != want {
		t.Fatalf("writes:\n%s\nwant:\n%s", got, want)
	}
	if strings.Join(journaledAtDelete, ",") != "tok-1,tok-1,tok-1" {
		t.Fatalf("token journaled at each deletion: %v", journaledAtDelete)
	}
	record := loadRecord(t, dir)
	if record.Phase != "cleaned" || record.SDNLockToken != "" || !strings.HasPrefix(record.SDNApplyTask, "UPID:node1:") || fake.Pending() {
		t.Fatalf("journal %+v, pending %v", record, fake.Pending())
	}
}

// An administrator's pending change refuses the lock. Recovery writes nothing
// to SDN (a deletion made without the lock would mix with the change, and the
// apply that enacts theirs would enact it); once the administrator has applied
// their change, a second recovery takes the lock, deletes the run's objects and
// applies, and leaves their zone alone.
func TestRecoverOverPendingChangesWritesNothingAndFinishesLater(t *testing.T) {
	fake := appliedSandbox()
	fake.Zones["prodZ"] = true
	recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-pending"))
	err := RecoverLocked(dir)
	if err == nil || !strings.Contains(err.Error(), "zone prodZ (new)") || !strings.Contains(err.Error(), "changed nothing") {
		t.Fatalf("RecoverLocked = %v, want the pending change named and nothing changed", err)
	}
	for _, w := range fake.Writes() {
		if strings.HasPrefix(w, "DELETE") || strings.HasPrefix(w, "PUT") {
			t.Fatalf("recovery wrote to SDN over an administrator's pending change: %v", fake.Writes())
		}
	}
	var stillThere bool
	fake.Do(func(p *sdntest.PVE) {
		stillThere = p.Zones["csZone77"] && p.VNets["csVn77"] != "" && len(p.Subnets["csVn77"]) == 1
	})
	if fake.Applies != 0 || !stillThere {
		t.Fatalf("applies %d, the run's objects still there %v; want none and true", fake.Applies, stillThere)
	}
	record := loadRecord(t, dir)
	if record.Phase != "cleanup_failed" || len(record.SDNZones) != 1 || len(record.SDNVNets) != 1 {
		t.Fatalf("journal %+v; want the run's objects kept for the next attempt", record)
	}

	// The administrator applies their change (the run's objects are still
	// running, and now nothing is pending).
	fake.Do(func(p *sdntest.PVE) { p.RunningZones["prodZ"] = true })
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("second RecoverLocked: %v", err)
	}
	var prod, gone bool
	fake.Do(func(p *sdntest.PVE) {
		prod = p.Zones["prodZ"] && p.RunningZones["prodZ"]
		gone = !p.Zones["csZone77"] && !p.RunningZones["csZone77"] && p.VNets["csVn77"] == "" && p.RunningVNets["csVn77"] == ""
	})
	if !prod || !gone || fake.Applies != 1 || loadRecord(t, dir).Phase != "cleaned" {
		t.Fatalf("second recovery: their zone kept %v, the run's objects gone %v, applies %d, journal %+v", prod, gone, fake.Applies, loadRecord(t, dir))
	}
}

// The run's deletion was made but not applied. With the run's
// journaled lock still standing, recovery applies under it; with no lock,
// the deletion is pending, the lock is refused, and nothing is applied.
func TestRecoverUnappliedDeletion(t *testing.T) {
	deleted := func() *sdntest.PVE {
		fake := appliedSandbox()
		fake.Zones, fake.VNets, fake.Subnets = map[string]bool{}, map[string]string{}, map[string][]string{}
		return fake
	}
	t.Run("under the run's standing lock", func(t *testing.T) {
		fake := deleted()
		fake.Lock = "tok-dead"
		recoverAgainst(t, fake)
		record := sandboxRecord("recover-unapplied-locked")
		record.SDNLockToken = "tok-dead"
		dir := writeRecord(t, record)
		if err := RecoverLocked(dir); err != nil {
			t.Fatalf("RecoverLocked: %v", err)
		}
		want := "POST cluster/sdn/lock\nPOST cluster/sdn/lock\nPUT cluster/sdn {\"lock-token\":\"tok-dead\",\"release-lock\":1}"
		if got := strings.Join(fake.Writes(), "\n"); got != want || fake.Pending() || fake.Lock != "" {
			t.Fatalf("writes:\n%s\nwant:\n%s\npending %v, lock %q", got, want, fake.Pending(), fake.Lock)
		}
		if loadRecord(t, dir).Phase != "cleaned" {
			t.Fatalf("journal %+v", loadRecord(t, dir))
		}
	})
	t.Run("with no lock standing", func(t *testing.T) {
		fake := deleted()
		recoverAgainst(t, fake)
		dir := writeRecord(t, sandboxRecord("recover-unapplied"))
		err := RecoverLocked(dir)
		if err == nil || fake.Applies != 0 || !strings.Contains(err.Error(), "zone csZone77 (deleted)") {
			t.Fatalf("RecoverLocked = %v, applies %d", err, fake.Applies)
		}
		if loadRecord(t, dir).Phase == "cleaned" {
			t.Fatal("an unapplied deletion was marked cleaned")
		}
	})
}

// The journaled token is kept, and the journal unclean, unless its
// release is established: PVE released it, or PVE says another lock stands.
func TestRecoverKeepsTheJournaledLockUntilItsReleaseIsEstablished(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lock      string
		fault     sdntest.Fault
		wantClean bool
	}{
		{"released", "tok-dead", sdntest.Fault{}, true},
		{"backend failure", "tok-dead", sdntest.Fault{Refuse: "could not release lock: backend unavailable"}, false},
		{"authorization failure", "tok-dead", sdntest.Fault{Refuse: "Permission check failed (/sdn, SDN.Allocate)", Status: 403}, false},
		{"lost reply", "tok-dead", sdntest.Fault{Lose: true}, false},
		{"another client's lock", "tok-theirs", sdntest.Fault{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := sdntest.New()
			fake.Lock = tc.lock
			fake.Fault("DELETE cluster/sdn/lock", tc.fault)
			recoverAgainst(t, fake)
			dir := writeRecord(t, journal.Record{RunID: "recover-lock", Phase: "running", UpdatedAt: time.Now().UTC(), SDNLockToken: "tok-dead"})
			err := RecoverLocked(dir)
			record := loadRecord(t, dir)
			if tc.wantClean {
				if err != nil || record.Phase != "cleaned" || record.SDNLockToken != "" {
					t.Fatalf("RecoverLocked = %v, journal %+v", err, record)
				}
				return
			}
			if err == nil || record.Phase == "cleaned" || record.SDNLockToken != "tok-dead" {
				t.Fatalf("RecoverLocked = %v, journal %+v; want the token kept", err, record)
			}
			// The next attempt settles it: the lock stood, or no lock stands.
			if err := RecoverLocked(dir); err != nil {
				t.Fatalf("second RecoverLocked: %v", err)
			}
			if record := loadRecord(t, dir); record.Phase != "cleaned" || record.SDNLockToken != "" || fake.Lock != "" {
				t.Fatalf("journal %+v, lock %q", record, fake.Lock)
			}
		})
	}
}

// Recovery's own lock is journaled before use, and stays journaled
// when its apply fails, so the next attempt applies under it.
func TestRecoverKeepsItsOwnLockWhenItsApplyFails(t *testing.T) {
	fake := appliedSandbox()
	fake.Fault("PUT cluster/sdn", sdntest.Fault{Refuse: "could not commit SDN config: cfs-lock 'domain-sdn' error: got lock request timeout"})
	recoverAgainst(t, fake)
	dir := writeRecord(t, sandboxRecord("recover-apply-fails"))
	if err := RecoverLocked(dir); err == nil {
		t.Fatal("a failed apply was not reported")
	}
	record := loadRecord(t, dir)
	if record.Phase != "cleanup_failed" || record.SDNLockToken != "tok-1" || fake.Lock != "tok-1" {
		t.Fatalf("journal %+v, lock %q; want recovery's lock journaled and standing", record, fake.Lock)
	}
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("second RecoverLocked: %v", err)
	}
	if record := loadRecord(t, dir); record.Phase != "cleaned" || record.SDNLockToken != "" || fake.Lock != "" || fake.Pending() {
		t.Fatalf("journal %+v, lock %q, pending %v", record, fake.Lock, fake.Pending())
	}
}

// The run's last apply must have ended before recovery applies.
func TestRecoverWaitsForTheRunsLastApply(t *testing.T) {
	fake := appliedSandbox()
	fake.TaskStatus = pve.TaskStatus{Status: "running"}
	recoverAgainst(t, fake)
	timeout := pveRecoveryTimeout
	pveRecoveryTimeout = 500 * time.Millisecond
	t.Cleanup(func() { pveRecoveryTimeout = timeout })
	record := sandboxRecord("recover-apply-running")
	record.SDNApplyTask = "UPID:node1:00000009:1:1:reloadnetworkall::root@pam:"
	dir := writeRecord(t, record)
	if err := RecoverLocked(dir); err == nil || !strings.Contains(err.Error(), "has not ended") {
		t.Fatalf("RecoverLocked = %v, want the running apply waited for", err)
	}
	if writes := fake.Writes(); len(writes) != 0 {
		t.Fatalf("writes %v while the run's apply ran", writes)
	}
	if got := loadRecord(t, dir); got.Phase == "cleaned" || got.SDNApplyTask != record.SDNApplyTask {
		t.Fatalf("journal %+v", got)
	}
	fake.Do(func(p *sdntest.PVE) { p.TaskStatus = pve.TaskStatus{Status: "stopped", ExitStatus: "OK"} })
	pveRecoveryTimeout = timeout
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked after the apply ended: %v", err)
	}
}

// The run's lock request got no answer, and a lock stands. It may
// be the run's: recovery never releases it by force, says how, and keeps
// the journal; once released, recovery settles the request.
func TestRecoverWithALostLockRequest(t *testing.T) {
	fake := sdntest.New()
	fake.Lock = "tok-lost"
	recoverAgainst(t, fake)
	dir := writeRecord(t, journal.Record{RunID: "recover-lost-lock", Phase: "cleanup_failed", UpdatedAt: time.Now().UTC(), SDNLockRequested: "2026-09-29T20:00:00Z"})
	err := RecoverLocked(dir)
	if err == nil || !strings.Contains(err.Error(), "pvesh delete /cluster/sdn/lock --force 1") {
		t.Fatalf("RecoverLocked = %v, want the forced release explained", err)
	}
	for _, write := range fake.Writes() {
		if strings.HasPrefix(write, "DELETE") {
			t.Fatalf("recovery released a lock that may not be the run's: %s", write)
		}
	}
	if record := loadRecord(t, dir); record.Phase == "cleaned" || record.SDNLockRequested != "2026-09-29T20:00:00Z" {
		t.Fatalf("journal %+v", record)
	}
	fake.Do(func(p *sdntest.PVE) { p.Lock = "" }) // the operator's forced release
	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked after the release: %v", err)
	}
	if record := loadRecord(t, dir); record.Phase != "cleaned" || record.SDNLockRequested != "" || fake.Lock != "" {
		t.Fatalf("journal %+v, lock %q", record, fake.Lock)
	}

	// A refusal over pending changes proves no lock stands: settled.
	fake = sdntest.New()
	fake.Zones["prodZ"] = true
	recoverAgainst(t, fake)
	dir = writeRecord(t, journal.Record{RunID: "recover-lost-lock-pending", Phase: "cleanup_failed", UpdatedAt: time.Now().UTC(), SDNLockRequested: "2026-09-29T20:00:00Z"})
	if err := RecoverLocked(dir); err != nil || loadRecord(t, dir).Phase != "cleaned" || fake.Applies != 0 {
		t.Fatalf("RecoverLocked = %v, journal %+v", err, loadRecord(t, dir))
	}
}

// Journals with the lock token but no lock request or apply task, and journals
// without the token, are read and recovered, but they name no owner marker: the
// run died with its zone and VNet created, never applied, and nothing in PVE
// shows that objects of those names are still the run's. Recovery deletes
// nothing of them, gives back the lock a journal with a token holds, and says
// what the operator does next. Once the operator has deleted the objects,
// recovery cleans the journal.
func TestRecoverOlderJournals(t *testing.T) {
	for name, raw := range map[string]string{
		"with a lock token":    `{"run_id":"run-earlier-1","phase":"running","updated_at":"2026-09-28T20:00:00Z","scratch":"","sdn_zones":["csZone77"],"sdn_vnets":["csVn77"],"sdn_lock_token":"tok-dead"}`,
		"without a lock token": `{"run_id":"run-earlier-2","phase":"running","updated_at":"2026-09-27T20:00:00Z","scratch":"","sdn_zones":["csZone77"],"sdn_vnets":["csVn77"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			fake := sdntest.New()
			fake.Zones["csZone77"], fake.VNets["csVn77"] = true, "csZone77"
			fake.Subnets["csVn77"] = []string{"csZone77-10.89.0.0-24"}
			if name == "with a lock token" {
				fake.Lock = "tok-dead"
			}
			recoverAgainst(t, fake)
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "active.json"), []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			err := RecoverLocked(dir)
			if err == nil || !strings.Contains(err.Error(), "cannot show that it is the interrupted run's") ||
				!strings.Contains(err.Error(), "delete it there") || !strings.Contains(err.Error(), recoverhint.Again) {
				t.Fatalf("RecoverLocked = %v, want the objects refused, with what the operator does next", err)
			}
			if got := deletesMade(fake); len(got) != 0 {
				t.Fatalf("recovery deleted on a journal that names no marker: %v", got)
			}
			if zone, vnet := sandboxState(fake); !zone || !vnet || fake.Applies != 0 || fake.Lock != "" {
				t.Fatalf("zone %v, vnet %v, applies %d, lock %q; want both left, nothing applied, no lock kept", zone, vnet, fake.Applies, fake.Lock)
			}
			if got := loadRecord(t, dir); got.Phase == "cleaned" || len(got.SDNZones) != 1 || len(got.SDNVNets) != 1 || got.SDNLockToken != "" {
				t.Fatalf("journal %+v; want it unclean, with the objects kept and the lock given back", got)
			}
			// The operator deletes them in PVE (the VNet with its subnets first).
			fake.Do(func(p *sdntest.PVE) {
				p.Zones, p.VNets, p.Subnets = map[string]bool{}, map[string]string{}, map[string][]string{}
			})
			if err := RecoverLocked(dir); err != nil || loadRecord(t, dir).Phase != "cleaned" {
				t.Fatalf("RecoverLocked after the operator's deletion = %v, journal %+v", err, loadRecord(t, dir))
			}
		})
	}
}
