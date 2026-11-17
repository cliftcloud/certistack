//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"strings"
	"testing"
)

// An HTTP 404 was taken for "the VM does not exist", from any source: a proxy
// that answered 404 to the API made recovery find every recorded VM gone, and
// it marked the journal cleaned and released the VM's maps, address and overlays
// while the VM ran. It is an absence only when the cluster's own list agrees.
func TestRecoveryDoesNotTakeAProxys404ForTheVMsAbsence(t *testing.T) {
	f := &reuseFixture{occupant: "ours", status: "running", all404: true}
	f.serve(t)
	stateDir := reuseJournal(t)

	err := RecoverLocked(stateDir)
	if err == nil {
		t.Fatal("recovery reported success for a VM it could not read, only because every answer was a 404")
	}
	if f.called("POST ") || f.called("DELETE ") {
		t.Fatalf("recovery acted on a proxy's 404: %v", f.calls)
	}
	assertKept(t, stateDir)
}

// A stop that answers 404 for a VM the cluster lists is not the end of the VM,
// and the error says what PVE says of it now.
func TestRecoveryReportsAStop404ForAVMTheClusterStillLists(t *testing.T) {
	f := &reuseFixture{occupant: "ours", status: "running", stopNotFound: true}
	f.serve(t)
	stateDir := reuseJournal(t)

	err := RecoverLocked(stateDir)
	if f.called("DELETE ") {
		t.Fatalf("recovery destroyed a VM whose stop it could not do: %v", f.calls)
	}
	if err == nil || !strings.Contains(err.Error(), "HTTP 404 that the cluster does not back") || !strings.Contains(err.Error(), "still exists (status: running)") {
		t.Fatalf("recovery = %v, want the unbacked 404 and the VM that is still running", err)
	}
	assertKept(t, stateDir)
}

// The control: a stop's 404 that the list backs (the VM was removed since it was
// read, and nothing is at the ID) is the VM's absence, and recovery is clean.
func TestRecoveryAcceptsA404TheClusterListBacks(t *testing.T) {
	f := &reuseFixture{occupant: "ours", status: "running", stopNotFound: true}
	f.onStop = func() { f.occupant = "" }
	f.serve(t)
	stateDir := reuseJournal(t)
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery = %v; the VM is gone", err)
	}
	if !f.called("GET /api2/json/cluster/resources") {
		t.Fatalf("the stop's 404 was accepted without the cluster's list: %v", f.calls)
	}
	if after := journalPhase(t, stateDir); after.Phase != "cleaned" {
		t.Fatalf("journal phase = %q, want cleaned", after.Phase)
	}
}
