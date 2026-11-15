// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fullState is the largest state the product writes: every field set, as many
// clusters as a run records.
func fullState(t *testing.T) State {
	t.Helper()
	st := enabledState(t, true)
	st.LastTestRun = "2026-10-01"
	st.LastSent = "2026-10-01T12:00:00Z"
	for i := 0; i < clusterCap+50; i++ {
		if err := st.AddCluster(fmt.Sprintf("pve-node-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// The writer used to check only the logical consistency of what it wrote, and
// the reader refuses a file over 64 KiB: with up to 4096 clusters of 72 bytes
// each, a fleet of about 900 clusters produced a file the next run read as
// corrupt, which turned telemetry off and made the install ID, the salt and the
// history unavailable (audit F115).
func TestAStateAtTheClusterCapRoundTripsAndStaysUnderTheReadersLimit(t *testing.T) {
	path := statePath(t)
	st := fullState(t)
	if len(st.Clusters) != clusterCap {
		t.Fatalf("%d clusters after adding more than the cap; want %d", len(st.Clusters), clusterCap)
	}
	if err := WriteState(path, st); err != nil {
		t.Fatalf("WriteState at the cap: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() >= maxStateBytes {
		t.Fatalf("the state at the cap is %d bytes; the reader refuses %d", info.Size(), maxStateBytes)
	}
	got, status := ReadState(path)
	if status != StateOK {
		t.Fatalf("the state the writer wrote at the cap reads back as %v", status)
	}
	if got.InstallID != st.InstallID || got.Salt != st.Salt || !got.Enabled || !got.BusinessUse || len(got.Clusters) != clusterCap {
		t.Fatalf("round trip at the cap changed the state: %d clusters, id %q", len(got.Clusters), got.InstallID)
	}
	// Past the cap a run keeps the cap and the identity, and the file goes on
	// being one the reader believes.
	if err := got.AddCluster("one-more-cluster"); err != nil {
		t.Fatal(err)
	}
	if len(got.Clusters) != clusterCap {
		t.Fatalf("%d clusters after one more; want the cap, %d", len(got.Clusters), clusterCap)
	}
	if err := WriteState(path, got); err != nil {
		t.Fatalf("WriteState past the cap: %v", err)
	}
	if again, status := ReadState(path); status != StateOK || again.InstallID != st.InstallID {
		t.Fatalf("past the cap the state reads back as %v, id %q", status, again.InstallID)
	}
}

// What the reader would refuse for its size is not written, whatever its
// population says, and the file that is there stays as it was.
func TestWriteStateRefusesWhatReadStateWouldRefuseForItsSize(t *testing.T) {
	path := statePath(t)
	good := enabledState(t, false)
	if err := WriteState(path, good); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	big := enabledState(t, false)
	for i := 0; i < 1000; i++ {
		big.Clusters = append(big.Clusters, ClusterHash(big.Salt, fmt.Sprintf("n%d", i)))
	}
	if err := big.validate(); err != nil {
		t.Fatalf("the oversized state is meant to be consistent but for its size: %v", err)
	}
	err = WriteState(path, big)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("WriteState of %d clusters = %v; want a refusal for its size", len(big.Clusters), err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a refused write changed the state file")
	}
	leftovers, _ := filepath.Glob(path + ".tmp-*")
	if entries, _ := filepath.Glob(filepath.Join(filepath.Dir(path), StateFileName+".tmp-*")); len(entries) != 0 || len(leftovers) != 0 {
		t.Fatalf("a refused write left temporary files: %v", entries)
	}
}

// A controller that has validated more clusters than the cap keeps its consent
// and its identity, and reports the cap as its count: telemetry is never lost to
// the size of its own bookkeeping.
func TestAFleetPastTheClusterCapKeepsItsInstallAndItsAnswer(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	id := mustEnable(t, h, false).InstallID
	for i := 0; i < clusterCap+40; i++ {
		if out := h.AfterRun(context.Background(), completed(fmt.Sprintf("cluster-%d", i), h.now)); out.Err != nil {
			t.Fatalf("run %d: %+v", i, out)
		}
	}
	snap := h.Resolve()
	if !snap.Decision.Enabled || snap.Status != StateOK || snap.State.InstallID != id {
		t.Fatalf("after %d clusters: enabled %v, status %v, id %q (was %q); want the answer and the identity kept", clusterCap+40, snap.Decision.Enabled, snap.Status, snap.State.InstallID, id)
	}
	if len(snap.State.Clusters) != clusterCap {
		t.Fatalf("%d clusters kept; want the cap, %d", len(snap.State.Clusters), clusterCap)
	}
	if _, body, err := h.Show(); err != nil || !strings.Contains(string(body), fmt.Sprintf(`"cluster_count": %d`, clusterCap)) {
		t.Fatalf("the report after the cap says %s (%v); want the cap as the count", body, err)
	}
	// An opt-out is never refused for size.
	if _, err := h.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
}
