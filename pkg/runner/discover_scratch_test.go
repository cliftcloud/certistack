// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// Remote init validated its --scratch, sent it, and the worker threw
// it away, so backups' configurations were restored into the node's
// temporary directory. The chain has several hops, and a test at each end
// leaves the middle ones free to drop the value again. This is the last
// hop: Discover hands the directory it prepared to initplan.Discover, which
// reads the configurations beneath it. An empty value here is the reporter's
// defect, whatever the flag, the controller and the worker command did.
func TestDiscoverGivesItsScratchDirectoryToTheReadOfTheBackups(t *testing.T) {
	t.Setenv("PVE_TLS_INSECURE", "")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!token@pbs.example:store")
	t.Setenv("PBS_PASSWORD", "unused")
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(state, "scratch")

	previous := initplanDiscover
	t.Cleanup(func() { initplanDiscover = previous })
	var calls int
	var gotScratch string
	var gotRequest initplan.Request
	initplanDiscover = func(_ context.Context, _ initplan.Backups, _ initplan.Cluster, req initplan.Request, scratchDir string) (*initplan.Discovery, error) {
		calls++
		gotScratch, gotRequest = scratchDir, req
		return &initplan.Discovery{Node: req.Node}, nil
	}

	if _, err := Discover(context.Background(), initplan.Request{Node: "pve1", VMIDs: []int{100}}, scratch); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || gotScratch != scratch {
		t.Fatalf("initplan.Discover was called %d time(s) with scratch %q, want once with %q", calls, gotScratch, scratch)
	}
	if info, err := os.Stat(scratch); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o700) {
		t.Errorf("the scratch directory it was given was not prepared private first: %v, %v", info, err)
	}
	if gotRequest.Node != "pve1" || len(gotRequest.VMIDs) != 1 || gotRequest.VMIDs[0] != 100 {
		t.Errorf("the request did not arrive as given: %+v", gotRequest)
	}

	// With no directory chosen the node's temporary directory is meant, and
	// is what discovery is told: empty.
	if _, err := Discover(context.Background(), initplan.Request{Node: "pve1"}, ""); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || gotScratch != "" {
		t.Errorf("without a scratch directory: %d calls, scratch %q", calls, gotScratch)
	}
}
