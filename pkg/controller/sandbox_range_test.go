// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"strings"
	"testing"
)

// A sandbox range that holds the PVE API or the PBS server by its address is
// refused on the controller, before it stages a worker or contacts the node at
// all: the run would lose its own connection once the probe address is up. The
// node's own check, which resolves names as the node does, is the one that
// counts; the controller does not resolve names, so its resolver cannot refuse
// a range the node would accept.
func TestExecutorRunRefusesARangeHoldingAServerByAddress(t *testing.T) {
	for _, tc := range []struct {
		name, pveURL, repository, want string
	}{
		{"PVE API address inside", "https://192.0.2.5:8006", "backup@pbs!read@198.51.100.7:8007:datastore", "the PVE API"},
		{"PBS server address inside", "https://203.0.113.5:8006", "backup@pbs!read@192.0.2.9:8007:datastore", "the PBS server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := preflightTestOptions(t)
			t.Setenv("PVE_URL", tc.pveURL)
			t.Setenv("PBS_REPOSITORY", tc.repository)
			fake := &fakeCommandRunner{}
			_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), "network.ip_range 192.0.2.0/24 contains "+tc.want) {
				t.Fatalf("Run error = %v, want a refusal that the range contains %s", err, tc.want)
			}
			if len(fake.calls) != 0 {
				t.Fatalf("the node was contacted before the refusal: %#v", fake.calls)
			}
		})
	}
}

// Names are the node's to resolve: a name the controller could resolve inside
// the range, or not at all, is not a refusal here, and the run goes on to stage
// its worker.
func TestExecutorRunLeavesNamesToTheNode(t *testing.T) {
	opts := preflightTestOptions(t) // PVE_URL and PBS_REPOSITORY name hosts
	fake := &fakeCommandRunner{nodeMachine: "s390x"}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "architecture") {
		t.Fatalf("Run error = %v, want it to get as far as the node's architecture", err)
	}
	if len(fake.calls) == 0 {
		t.Fatal("the node was never contacted")
	}
}
