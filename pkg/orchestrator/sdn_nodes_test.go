// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// The reported case: a node name that is a list, "pve1,pve2", used
// to reach PVE as the zone's node list and apply SDN before anything rejected
// it. Run and Plan now refuse it before any PVE, PBS, SDN or journal work.
func TestRunAndPlanRefuseANodeListBeforeTouchingAnything(t *testing.T) {
	for _, node := range []string{"pve1,pve2", "pve1 ", "../pve1"} {
		t.Run("run "+node, func(t *testing.T) {
			fake := sdntest.New()
			stateDir := t.TempDir()
			orch := New(ephemeralPlan(), Options{NodeName: node, ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
			orch.hostAddresses = &fakeHostAddressManager{}
			res, err := orch.Run(context.Background())
			if err == nil || !strings.Contains(err.Error(), "invalid PVE node name") {
				t.Fatalf("Run = %v, want the node refused", err)
			}
			if res == nil || res.AllPassed {
				t.Fatalf("result %+v; want a failed result", res)
			}
			if len(fake.Requests) != 0 {
				t.Fatalf("PVE saw %v; want no request", fake.Requests)
			}
			if _, statErr := os.Stat(filepath.Join(stateDir, "active.json")); !os.IsNotExist(statErr) {
				t.Fatalf("a journal was written for a run that never started: %v", statErr)
			}
		})
		t.Run("plan "+node, func(t *testing.T) {
			fake := sdntest.New()
			o := planOrchestrator(t, planTestPlan(), fake.Serve(t))
			o.opts.NodeName = node
			p, err := o.Plan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Refusals) != 1 || !strings.Contains(p.Refusals[0], "invalid PVE node name") {
				t.Fatalf("refusals %v; want the node refused", p.Refusals)
			}
			if len(fake.Requests) != 0 {
				t.Fatalf("PVE saw %v; want no request", fake.Requests)
			}
		})
	}
}
