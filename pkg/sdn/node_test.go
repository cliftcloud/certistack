// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// A simple zone's node list is the run's one node. A name that is a
// list ("pve1,pve2") or anything else PVE's node names are not
// is refused before the zone request, not sent to build the zone on other
// nodes.
func TestCreateZoneRefusesANodeThatIsNotOneNodeName(t *testing.T) {
	netCfg := config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01"}
	for _, node := range []string{"pve1,pve2", "pve1 pve2", "pve1;pve2", "../pve1", "pve1\n", "-pve1"} {
		fake := sdntest.New()
		err := NewManager(fake.Serve(t)).CreateZone(context.Background(), netCfg, node)
		if err == nil || !strings.Contains(err.Error(), "invalid PVE node name") {
			t.Errorf("node %q: CreateZone = %v, want the name refused", node, err)
		}
		if len(fake.Requests) != 0 {
			t.Errorf("node %q: requests %v; want none", node, fake.Requests)
		}
	}
	fake := sdntest.New()
	if err := NewManager(fake.Serve(t)).CreateZone(context.Background(), netCfg, "pve-1.lab_2"); err != nil {
		t.Fatalf("CreateZone on a valid node name = %v", err)
	}
	if writes := fake.Writes(); len(writes) != 1 || !strings.Contains(writes[0], `"nodes":"pve-1.lab_2"`) {
		t.Fatalf("writes %v; want the zone on its one node", writes)
	}
}
