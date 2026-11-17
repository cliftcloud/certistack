// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/macaddr"
	"github.com/cliftcloud/certistack/pkg/config"
)

func flatDoc(t *testing.T, parts ...string) string {
	t.Helper()
	data, err := os.ReadFile(repoFile(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(string(data)), " ")
}

// The plan reference states the rules a NIC's MAC address must meet (unique
// in the plan, not zero, broadcast or multicast), and the plan loader refuses
// each address the rules exclude. A change to either side fails here until the
// other follows.
func TestPlanReferenceStatesTheMACRulesTheLoaderEnforces(t *testing.T) {
	reference := flatDoc(t, "docs", "plan-reference.md")
	for _, rule := range []string{"unique in the plan", "not zero, broadcast or multicast"} {
		if !strings.Contains(reference, rule) {
			t.Errorf("docs/plan-reference.md does not state the MAC rule %q", rule)
		}
	}
	for _, mac := range []string{"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01", "33:33:00:00:00:01"} {
		if _, err := macaddr.Parse(mac); err == nil {
			t.Errorf("%s is accepted, and the plan reference says it is refused", mac)
		}
	}
	if _, err := macaddr.Parse("02:00:00:00:00:01"); err != nil {
		t.Errorf("a unicast address is refused: %v", err)
	}
	plan := &config.Plan{Tiers: []config.Tier{{VMs: []config.VM{
		{VMID: 9900, MAC: "00:11:22:33:44:55"},
		{VMID: 9901, MAC: "00-11-22-33-44-55"},
	}}}}
	if err := config.CheckNICIdentities(plan); err == nil || !strings.Contains(err.Error(), "both use 00:11:22:33:44:55") {
		t.Errorf("a plan whose VMs share a MAC address = %v, want it refused as the plan reference says", err)
	}
}
