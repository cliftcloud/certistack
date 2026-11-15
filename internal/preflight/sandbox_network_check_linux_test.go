// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

func withNodeNetworks(t *testing.T, read func() (NodeNetworks, error)) {
	t.Helper()
	previous := readNodeNetworksForCheck
	t.Cleanup(func() { readNodeNetworksForCheck = previous })
	readNodeNetworksForCheck = read
}

func checkedPlan(ipRange, probe string) *config.Plan {
	plan := rangePlan(ipRange)
	plan.Network.ProbeIP, plan.Network.VNetID, plan.Network.ZoneID = probe, "csVnet1", "csZone1"
	return plan
}

// doctor and the node worker's preflight both run it: a range over a real
// network of the node makes the host not ready, with the refusal in the item.
func TestCheckRefusesASandboxRangeOverTheNodesNetworks(t *testing.T) {
	withNodeNetworks(t, func() (NodeNetworks, error) { return sampleNode(), nil })
	result := Check(context.Background(), checkedPlan("10.42.15.0/24", "10.42.15.250"), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()})
	item := checkItem(result, SandboxNetworkCheckName)
	if item == nil || item.Status != "failed" || !strings.Contains(item.Detail, "overlaps the node's real network 10.42.15.0/24 (on interface vmbr4)") {
		t.Fatalf("%s item = %+v", SandboxNetworkCheckName, item)
	}
	if result.Ready {
		t.Error("the host is ready with a sandbox range over its own network")
	}
}

func TestCheckPassesASandboxRangeTheNodeDoesNotUse(t *testing.T) {
	withNodeNetworks(t, func() (NodeNetworks, error) { return sampleNode(), nil })
	result := Check(context.Background(), checkedPlan("192.0.2.0/24", "192.0.2.1"), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()})
	if item := checkItem(result, SandboxNetworkCheckName); item == nil || item.Status != "passed" {
		t.Fatalf("%s item = %+v", SandboxNetworkCheckName, item)
	}
}

// Routes it cannot read are a warning that says so: not a pass, and not a
// reason to refuse a host whose range may be fine.
func TestCheckWarnsWhenTheNodesRoutesCannotBeRead(t *testing.T) {
	withNodeNetworks(t, func() (NodeNetworks, error) {
		return NodeNetworks{}, errors.New("open /proc/net/route: permission denied")
	})
	result := Check(context.Background(), checkedPlan("192.0.2.0/24", "192.0.2.1"), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()})
	item := checkItem(result, SandboxNetworkCheckName)
	if item == nil || item.Status != "warning" || !strings.Contains(item.Detail, "could not check the node's routes") || !strings.Contains(item.Detail, "ip -4 route") {
		t.Fatalf("%s item = %+v", SandboxNetworkCheckName, item)
	}
}

// A pre-provisioned sandbox carries its range on its own VNet's interface.
func TestCheckLeavesAPreprovisionedVNetsInterfaceOut(t *testing.T) {
	node := sampleNode()
	node.Routes = append(node.Routes, NodeRoute{Destination: netip.MustParsePrefix("192.0.2.0/24"), Interface: "csVnet1"})
	node.Addresses = append(node.Addresses, NodeAddress{Prefix: netip.MustParsePrefix("192.0.2.1/24"), Interface: "csVnet1"})
	withNodeNetworks(t, func() (NodeNetworks, error) { return node, nil })

	plan := checkedPlan("192.0.2.0/24", "192.0.2.1")
	plan.Network.Lifecycle = "preprovisioned"
	if item := checkItem(Check(context.Background(), plan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}), SandboxNetworkCheckName); item == nil || item.Status != "passed" {
		t.Errorf("pre-provisioned: %s item = %+v", SandboxNetworkCheckName, item)
	}
	plan.Network.Lifecycle = ""
	if item := checkItem(Check(context.Background(), plan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}), SandboxNetworkCheckName); item == nil || item.Status != "failed" {
		t.Errorf("ephemeral: %s item = %+v", SandboxNetworkCheckName, item)
	}
}

// Without a plan there is no range to judge, and nothing is read.
func TestCheckWithoutAPlanReadsNoRoutes(t *testing.T) {
	withNodeNetworks(t, func() (NodeNetworks, error) {
		t.Error("the node's routes were read for no plan")
		return NodeNetworks{}, nil
	})
	if item := checkItem(Check(context.Background(), nil, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}), SandboxNetworkCheckName); item != nil {
		t.Errorf("%s item = %+v for no plan", SandboxNetworkCheckName, item)
	}
}
