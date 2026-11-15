// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodecheck

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

func sandboxProbes(networks preflight.NodeNetworks, readErr error) Probes {
	p, _ := probes()
	p.NodeNetworks = func() (preflight.NodeNetworks, error) { return networks, readErr }
	return p
}

func managementNode() preflight.NodeNetworks {
	return preflight.NodeNetworks{
		Routes: []preflight.NodeRoute{
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.42.20.1"), Interface: "vmbr0"},
			{Destination: netip.MustParsePrefix("10.42.20.0/24"), Interface: "vmbr0"},
		},
		Addresses: []preflight.NodeAddress{{Prefix: netip.MustParsePrefix("10.42.20.36/24"), Interface: "vmbr0"}},
	}
}

func sandboxSettings(ipRange, probe string) Settings {
	return Settings{
		PVEURL:        "https://10.42.20.5:8006",
		PBSRepository: "ro@pbs!t@10.42.10.5:8007:ds",
		Sandbox:       &Sandbox{IPRange: ipRange, ProbeIP: probe, VNetID: "csVnet1"},
	}
}

// Without a plan to judge there is no sandbox layer, and the three layers are
// what they were.
func TestSandboxLayerIsAbsentWithoutAPlan(t *testing.T) {
	p := sandboxProbes(managementNode(), nil)
	p.NodeNetworks = func() (preflight.NodeNetworks, error) {
		t.Error("the node's networks were read for no plan")
		return preflight.NodeNetworks{}, nil
	}
	report := RunThrough(context.Background(), Settings{}, p, "")
	if len(report.Layers) != 3 || report.Failed() != nil {
		t.Fatalf("report = %+v", report)
	}
}

// With a plan, the node's last layer: the range holds neither server and
// overlaps no network the node uses.
func TestSandboxLayerPassesARangeTheNodeDoesNotUse(t *testing.T) {
	report := RunThrough(context.Background(), sandboxSettings("192.0.2.0/24", "192.0.2.1"), sandboxProbes(managementNode(), nil), "")
	if report.Failed() != nil || len(report.Layers) != 4 {
		t.Fatalf("report = %+v", report)
	}
	layer := report.Layers[3]
	if layer.Name != LayerSandbox || layer.Status != StatusPassed || !strings.Contains(layer.Detail, "192.0.2.0/24") {
		t.Errorf("layer = %+v", layer)
	}
}

func TestSandboxLayerRefusesARangeHoldingTheServers(t *testing.T) {
	report := RunThrough(context.Background(), sandboxSettings("10.42.20.0/24", "10.42.20.250"), sandboxProbes(preflight.NodeNetworks{}, nil), "")
	failed := report.Failed()
	if failed == nil || failed.Name != LayerSandbox || failed.Code != CodeSandboxRange || !strings.Contains(failed.Detail, "contains the PVE API") {
		t.Fatalf("report = %+v", report)
	}
}

func TestSandboxLayerRefusesARangeOverTheNodesNetworks(t *testing.T) {
	report := RunThrough(context.Background(), sandboxSettings("10.42.20.128/25", "10.42.20.130"), sandboxProbes(managementNode(), nil), "")
	failed := report.Failed()
	if failed == nil || failed.Name != LayerSandbox || failed.Code != CodeSandboxNetwork || !strings.Contains(failed.Detail, "overlaps the node's real network 10.42.20.0/24 (on interface vmbr0)") {
		t.Fatalf("report = %+v", report)
	}
	// The range check comes first: a range holding the PVE API is that refusal.
	report = RunThrough(context.Background(), Settings{PVEURL: "https://10.42.20.130:8006", Sandbox: &Sandbox{IPRange: "10.42.20.128/25", ProbeIP: "10.42.20.131"}}, sandboxProbes(managementNode(), nil), "")
	if failed := report.Failed(); failed == nil || failed.Code != CodeSandboxRange {
		t.Fatalf("report = %+v", report)
	}
}

// Review R2-01: a range the node-side check cannot read is never a pass. The
// spellings below validated once (net.ParseCIDR) but could not be read by the
// overlap check (netip.ParsePrefix), which called that "nothing to judge" and
// printed a pass for a range that is in fact 10.0.0.0/8.
func TestSandboxLayerNeverPassesARangeItCannotRead(t *testing.T) {
	for _, ipRange := range []string{"10.0.0.0/08", "10.42.15.0/024", " 192.0.2.0/24", "192.0.2.0/24 ", "192.0.2.5/24", "fd00::/64"} {
		report := RunThrough(context.Background(), sandboxSettings(ipRange, "192.0.2.1"), sandboxProbes(managementNode(), nil), "")
		failed := report.Failed()
		if failed == nil || failed.Name != LayerSandbox || !strings.Contains(failed.Detail, "network.ip_range") {
			t.Errorf("ip_range %q: report = %+v, want the sandbox layer to fail naming network.ip_range", ipRange, report)
		}
		for _, layer := range report.Layers {
			if layer.Name == LayerSandbox && layer.Status == StatusPassed {
				t.Errorf("ip_range %q passed the sandbox layer: %+v", ipRange, layer)
			}
		}
	}
}

// Routes the node would not give: not a failure and not a pass.
func TestSandboxLayerIsUncheckedWhenTheNodesRoutesCannotBeRead(t *testing.T) {
	report := RunThrough(context.Background(), sandboxSettings("192.0.2.0/24", "192.0.2.1"), sandboxProbes(preflight.NodeNetworks{}, errors.New("open /proc/net/route: permission denied")), "")
	if report.Failed() != nil || len(report.Layers) != 4 {
		t.Fatalf("report = %+v", report)
	}
	layer := report.Layers[3]
	if layer.Status != StatusUnchecked || !strings.Contains(layer.Detail, "could not check the node's routes") {
		t.Errorf("layer = %+v, want it unchecked with the reason", layer)
	}
}

// A pre-provisioned sandbox is carried on its own VNet's interface.
func TestSandboxLayerLeavesAPreprovisionedVNetOut(t *testing.T) {
	node := managementNode()
	node.Routes = append(node.Routes, preflight.NodeRoute{Destination: netip.MustParsePrefix("192.0.2.0/24"), Interface: "csVnet1"})
	s := sandboxSettings("192.0.2.0/24", "192.0.2.1")
	if report := RunThrough(context.Background(), s, sandboxProbes(node, nil), ""); report.Failed() == nil {
		t.Fatalf("an ephemeral sandbox already on the node passed: %+v", report)
	}
	s.Sandbox.Lifecycle = "preprovisioned"
	if report := RunThrough(context.Background(), s, sandboxProbes(node, nil), ""); report.Failed() != nil {
		t.Fatalf("a pre-provisioned sandbox on its own VNet failed: %+v", report)
	}
}

// The sandbox layer is the last: through stops short of it, and an earlier
// failing layer ends the report before it.
func TestSandboxLayerFollowsTheOtherLayers(t *testing.T) {
	read := false
	p := sandboxProbes(managementNode(), nil)
	p.NodeNetworks = func() (preflight.NodeNetworks, error) { read = true; return managementNode(), nil }
	if report := RunThrough(context.Background(), sandboxSettings("192.0.2.0/24", "192.0.2.1"), p, LayerPBS); len(report.Layers) != 3 || read {
		t.Fatalf("through %s: %d layers, read %v", LayerPBS, len(report.Layers), read)
	}
	p.PBSBackups = func(context.Context, Settings) ([]pbs.VMBackups, error) { return nil, errors.New("boom") }
	if report := RunThrough(context.Background(), sandboxSettings("192.0.2.0/24", "192.0.2.1"), p, ""); len(report.Layers) != 3 || read {
		t.Fatalf("after a PBS failure: %d layers, read %v", len(report.Layers), read)
	}
}
