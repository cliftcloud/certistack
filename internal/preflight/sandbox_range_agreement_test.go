// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// Plan validation, the node-side overlap judgement and the engine's use of
// network.ip_range read the same text. Two parsers can disagree over a prefix
// length with leading zeros (10.0.0.0/08): net.ParseCIDR accepts it and
// netip.ParsePrefix does not, so validation could pass a range the overlap
// check cannot read ("nothing to judge") while the engine puts 10.x.x.x/8 on
// the sandbox bridge. These tests hold the three together: whatever validation
// accepts, the overlap judgement reads as the same network.

var (
	exampleOnce sync.Once
	examplePlan *config.Plan
	exampleErr  error
)

// planWithRange is the minimal example plan with its sandbox range replaced.
func planWithRange(t *testing.T, ipRange string) *config.Plan {
	t.Helper()
	exampleOnce.Do(func() { examplePlan, exampleErr = config.LoadFromFile("../../examples/minimal-single-vm.yaml") })
	if exampleErr != nil {
		t.Fatalf("load the example plan: %v", exampleErr)
	}
	plan := *examplePlan
	plan.Network.IPRange = ipRange
	plan.Network.SubnetCIDR = ""
	return &plan
}

// validationAccepts is whether plan validation finds nothing wrong with the
// range itself (the probe address and the rest of the plan are not the range).
func validationAccepts(t *testing.T, ipRange string) bool {
	t.Helper()
	for _, problem := range config.Validate(planWithRange(t, ipRange)) {
		if problem.Field == "network.ip_range" {
			return false
		}
	}
	return true
}

// agreement fails when validation accepts ipRange yet the overlap judgement
// reads it as another network (or cannot read it), or when the engine's probe
// address would not sit in that same network.
func agreement(t *testing.T, ipRange string) {
	t.Helper()
	if !validationAccepts(t, ipRange) {
		return
	}
	_, loose, err := net.ParseCIDR(ipRange)
	if err != nil {
		t.Errorf("validation accepts %q but net.ParseCIDR does not: %v", ipRange, err)
		return
	}
	want, ok := netip.AddrFromSlice(loose.IP.To4())
	if !ok {
		t.Errorf("validation accepts %q, which is not an IPv4 network", ipRange)
		return
	}
	ones, _ := loose.Mask.Size()
	wantPrefix := netip.PrefixFrom(want, ones)

	network := config.Network{IPRange: ipRange}
	got, present, err := sandboxPrefix(network)
	switch {
	case err != nil:
		t.Errorf("validation accepts %q but the overlap check cannot read it: %v", ipRange, err)
		return
	case !present:
		t.Errorf("validation accepts %q but the overlap check finds no range to judge", ipRange)
		return
	case got != wantPrefix:
		t.Errorf("validation accepts %q (the network %s) but the overlap check judges %s", ipRange, wantPrefix, got)
		return
	}

	// A node route for exactly that network must be refused: the judgement is
	// made on the network validation accepted, not on a neighbour of it.
	if wantPrefix.Bits() > 0 {
		node := NodeNetworks{Routes: []NodeRoute{{Destination: wantPrefix, Interface: "vmbr9"}}}
		if err := CheckSandboxNetwork(network, "", node); err == nil {
			t.Errorf("validation accepts %q but a node route for %s passes the overlap check", ipRange, wantPrefix)
		}
	}

	// The engine's own use of the range: the address that goes on the bridge
	// lies in the same network with the same prefix length.
	if wantPrefix.Bits() < 31 {
		probe := wantPrefix.Addr().Next()
		engine := config.Network{IPRange: ipRange, ProbeIP: probe.String()}
		cidr, err := engine.ProbeAddressCIDR()
		if err != nil {
			t.Errorf("validation accepts %q but the engine cannot use it: %v", ipRange, err)
			return
		}
		onBridge, err := netip.ParsePrefix(cidr)
		if err != nil || onBridge.Bits() != wantPrefix.Bits() || onBridge.Masked() != wantPrefix {
			t.Errorf("validation accepts %q (%s) but the engine puts %q on the sandbox bridge (%v)", ipRange, wantPrefix, cidr, err)
		}
	}
}

// spellings are one network written many ways: canonical, with leading zeros in
// the prefix length or the octets, with spaces, zones, signs, other digits, in
// IPv6 and IPv4-mapped IPv6 forms, in upper and lower case.
var spellings = []string{
	"10.0.0.0/8", "10.0.0.0/08", "10.0.0.0/008", "10.42.15.0/24", "10.42.15.0/024", "10.42.15.0/0024",
	"10.42.015.0/24", "010.42.15.0/24", "10.042.15.0/24", "10.42.15.0/+24", "10.42.15.0/-24",
	" 10.42.15.0/24", "10.42.15.0/24 ", "10.42.15.0/24\n", "\t10.42.15.0/24", "10.42.15.0 /24", "10.42.15.0/ 24",
	"10.42.15.5/24", "10.42.15.5/024", "10.42.15.0/32", "10.42.15.0/32 ", "10.42.15.0/33", "10.42.15.0",
	"10.42.15.0/", "/24", "", "10.42.15.0%eth0/24", "10.42.15.0/24%eth0",
	"::ffff:10.42.15.0/120", "::FFFF:10.42.15.0/120", "::ffff:a2a:f00/120", "0:0:0:0:0:ffff:a2a:f00/120",
	"fd00::/64", "FD00::/64", "fe80::1%eth0/64", "2001:db8::/32",
	"0xa.0.0.0/8", "10.1/16", "10.0.0.0/0x8", "10.0.0.0/8.0", "10.0.0.0/2_4", "10.42.15.0/２４",
	"１０.42.15.0/24", "192.0.2.0/24", "192.0.2.0/024", "192.0.2.0/25", "198.51.100.0/22", "203.0.113.128/25",
	"172.16.0.0/12", "172.16.0.0/012", "100.64.0.0/10", "100.64.0.0/010", "192.168.0.0/16", "192.168.0.0/016",
	"169.254.0.0/16", "127.0.0.0/8", "127.0.0.0/08", "0.0.0.0/0", "0.0.0.0/00", "0.0.0.0/8", "224.0.0.0/4",
}

func TestValidationAndTheOverlapCheckAgreeOnEverySpelling(t *testing.T) {
	for _, text := range spellings {
		t.Run(text, func(t *testing.T) { agreement(t, text) })
	}
}

// Fuzzed: nothing validation accepts may be read differently by the overlap
// judgement or the engine.
func FuzzSandboxRangeAgreement(f *testing.F) {
	for _, text := range spellings {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 64 {
			t.Skip()
		}
		agreement(t, text)
	})
}

// Each of these spellings fails validation, and the overlap judgement
// fails closed on them too: a non-empty range it cannot read is an error, never
// "nothing to judge".
func TestAnUnreadableSandboxRangeIsNeverAPass(t *testing.T) {
	node := sampleNode()
	read := func() (NodeNetworks, error) { return node, nil }
	for _, text := range []string{"10.0.0.0/08", "10.42.15.0/024", " 10.42.15.0/24", "10.42.15.0/24 ", "10.42.15.0%eth0/24", "::ffff:10.42.15.0/120", "not a range", "10.42.15.0/33", "10.42.15.0"} {
		network := config.Network{IPRange: text, ProbeIP: "10.42.15.1"}
		if err := CheckSandboxNetwork(network, "", node); err == nil {
			t.Errorf("CheckSandboxNetwork accepted the unreadable range %q", text)
		}
		if warning, err := VerifySandboxNetwork(network, "", read); err == nil {
			t.Errorf("VerifySandboxNetwork passed the unreadable range %q (warning %q)", text, warning)
		}
		if err := CheckSandboxRange(context.Background(), &config.Plan{Network: network}, "https://192.0.2.10:8006", "", nil); err == nil {
			t.Errorf("CheckSandboxRange passed the unreadable range %q", text)
		}
		if validationAccepts(t, text) {
			t.Errorf("plan validation accepts the range %q", text)
		}
	}
	// An empty range is the one thing with nothing to judge (validation refuses
	// the plan that has none).
	if err := CheckSandboxNetwork(config.Network{}, "", node); err != nil {
		t.Errorf("a plan with no range: %v", err)
	}
	// The refusal says what is wrong and the canonical form.
	_, err := VerifySandboxNetwork(config.Network{IPRange: "10.42.15.0/024", ProbeIP: "10.42.15.1"}, "", read)
	if err == nil || !strings.Contains(err.Error(), "network.ip_range") || !strings.Contains(err.Error(), "write it as 10.42.15.0/24") {
		t.Errorf("refusal = %v, want it to name network.ip_range and the canonical form", err)
	}
}
