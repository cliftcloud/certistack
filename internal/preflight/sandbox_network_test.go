// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// sampleNode is a sample node (pve-node-01): connected
// routes for its storage, cluster, backup and management networks, a default
// route through the management gateway, an iDRAC link-local network, and the
// addresses that go with them. The integration expectations of the hardening
// brief are stated against it.
func sampleNode() NodeNetworks {
	route := func(destination, gateway, iface string) NodeRoute {
		r := NodeRoute{Destination: netip.MustParsePrefix(destination), Interface: iface}
		if gateway != "" {
			r.Gateway = netip.MustParseAddr(gateway)
		}
		return r
	}
	address := func(prefix, iface string) NodeAddress {
		return NodeAddress{Prefix: netip.MustParsePrefix(prefix), Interface: iface}
	}
	return NodeNetworks{
		Routes: []NodeRoute{
			route("0.0.0.0/0", "10.42.20.1", "vmbr0"),
			route("10.42.10.0/24", "", "vmbr1"),
			route("10.42.11.0/24", "", "vmbr2"),
			route("10.42.12.0/24", "", "vmbr3"),
			route("10.42.15.0/24", "", "vmbr4"),
			route("10.42.20.0/24", "", "vmbr0"),
			route("169.254.0.0/16", "", "idrac"),
		},
		Addresses: []NodeAddress{
			address("127.0.0.1/8", "lo"),
			address("10.42.20.36/24", "vmbr0"),
			address("10.42.10.36/24", "vmbr1"),
			address("10.42.11.36/24", "vmbr2"),
			address("10.42.12.36/24", "vmbr3"),
			address("10.42.15.36/24", "vmbr4"),
			address("169.254.0.2/16", "idrac"),
		},
	}
}

func sandbox(ipRange, probe string) config.Network {
	return config.Network{Mode: "simple", ZoneID: "csZone1", VNetID: "csVnet1", IPRange: ipRange, ProbeIP: probe}
}

// The cases of the sweep (sweep_overlap.sh) and the edges around them.
func TestCheckSandboxNetworkAgainstTheNodesRealNetworks(t *testing.T) {
	for _, tc := range []struct {
		name, ipRange, probe string
		want                 []string // fragments of the refusal; none: accepted
	}{
		{"documentation range", "192.0.2.0/24", "192.0.2.1", nil},
		{"unused private range", "192.168.250.0/24", "192.168.250.1", nil},
		{"unused 10.x range beside the node's", "10.42.30.0/24", "10.42.30.1", nil},
		{"equal to a real network", "10.42.15.0/24", "10.42.15.250", []string{"10.42.15.0/24 overlaps the node's real network 10.42.15.0/24 (on interface vmbr4)"}},
		{"equal to the backup network", "10.42.10.0/24", "10.42.10.250", []string{"overlaps the node's real network 10.42.10.0/24 (on interface vmbr1)"}},
		{"equal to the management network", "10.42.20.0/24", "10.42.20.250", []string{"overlaps the node's real network 10.42.20.0/24 (on interface vmbr0)", "contains the node's default gateway 10.42.20.1"}},
		{"contained in a real network (/25 in a /24)", "10.42.20.128/25", "10.42.20.130", []string{"10.42.20.128/25 overlaps the node's real network 10.42.20.0/24 (on interface vmbr0)"}},
		{"contained, a /29 deep in a /24", "10.42.11.8/29", "10.42.11.9", []string{"overlaps the node's real network 10.42.11.0/24 (on interface vmbr2)"}},
		{"containing several real networks (/8)", "10.0.0.0/8", "10.250.0.1", []string{"10.0.0.0/8 overlaps the node's real networks", "10.42.10.0/24 (on interface vmbr1)", "10.42.11.0/24 (on interface vmbr2)", "10.42.12.0/24 (on interface vmbr3)", "and 2 more"}},
		{"containing real networks (/16)", "10.42.0.0/16", "10.42.250.1", []string{"10.42.0.0/16 overlaps the node's real networks"}},
		{"link-local network of the iDRAC", "169.254.0.0/24", "169.254.0.1", []string{"overlaps the node's real network 169.254.0.0/16 (on interface idrac)"}},
		{"the gateway's own network", "10.42.20.0/30", "10.42.20.1", []string{"10.42.20.0/30 overlaps the node's real network 10.42.20.0/24", "contains the node's default gateway 10.42.20.1"}},
		{"the probe address is the node's address", "10.42.15.0/24", "10.42.15.36", []string{"overlaps the node's real network 10.42.15.0/24", "network.probe_ip 10.42.15.36 is an address of the node itself (on interface vmbr4)"}},
		{"loopback is plan validation's to refuse, not this check's", "127.0.0.0/24", "127.0.0.1", nil},
		{"just outside a real network", "10.42.13.0/24", "10.42.13.1", nil},
		{"adjacent to a real network, not inside it", "10.42.16.0/24", "10.42.16.1", nil},
		// Review R2-01: the one reader of the range (config.ParseSandboxRange)
		// refuses a range with host bits set, as plan validation does, rather
		// than judging a network the plan did not write.
		{"range written with host bits is refused, naming its network", "10.42.15.77/24", "10.42.15.250", []string{"network.ip_range 10.42.15.77/24 has host bits set", "did you mean 10.42.15.0/24?"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSandboxNetwork(sandbox(tc.ipRange, tc.probe), "", sampleNode())
			assertRefusal(t, err, tc.want)
			if err != nil {
				// Every refusal says how to choose again.
				for _, fix := range []string{"192.0.2.0/24", "ip -4 route"} {
					if !strings.Contains(err.Error(), fix) && !strings.Contains(err.Error(), "probe_ip") && !strings.Contains(err.Error(), "host bits set") {
						t.Errorf("refusal does not say %q: %v", fix, err)
					}
				}
			}
		})
	}
}

func assertRefusal(t *testing.T, err error, want []string) {
	t.Helper()
	switch {
	case len(want) == 0 && err != nil:
		t.Fatalf("refused: %v", err)
	case len(want) > 0 && err == nil:
		t.Fatalf("accepted, want a refusal naming %q", want)
	}
	for _, fragment := range want {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("refusal lacks %q:\n%v", fragment, err)
		}
	}
}

// The default route holds every destination, so it overlaps every range; it is
// what the node reaches the rest of the network by, and is not a finding.
func TestCheckSandboxNetworkIgnoresTheDefaultRoute(t *testing.T) {
	nodeNetworks := NodeNetworks{Routes: []NodeRoute{
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("198.51.100.1"), Interface: "eth0"},
		{Destination: netip.MustParsePrefix("198.51.100.0/24"), Interface: "eth0"},
	}}
	if err := CheckSandboxNetwork(sandbox("192.0.2.0/24", "192.0.2.1"), "", nodeNetworks); err != nil {
		t.Fatalf("a default route made %v", err)
	}
}

// Review R2-15. A VPN client (OpenVPN's redirect-gateway def1, WireGuard with
// AllowedIPs 0.0.0.0/0 on some setups) installs the default route as two halves,
// 0.0.0.0/1 and 128.0.0.0/1. Read as ordinary networks they overlap every range,
// so every plan was refused; they are the default route, which holds every
// destination and is not a network of its own.
func TestCheckSandboxNetworkTreatsASplitDefaultRouteAsTheDefaultRoute(t *testing.T) {
	nodeNetworks := NodeNetworks{Routes: []NodeRoute{
		{Destination: netip.MustParsePrefix("0.0.0.0/1"), Gateway: netip.MustParseAddr("10.8.0.1"), Interface: "tun0"},
		{Destination: netip.MustParsePrefix("128.0.0.0/1"), Gateway: netip.MustParseAddr("10.8.0.1"), Interface: "tun0"},
		{Destination: netip.MustParsePrefix("10.8.0.0/24"), Interface: "tun0"},
	}}
	if err := CheckSandboxNetwork(sandbox("192.0.2.0/24", "192.0.2.1"), "", nodeNetworks); err != nil {
		t.Fatalf("the two halves of a default route refused a range beside them: %v", err)
	}
	// The gateway of the halves is the node's way out, whatever the halves are.
	err := CheckSandboxNetwork(sandbox("10.8.0.0/29", "10.8.0.2"), "", nodeNetworks)
	assertRefusal(t, err, []string{"overlaps the node's real network 10.8.0.0/24 (on interface tun0)", "contains the node's default gateway 10.8.0.1"})
}

// A default gateway that is not inside any connected network (an onlink route)
// is still lost once the range holding it is routed to the sandbox bridge.
func TestCheckSandboxNetworkRefusesARangeHoldingTheDefaultGateway(t *testing.T) {
	nodeNetworks := NodeNetworks{Routes: []NodeRoute{
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("203.0.113.1"), Interface: "eth0"},
	}}
	err := CheckSandboxNetwork(sandbox("203.0.113.0/24", "203.0.113.10"), "", nodeNetworks)
	assertRefusal(t, err, []string{"network.ip_range 203.0.113.0/24 contains the node's default gateway 203.0.113.1", "lose its way out", "ip -4 route"})
	if err := CheckSandboxNetwork(sandbox("203.0.114.0/24", "203.0.114.10"), "", nodeNetworks); err != nil {
		t.Fatalf("a range beside the gateway's was refused: %v", err)
	}
}

// Every default route counts, a second one at another metric included.
func TestCheckSandboxNetworkChecksEveryDefaultRoute(t *testing.T) {
	nodeNetworks := NodeNetworks{Routes: []NodeRoute{
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("198.51.100.1"), Interface: "eth0"},
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("203.0.113.1"), Interface: "eth1"},
	}}
	assertRefusal(t, CheckSandboxNetwork(sandbox("203.0.113.0/24", "203.0.113.10"), "", nodeNetworks), []string{"default gateway 203.0.113.1"})
}

// The gateway of a route that is not the default one is as much the node's way
// out as the default gateway is.
func TestCheckSandboxNetworkRefusesARangeHoldingAnyRoutesGateway(t *testing.T) {
	nodeNetworks := NodeNetworks{Routes: []NodeRoute{
		{Destination: netip.MustParsePrefix("172.31.0.0/16"), Gateway: netip.MustParseAddr("203.0.113.254"), Interface: "eth0"},
	}}
	assertRefusal(t, CheckSandboxNetwork(sandbox("203.0.113.0/24", "203.0.113.10"), "", nodeNetworks), []string{"the gateway 203.0.113.254 of the node's route to 172.31.0.0/16"})
}

// A node address that no route covers (a /32 on a dummy interface, an address
// added with noprefixroute) is still the node's own.
func TestCheckSandboxNetworkRefusesARangeHoldingANodeAddress(t *testing.T) {
	nodeNetworks := NodeNetworks{Addresses: []NodeAddress{
		{Prefix: netip.MustParsePrefix("192.0.2.77/32"), Interface: "dummy0"},
	}}
	assertRefusal(t, CheckSandboxNetwork(sandbox("192.0.2.0/24", "192.0.2.1"), "", nodeNetworks), []string{"contains the node's own address 192.0.2.77 (on interface dummy0)", "ip -4 route"})
	if err := CheckSandboxNetwork(sandbox("192.0.2.128/25", "192.0.2.129"), "", NodeNetworks{Addresses: []NodeAddress{{Prefix: netip.MustParsePrefix("192.0.2.77/32"), Interface: "dummy0"}}}); err != nil {
		t.Fatalf("a range beside the address was refused: %v", err)
	}
}

// An address whose mask is wider than a route for it shows is a network as well.
func TestCheckSandboxNetworkReadsTheNetworkOfAnAddressWithoutARoute(t *testing.T) {
	nodeNetworks := NodeNetworks{Addresses: []NodeAddress{
		{Prefix: netip.MustParsePrefix("198.51.100.5/24"), Interface: "eth9"},
	}}
	assertRefusal(t, CheckSandboxNetwork(sandbox("198.51.100.128/25", "198.51.100.129"), "", nodeNetworks), []string{"overlaps the node's real network 198.51.100.0/24 (on interface eth9)"})
}

// A route and the address that made it are one network, named once.
func TestCheckSandboxNetworkNamesAConnectedNetworkOnce(t *testing.T) {
	err := CheckSandboxNetwork(sandbox("10.42.15.0/24", "10.42.15.250"), "", sampleNode())
	if err == nil {
		t.Fatal("accepted")
	}
	if got := strings.Count(err.Error(), "(on interface vmbr4)"); got != 1 {
		t.Errorf("the network is named %d times:\n%v", got, err)
	}
}

// A pre-provisioned sandbox exists already: its VNet's interface carries the
// range's route and the probe address, legitimately. An ephemeral one must not
// find the range on any interface yet; one that does is a leftover.
func TestCheckSandboxNetworkTreatsTheVNetsOwnInterface(t *testing.T) {
	nodeNetworks := sampleNode()
	nodeNetworks.Routes = append(nodeNetworks.Routes, NodeRoute{Destination: netip.MustParsePrefix("192.0.2.0/24"), Interface: "csVnet1"})
	nodeNetworks.Addresses = append(nodeNetworks.Addresses, NodeAddress{Prefix: netip.MustParsePrefix("192.0.2.1/24"), Interface: "csVnet1"})

	network := sandbox("192.0.2.0/24", "192.0.2.1")
	if err := CheckSandboxNetwork(network, "csVnet1", nodeNetworks); err != nil {
		t.Fatalf("a pre-provisioned VNet's own interface was refused: %v", err)
	}
	err := CheckSandboxNetwork(network, "", nodeNetworks)
	assertRefusal(t, err, []string{"overlaps the node's real network 192.0.2.0/24 (on interface csVnet1)", "the plan's own VNet", "certistack-node recover"})
	assertRefusal(t, err, []string{"network.probe_ip 192.0.2.1 is an address of the node itself (on interface csVnet1)"})
	if strings.Contains(err.Error(), "Choose a range") {
		t.Errorf("another range does not help when what is in the way is the plan's own leftover VNet: %v", err)
	}

	// Only the plan's own interface is ignored: the same range on another one is real.
	other := sampleNode()
	other.Routes = append(other.Routes, NodeRoute{Destination: netip.MustParsePrefix("192.0.2.0/24"), Interface: "vmbr9"})
	assertRefusal(t, CheckSandboxNetwork(network, "csVnet1", other), []string{"overlaps the node's real network 192.0.2.0/24 (on interface vmbr9)", "Choose a range"})
}

func TestCheckSandboxNetworkRefusesNothingWithoutARangeToJudge(t *testing.T) {
	// A plan that names no range has nothing to compare (plan validation refuses it).
	if err := CheckSandboxNetwork(config.Network{}, "", sampleNode()); err != nil {
		t.Errorf("a plan with no range: %v", err)
	}
	// A range that is named but cannot be read is not "nothing to judge" (review
	// R2-01): it has not been compared with anything, so it is refused.
	for _, network := range []config.Network{
		{IPRange: "not-a-cidr"},
		{IPRange: "fd00::/64", ProbeIP: "fd00::1"},
	} {
		if err := CheckSandboxNetwork(network, "", sampleNode()); err == nil || !strings.Contains(err.Error(), "network.ip_range") {
			t.Errorf("%+v: error = %v, want a refusal naming network.ip_range", network, err)
		}
	}
	// The legacy field names the same range.
	assertRefusal(t, CheckSandboxNetwork(config.Network{SubnetCIDR: "10.42.15.0/24", ProbeIP: "10.42.15.250"}, "", sampleNode()), []string{"overlaps the node's real network 10.42.15.0/24"})
}

// The routes the node cannot give are not a pass: the step says it could not
// check, with what to do by hand, and a refusal stays a refusal.
func TestVerifySandboxNetworkSaysItCouldNotCheck(t *testing.T) {
	network := sandbox("192.0.2.0/24", "192.0.2.1")
	warning, err := VerifySandboxNetwork(network, "", func() (NodeNetworks, error) {
		return NodeNetworks{}, errors.New("open /proc/net/route: permission denied")
	})
	if err != nil {
		t.Fatalf("an unreadable table refused the plan: %v", err)
	}
	for _, want := range []string{"could not check the node's routes", "permission denied", "192.0.2.0/24", "ip -4 route"} {
		if !strings.Contains(warning, want) {
			t.Errorf("warning lacks %q: %s", want, warning)
		}
	}

	warning, err = VerifySandboxNetwork(network, "", func() (NodeNetworks, error) { return sampleNode(), nil })
	if err != nil || warning != "" {
		t.Fatalf("a clean range: warning %q, error %v", warning, err)
	}
	warning, err = VerifySandboxNetwork(sandbox("10.42.15.0/24", "10.42.15.250"), "", func() (NodeNetworks, error) { return sampleNode(), nil })
	if err == nil || warning != "" {
		t.Fatalf("an overlapping range: warning %q, error %v", warning, err)
	}
	// A plan with no range is not this check's business and reads nothing.
	read := false
	warning, err = VerifySandboxNetwork(config.Network{}, "", func() (NodeNetworks, error) { read = true; return NodeNetworks{}, nil })
	if err != nil || warning != "" || read {
		t.Fatalf("no range: warning %q, error %v, read %v", warning, err, read)
	}
}

// procRoute renders one /proc/net/route row the way the kernel does: addresses
// as the host-order reading of their network-order bytes.
func procRoute(iface, destination string, bits int, gateway string) string {
	hexOf := func(a netip.Addr) string {
		b := a.As4()
		return fmt.Sprintf("%08X", binary.NativeEndian.Uint32(b[:]))
	}
	var maskBytes [4]byte
	for i := 0; i < bits; i++ {
		maskBytes[i/8] |= 0x80 >> (i % 8)
	}
	flags := "0001"
	gw := "00000000"
	if gateway != "" {
		flags, gw = "0003", hexOf(netip.MustParseAddr(gateway))
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s\t0\t0\t0\t%08X\t0\t0\t0\n", iface, hexOf(netip.MustParseAddr(destination)), gw, flags, binary.NativeEndian.Uint32(maskBytes[:]))
}

const procRouteHeader = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

func TestParseProcNetRoute(t *testing.T) {
	table := procRouteHeader +
		procRoute("vmbr0", "0.0.0.0", 0, "10.42.20.1") +
		procRoute("vmbr0", "10.42.20.0", 24, "") +
		procRoute("vmbr1", "10.42.10.0", 24, "") +
		procRoute("idrac", "169.254.0.0", 16, "") +
		procRoute("eth1", "172.31.5.4", 32, "10.42.20.254")
	routes, err := ParseProcNetRoute(strings.NewReader(table))
	if err != nil {
		t.Fatal(err)
	}
	want := []NodeRoute{
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.42.20.1"), Interface: "vmbr0"},
		{Destination: netip.MustParsePrefix("10.42.20.0/24"), Interface: "vmbr0"},
		{Destination: netip.MustParsePrefix("10.42.10.0/24"), Interface: "vmbr1"},
		{Destination: netip.MustParsePrefix("169.254.0.0/16"), Interface: "idrac"},
		{Destination: netip.MustParsePrefix("172.31.5.4/32"), Gateway: netip.MustParseAddr("10.42.20.254"), Interface: "eth1"},
	}
	if len(routes) != len(want) {
		t.Fatalf("routes = %+v, want %d", routes, len(want))
	}
	for i := range want {
		if routes[i] != want[i] {
			t.Errorf("route %d = %+v, want %+v", i, routes[i], want[i])
		}
	}
	// The header alone is an empty table, which is a table.
	if routes, err := ParseProcNetRoute(strings.NewReader(procRouteHeader)); err != nil || len(routes) != 0 {
		t.Errorf("header only: %v, %v", routes, err)
	}
}

// A table that cannot be read whole is not read at all: one row skipped could
// be the one that overlaps.
func TestParseProcNetRouteRefusesATableItCannotReadWhole(t *testing.T) {
	good := procRoute("vmbr0", "10.42.20.0", 24, "")
	for name, table := range map[string]string{
		"empty":                    "",
		"no header":                good,
		"short row":                procRouteHeader + "vmbr0\t0014000A\t00000000\n",
		"destination not hex":      procRouteHeader + "vmbr0\tZZZZZZZZ\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
		"gateway not hex":          procRouteHeader + "vmbr0\t0014000A\tnope\t0003\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
		"mask not hex":             procRouteHeader + "vmbr0\t0014000A\t00000000\t0001\t0\t0\t0\tZZ\t0\t0\t0\n",
		"mask not contiguous":      procRouteHeader + "vmbr0\t0014000A\t00000000\t0001\t0\t0\t0\t00FF00FF\t0\t0\t0\n",
		"good row after a bad one": procRouteHeader + "vmbr0\tZZZZZZZZ\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" + good,
	} {
		t.Run(name, func(t *testing.T) {
			if routes, err := ParseProcNetRoute(strings.NewReader(table)); err == nil {
				t.Fatalf("parsed %+v", routes)
			}
		})
	}
}

// The plan's own VNet is left out only where the node is expected to carry the
// range on it already.
func TestOwnVNetInterface(t *testing.T) {
	for _, tc := range []struct {
		name         string
		network      config.Network
		removedFirst []string
		want         string
	}{
		{"ephemeral, nothing left", config.Network{VNetID: "csVnet1"}, nil, ""},
		{"ephemeral, explicit", config.Network{VNetID: "csVnet1", Lifecycle: "ephemeral"}, nil, ""},
		{"ephemeral, another VNet is removed first", config.Network{VNetID: "csVnet1"}, []string{"csOther"}, ""},
		{"ephemeral, a recovery removes this VNet first", config.Network{VNetID: "csVnet1"}, []string{"csOther", "csvnet1"}, "csVnet1"},
		{"pre-provisioned", config.Network{VNetID: "csVnet1", Lifecycle: "preprovisioned"}, nil, "csVnet1"},
		{"pre-provisioned, any case", config.Network{VNetID: "csVnet1", Lifecycle: " PreProvisioned "}, nil, "csVnet1"},
		{"no VNet to name", config.Network{Lifecycle: "preprovisioned"}, []string{""}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := OwnVNetInterface(tc.network, tc.removedFirst...); got != tc.want {
				t.Errorf("OwnVNetInterface = %q, want %q", got, tc.want)
			}
		})
	}
}

// A network the table lists twice (two metrics, a route and a second route on
// another interface) is one network, named once.
func TestCheckSandboxNetworkNamesADuplicatedRouteOnce(t *testing.T) {
	nodeNetworks := NodeNetworks{Routes: []NodeRoute{
		{Destination: netip.MustParsePrefix("198.51.100.0/24"), Interface: "eth0"},
		{Destination: netip.MustParsePrefix("198.51.100.0/24"), Interface: "eth1"},
	}}
	err := CheckSandboxNetwork(sandbox("198.51.100.0/25", "198.51.100.1"), "", nodeNetworks)
	assertRefusal(t, err, []string{"overlaps the node's real network 198.51.100.0/24 (on interface eth0)"})
	if strings.Contains(err.Error(), "eth1") {
		t.Errorf("the same network is named twice:\n%v", err)
	}
}

// A blackhole or unreachable route has no interface; it is still a route over
// part of the range, and the table with one in it still reads.
func TestParseProcNetRouteReadsARouteWithoutAnInterface(t *testing.T) {
	row := "*\t0A0A0A0A\t00000000\t0201\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n"
	// The addresses of a row are in host order: render them as the kernel does.
	row = strings.Replace(row, "0A0A0A0A", procAddressText("10.10.10.10"), 1)
	row = strings.Replace(row, "FFFFFFFF", procAddressText("255.255.255.255"), 1)
	routes, err := ParseProcNetRoute(strings.NewReader(procRouteHeader + row))
	if err != nil || len(routes) != 1 || routes[0].Interface != "*" || routes[0].Destination != netip.MustParsePrefix("10.10.10.10/32") || routes[0].Gateway.IsValid() {
		t.Fatalf("routes = %+v, err = %v", routes, err)
	}
	assertRefusal(t, CheckSandboxNetwork(sandbox("10.10.10.0/24", "10.10.10.1"), "", NodeNetworks{Routes: routes}), []string{"overlaps the node's real network 10.10.10.10/32 (on interface *)"})
}

func procAddressText(address string) string {
	b := netip.MustParseAddr(address).As4()
	return fmt.Sprintf("%08X", binary.NativeEndian.Uint32(b[:]))
}
