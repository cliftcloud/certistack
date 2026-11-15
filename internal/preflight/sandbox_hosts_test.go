// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// Review R2-06. The check compared the range with the node's main routing table
// and its own addresses only. Four more things go into the sandbox once the
// probe address is on its bridge, and each is judged with a message of its own:
// the routes of the node's other routing tables (Tailscale keeps its subnet
// routes in table 52), the address the SSH session reaches the node from, the
// DNS servers of /etc/resolv.conf, and the VXLAN peers of the plan's zone.

// A route in another routing table is a real network of the node: the sandbox
// range must not overlap it, and the message names the table.
func TestCheckSandboxNetworkJudgesTheRoutesOfOtherRoutingTables(t *testing.T) {
	node := sampleNode()
	node.Routes = append(node.Routes,
		NodeRoute{Destination: netip.MustParsePrefix("192.168.1.0/24"), Interface: "tailscale0", Table: "52"},
		NodeRoute{Destination: netip.MustParsePrefix("100.64.0.0/10"), Interface: "tailscale0", Table: "52"},
	)
	err := CheckSandboxNetwork(sandbox("192.168.1.0/24", "192.168.1.1"), "", node)
	assertRefusal(t, err, []string{"overlaps the node's real network 192.168.1.0/24 (on interface tailscale0, routing table 52)", "ip route show table all"})
	// A range beside it is fine, and a route of the main table says no table.
	if err := CheckSandboxNetwork(sandbox("192.0.2.0/24", "192.0.2.1"), "", node); err != nil {
		t.Errorf("a range beside the other table's routes was refused: %v", err)
	}
	err = CheckSandboxNetwork(sandbox("10.42.15.0/24", "10.42.15.250"), "", node)
	if err == nil || strings.Contains(err.Error(), "routing table") {
		t.Errorf("a main-table route is described as being in a routing table: %v", err)
	}
}

// The address the SSH session reaches the node from: with the probe address on
// the bridge the node would send the replies of that session into the sandbox.
func TestCheckSandboxNetworkRefusesARangeHoldingTheSSHClient(t *testing.T) {
	node := sampleNode()
	node.Held = []HeldAddress{{Address: netip.MustParseAddr("198.51.100.7"), Kind: HeldSSHClient}}
	err := CheckSandboxNetwork(sandbox("198.51.100.0/24", "198.51.100.200"), "", node)
	assertRefusal(t, err, []string{
		"network.ip_range 198.51.100.0/24 contains 198.51.100.7",
		"SSH",
		"replies",
		"controller",
		"192.0.2.0/24",
	})
	if err := CheckSandboxNetwork(sandbox("192.0.2.0/24", "192.0.2.1"), "", node); err != nil {
		t.Errorf("a range beside the SSH client's address was refused: %v", err)
	}
}

func TestCheckSandboxNetworkRefusesARangeHoldingADNSServer(t *testing.T) {
	node := sampleNode()
	node.Held = []HeldAddress{
		{Address: netip.MustParseAddr("198.51.100.53"), Kind: HeldDNSServer},
		{Address: netip.MustParseAddr("203.0.113.53"), Kind: HeldDNSServer},
	}
	err := CheckSandboxNetwork(sandbox("198.51.100.0/24", "198.51.100.200"), "", node)
	assertRefusal(t, err, []string{"network.ip_range 198.51.100.0/24 contains 198.51.100.53", "DNS server", "/etc/resolv.conf", "name lookups"})
	if err != nil && strings.Contains(err.Error(), "203.0.113.53") {
		t.Errorf("a DNS server outside the range is named: %v", err)
	}
}

func TestCheckSandboxNetworkRefusesARangeHoldingAVXLANPeer(t *testing.T) {
	network := sandbox("198.51.100.0/24", "198.51.100.200")
	network.Mode, network.Peers = "vxlan", "203.0.113.9, 198.51.100.9"
	err := CheckSandboxNetwork(network, "", sampleNode())
	assertRefusal(t, err, []string{"network.ip_range 198.51.100.0/24 contains 198.51.100.9", "VXLAN peer", "network.peers", "tunnel"})
	if err != nil && strings.Contains(err.Error(), "203.0.113.9") {
		t.Errorf("a peer outside the range is named: %v", err)
	}
	network.Peers = "203.0.113.9,203.0.113.10"
	if err := CheckSandboxNetwork(network, "", sampleNode()); err != nil {
		t.Errorf("peers outside the range were refused: %v", err)
	}
	// Peers of a simple zone are not a thing: only vxlan mode reads them.
	network.Mode, network.Peers = "simple", "198.51.100.9"
	if err := CheckSandboxNetwork(network, "", sampleNode()); err != nil {
		t.Errorf("peers of a simple zone were judged: %v", err)
	}
}

// Every kind of finding is its own sentence, and the output stays bounded.
func TestCheckSandboxNetworkKeepsTheMessageBounded(t *testing.T) {
	node := sampleNode()
	for i := 1; i <= 40; i++ {
		node.Held = append(node.Held, HeldAddress{Address: netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), Kind: HeldDNSServer})
	}
	for i := 1; i <= 40; i++ {
		node.Routes = append(node.Routes, NodeRoute{Destination: netip.MustParsePrefix("198.51.100.0/24"), Interface: "tailscale0", Table: "52"})
	}
	network := sandbox("198.51.100.0/24", "198.51.100.250")
	network.Mode = "vxlan"
	peers := make([]string, 0, 40)
	for i := 100; i < 140; i++ {
		peers = append(peers, fmt.Sprintf("198.51.100.%d", i))
	}
	network.Peers = strings.Join(peers, ",")
	err := CheckSandboxNetwork(network, "", node)
	if err == nil {
		t.Fatal("accepted")
	}
	if len(err.Error()) > 2500 {
		t.Errorf("the refusal is %d bytes long: %s", len(err.Error()), err)
	}
	assertRefusal(t, err, []string{"and 37 more"})
}

// The output of `ip -4 -o route show table all`: routes of tables other than
// main and local, parsed per line, with a line that cannot be read counted
// against its table instead of discarding the rest.
func TestParseIPRouteTables(t *testing.T) {
	output := strings.Join([]string{
		"default via 10.42.20.1 dev vmbr0 proto kernel onlink",
		"10.42.20.0/24 dev vmbr0 proto kernel scope link src 10.42.20.36",
		"192.168.1.0/24 dev tailscale0 table 52 proto kernel scope link",
		"100.64.0.0/10 dev tailscale0 table 52",
		"default via 10.8.0.1 dev tun0 table 200",
		"blackhole 198.51.100.0/24 table 201",
		"198.51.100.77 via 10.42.20.9 dev vmbr0 table 202",
		"throw 203.0.113.0/24 table 52",
		"broadcast 10.42.20.255 dev vmbr0 table local proto kernel scope link src 10.42.20.36",
		"local 10.42.20.36 dev vmbr0 table local proto kernel scope host src 10.42.20.36",
		"local 127.0.0.0/8 dev lo table 255 proto kernel scope host src 127.0.0.1",
		"192.0.2.0/24 dev eth9 table main",
		"not-an-address dev eth5 table 99",
		"10.89.0.0/33 dev eth5 table 99",
		"",
	}, "\n")
	routes, unread := ParseIPRouteTables(output)
	want := []NodeRoute{
		{Destination: netip.MustParsePrefix("192.168.1.0/24"), Interface: "tailscale0", Table: "52"},
		{Destination: netip.MustParsePrefix("100.64.0.0/10"), Interface: "tailscale0", Table: "52"},
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.8.0.1"), Interface: "tun0", Table: "200"},
		{Destination: netip.MustParsePrefix("198.51.100.0/24"), Table: "201"},
		{Destination: netip.MustParsePrefix("198.51.100.77/32"), Gateway: netip.MustParseAddr("10.42.20.9"), Interface: "vmbr0", Table: "202"},
	}
	if len(routes) != len(want) {
		t.Fatalf("routes = %+v, want %+v", routes, want)
	}
	for i := range want {
		if routes[i] != want[i] {
			t.Errorf("route %d = %+v, want %+v", i, routes[i], want[i])
		}
	}
	if len(unread) != 1 || !strings.Contains(unread[0], "routing table 99") || !strings.Contains(unread[0], "2 line") {
		t.Errorf("unread = %q, want one entry that names routing table 99 and its 2 lines", unread)
	}
}

// A route with no interface (a blackhole) is described as such, not as being
// on an interface named *.
func TestCheckSandboxNetworkDescribesARouteWithNoInterface(t *testing.T) {
	node := NodeNetworks{Routes: []NodeRoute{{Destination: netip.MustParsePrefix("198.51.100.0/24"), Table: "201"}}}
	err := CheckSandboxNetwork(sandbox("198.51.100.0/25", "198.51.100.1"), "", node)
	assertRefusal(t, err, []string{"overlaps the node's real network 198.51.100.0/24 (a route with no interface, routing table 201)"})
	if err != nil && strings.Contains(err.Error(), "interface )") {
		t.Errorf("an empty interface name is printed: %v", err)
	}
}

// What the node could not be read for is a check that was not made in full: a
// warning that names the part, after the part that was read has been judged
// (an overlap found in it is a refusal, whatever else could not be read).
func TestVerifySandboxNetworkSaysWhichPartsCouldNotBeRead(t *testing.T) {
	partial := sampleNode()
	partial.Unread = []string{"routing table 99 (2 lines could not be read)", "the DNS servers of /etc/resolv.conf (open /etc/resolv.conf: permission denied)"}
	warning, err := VerifySandboxNetwork(sandbox("192.0.2.0/24", "192.0.2.1"), "", func() (NodeNetworks, error) { return partial, nil })
	if err != nil {
		t.Fatalf("a partial read refused the plan: %v", err)
	}
	for _, want := range []string{"could not check", "routing table 99", "/etc/resolv.conf", "192.0.2.0/24", "ip route show table all"} {
		if !strings.Contains(warning, want) {
			t.Errorf("warning lacks %q: %s", want, warning)
		}
	}
	if warning, err = VerifySandboxNetwork(sandbox("10.42.15.0/24", "10.42.15.250"), "", func() (NodeNetworks, error) { return partial, nil }); err == nil || warning != "" {
		t.Errorf("an overlap in the part that was read: warning %q, error %v", warning, err)
	}
}

// The addresses the node needs are read from where they are kept.
func TestParseResolvConfNameservers(t *testing.T) {
	text := "# Generated by NetworkManager\nsearch example.test\nnameserver 198.51.100.53\nnameserver 127.0.0.53\nnameserver fd00::53\nnameserver   203.0.113.53   \n;nameserver 192.0.2.1\nnameserver not-an-address\noptions edns0\nnameserver 198.51.100.53\n"
	got := ParseResolvConfNameservers(text)
	want := []netip.Addr{netip.MustParseAddr("198.51.100.53"), netip.MustParseAddr("203.0.113.53")}
	if len(got) != len(want) {
		t.Fatalf("nameservers = %v, want %v (IPv4, not loopback, once each)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("nameserver %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestParseSSHConnectionGivesTheClientAddress(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"198.51.100.7 51234 192.0.2.10 22", "198.51.100.7"},
		{"  198.51.100.7 51234 192.0.2.10 22\n", "198.51.100.7"},
		{"::ffff:198.51.100.7 51234 192.0.2.10 22", "198.51.100.7"},
		{"2001:db8::7 51234 2001:db8::10 22", ""}, // IPv6 is not a sandbox's business
		{"", ""},
		{"not-an-address 1 2 3", ""},
		{"198.51.100.7", "198.51.100.7"},
		{"0.0.0.0 1 2 3", ""},
	} {
		got := ""
		if addr, ok := ParseSSHConnection(tc.in); ok {
			got = addr.String()
		}
		if got != tc.want {
			t.Errorf("ParseSSHConnection(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
