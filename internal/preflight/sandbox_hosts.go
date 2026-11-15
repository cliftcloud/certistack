// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
)

// HeldKind says why an address of someone else matters to the node: it is
// reached through the network the sandbox range would take over.
type HeldKind string

const (
	// HeldSSHClient is the address the SSH session that started the work reaches
	// the node from (the controller). With the probe address on the sandbox
	// bridge, the replies of that session would go into the sandbox.
	HeldSSHClient HeldKind = "ssh-client"
	// HeldDNSServer is a name server of /etc/resolv.conf.
	HeldDNSServer HeldKind = "dns-server"
)

// HeldAddress is an address the node reaches something it needs at.
type HeldAddress struct {
	Address netip.Addr
	Kind    HeldKind
}

// maxHeldAddresses bounds what is kept of one source: a resolv.conf names a few
// name servers, and a file that names thousands is not one to judge them all of.
const maxHeldAddresses = 8

// sshClient is the address the controller's SSH session reaches this node from,
// as the controller told this worker (SetSSHClient). A worker is started under
// sudo or as a transient service, and neither keeps SSH_CONNECTION, so the
// controller reads it in its own session and passes it on; where it is not told,
// the worker's own SSH_CONNECTION is read (a root login, an interactive shell).
var (
	sshClientMu sync.Mutex
	sshClient   string
)

// SetSSHClient records the address the controller's SSH session reaches this
// node from. An empty or unreadable text leaves the address unknown.
func SetSSHClient(text string) {
	sshClientMu.Lock()
	defer sshClientMu.Unlock()
	sshClient = strings.TrimSpace(text)
}

// SSHClientAddress is the address the SSH session that started this work reaches
// the node from (told by the controller, else SSH_CONNECTION), if it is known and IPv4.
func SSHClientAddress() (netip.Addr, bool) {
	sshClientMu.Lock()
	told := sshClient
	sshClientMu.Unlock()
	if addr, ok := ParseSSHConnection(told); ok {
		return addr, true
	}
	return ParseSSHConnection(os.Getenv("SSH_CONNECTION"))
}

// ParseSSHConnection reads the client address from the text of SSH_CONNECTION
// ("client_ip client_port server_ip server_port") or from a bare address. An
// IPv6 client, a loopback or unspecified one, and anything that is not an
// address are not a sandbox's business: false.
func ParseSSHConnection(text string) (netip.Addr, bool) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(fields[0])
	if err != nil {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}

// ParseResolvConfNameservers reads the IPv4 name servers of a resolv.conf, each
// once, in order, leaving out loopback ones (a local stub resolver is the node
// itself) and keeping at most maxHeldAddresses.
func ParseResolvConfNameservers(text string) []netip.Addr {
	var servers []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() || seen[addr] {
			continue
		}
		seen[addr] = true
		servers = append(servers, addr)
		if len(servers) == maxHeldAddresses {
			break
		}
	}
	return servers
}

// ignoredRoutingTable is a routing table whose routes are not networks the node
// reaches: the main table is read from /proc/net/route, and the local table
// holds the node's own and broadcast addresses, which the interface addresses
// already give.
func ignoredRoutingTable(table string) bool {
	switch table {
	case "main", "254", "local", "255", "default", "253", "unspec", "0":
		return true
	}
	return false
}

// ParseIPRouteTables reads the output of `ip -4 -o route show table all` for
// the routes of the routing tables other than main and local (Tailscale keeps
// the subnet routes of its peers in table 52, a VPN or a policy route in its
// own). It is lenient per line: a route it cannot read is counted against its
// table, and the entry in unread names the table and how many lines were lost,
// so that one bad table does not discard the others and is not taken for an
// empty one.
func ParseIPRouteTables(output string) (routes []NodeRoute, unread []string) {
	failed := map[string]int{}
	var order []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		table := ""
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "table" {
				table = fields[i+1]
			}
		}
		if len(fields) == 0 || table == "" || ignoredRoutingTable(table) {
			continue
		}
		route, keep, ok := parseIPRouteLine(fields)
		switch {
		case !ok:
			if failed[table] == 0 {
				order = append(order, table)
			}
			failed[table]++
		case keep:
			route.Table = table
			routes = append(routes, route)
		}
	}
	for _, table := range order {
		lines := "lines"
		if failed[table] == 1 {
			lines = "line"
		}
		unread = append(unread, fmt.Sprintf("routing table %s (%d %s could not be read)", table, failed[table], lines))
	}
	return routes, unread
}

// parseIPRouteLine reads one route of `ip -o route`. keep is false for a route
// that holds no network of the node's (a local or broadcast entry, a "throw",
// an IPv6 route); ok is false for a line that cannot be read.
func parseIPRouteLine(fields []string) (route NodeRoute, keep, ok bool) {
	routeType := "unicast"
	i := 0
	switch fields[0] {
	case "unicast", "blackhole", "unreachable", "prohibit", "throw", "local", "broadcast", "anycast", "multicast", "nat":
		routeType = fields[0]
		i = 1
	}
	if i >= len(fields) {
		return NodeRoute{}, false, false
	}
	switch routeType {
	case "local", "broadcast", "anycast", "multicast", "throw", "nat":
		return NodeRoute{}, false, true
	}
	destination := fields[i]
	switch {
	case destination == "default":
		route.Destination = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	case strings.Contains(destination, ":"):
		return NodeRoute{}, false, true // IPv6 is not a sandbox's business
	case strings.Contains(destination, "/"):
		prefix, err := netip.ParsePrefix(destination)
		if err != nil || !prefix.Addr().Is4() {
			return NodeRoute{}, false, false
		}
		route.Destination = prefix.Masked()
	default:
		addr, err := netip.ParseAddr(destination)
		if err != nil || !addr.Is4() {
			return NodeRoute{}, false, false
		}
		route.Destination = netip.PrefixFrom(addr, 32)
	}
	for j := i + 1; j+1 < len(fields); j++ {
		switch fields[j] {
		case "via":
			if gateway, err := netip.ParseAddr(fields[j+1]); err == nil && gateway.Is4() {
				route.Gateway = gateway
			}
		case "dev":
			route.Interface = fields[j+1]
		}
	}
	return route, true, true
}
