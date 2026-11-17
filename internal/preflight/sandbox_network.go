// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/pkg/config"
)

// SandboxNetworkCheckName names the check that the sandbox range overlaps none
// of the node's real networks.
const SandboxNetworkCheckName = "sandbox_network"

// NodeRoute is one route of one of the node's IPv4 routing tables.
type NodeRoute struct {
	Destination netip.Prefix
	// Gateway is the next hop, or the zero Addr for a connected route.
	Gateway netip.Addr
	// Interface is the interface the route leaves by, or "" for a route with
	// none (a blackhole, an unreachable route).
	Interface string
	// Table is the routing table the route is in when it is not the main table
	// (a number or a name, "52" for Tailscale's routes), "" for the main table.
	Table string
}

// NodeAddress is one IPv4 address configured on one of the node's interfaces,
// with the mask it was configured with.
type NodeAddress struct {
	Prefix    netip.Prefix
	Interface string
}

// NodeNetworks is what the node uses its IPv4 networks for: the routes of its
// routing tables (the main table and, where they could be read, the others) and
// the addresses of all its interfaces, and the addresses of others that it
// reaches something at.
type NodeNetworks struct {
	Routes    []NodeRoute
	Addresses []NodeAddress
	// Held are the addresses the node needs to reach, which a sandbox range
	// must not contain: the SSH client's, the DNS servers'.
	Held []HeldAddress
	// Unread names each part that could not be read in full (a routing table
	// the node would not list, a resolv.conf it would not open). Everything else
	// was read and judged; a check that has any is not a complete pass.
	Unread []string
}

// ParseProcNetRoute reads the routes /proc/net/route lists: the node's main
// IPv4 routing table. A table it cannot read whole is an error and no routes:
// the row it skipped could be the one that overlaps.
func ParseProcNetRoute(r io.Reader) ([]NodeRoute, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read the routing table: %w", err)
		}
		return nil, errors.New("the routing table is empty (not even its header line)")
	}
	header := strings.Fields(scanner.Text())
	if len(header) < 8 || header[0] != "Iface" || header[1] != "Destination" || header[2] != "Gateway" || header[7] != "Mask" {
		return nil, errors.New("the routing table does not start with the header line Iface, Destination, Gateway, ..., Mask")
	}
	var routes []NodeRoute
	for line := 2; scanner.Scan(); line++ {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 8 {
			return nil, fmt.Errorf("routing table line %d has %d columns, not the 8 or more that name a route", line, len(fields))
		}
		destination, err := procAddress(fields[1])
		if err != nil {
			return nil, fmt.Errorf("routing table line %d: destination: %w", line, err)
		}
		gateway, err := procAddress(fields[2])
		if err != nil {
			return nil, fmt.Errorf("routing table line %d: gateway: %w", line, err)
		}
		mask, err := procAddress(fields[7])
		if err != nil {
			return nil, fmt.Errorf("routing table line %d: mask: %w", line, err)
		}
		inverse := ^binary.BigEndian.Uint32(mask.AsSlice())
		if inverse&(inverse+1) != 0 {
			return nil, fmt.Errorf("routing table line %d: mask %s is not a network mask", line, mask)
		}
		route := NodeRoute{Destination: netip.PrefixFrom(destination, 32-bits.OnesCount32(inverse)).Masked(), Interface: fields[0]}
		if gateway != netip.IPv4Unspecified() {
			route.Gateway = gateway
		}
		routes = append(routes, route)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read the routing table: %w", err)
	}
	return routes, nil
}

// procAddress reads an address as /proc/net/route writes it: eight hex digits
// holding the network-order bytes as the host reads a 32-bit word.
func procAddress(text string) (netip.Addr, error) {
	if len(text) != 8 {
		return netip.Addr{}, fmt.Errorf("%q is not eight hex digits", text)
	}
	word, err := strconv.ParseUint(text, 16, 32)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not eight hex digits", text)
	}
	var octets [4]byte
	binary.NativeEndian.PutUint32(octets[:], uint32(word))
	return netip.AddrFrom4(octets), nil
}

// sandboxPrefix is the sandbox range the plan names, as its network. present is
// false only when the plan names no range at all (plan validation refuses
// that). A range that is named but that config.ParseSandboxRange refuses (the
// one reader of the text, shared with plan validation and the engine) is an
// error, never "nothing to judge": a range this check cannot read is a range it
// has not checked.
func sandboxPrefix(network config.Network) (prefix netip.Prefix, present bool, err error) {
	text := network.IPRange
	if text == "" {
		text = network.SubnetCIDR
	}
	if text == "" {
		return netip.Prefix{}, false, nil
	}
	prefix, err = config.ParseSandboxRange(text)
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf("network.ip_range %w (the range was not compared with the node's networks)", err)
	}
	return prefix, true, nil
}

// OwnVNetInterface is the interface whose routes and addresses CheckSandboxNetwork
// leaves out: the plan's own VNet when the node is expected to carry the range
// on it. That is a pre-provisioned sandbox (the zone and VNet exist, and the
// probe address lives there), and an ephemeral one whose VNet an earlier run left
// and a recovery removes first (removedFirst names the VNets it removes). For any
// other sandbox no interface carries the range yet.
func OwnVNetInterface(network config.Network, removedFirst ...string) string {
	if network.VNetID == "" {
		return ""
	}
	if network.EffectiveLifecycle() == "preprovisioned" {
		return network.VNetID
	}
	for _, id := range removedFirst {
		if strings.EqualFold(id, network.VNetID) {
			return network.VNetID
		}
	}
	return ""
}

// chooseAnotherRange tells the reader to pick another range, naming a
// documentation range other than the plan's own as the example.
func chooseAnotherRange(planRange string) string {
	if example := config.SuggestedDocumentationRange(planRange, nil); example != "" {
		return "Choose a range the node does not use, for example " + example + " (a documentation range, as the examples use) or another unused private range; list the node's networks with `ip -4 route`."
	}
	return "Choose a range the node does not use, such as an unused private range; list the node's networks with `ip -4 route`."
}

// forExample is ", for example <range>" with a documentation range other than
// the plan's own that holds none of avoid, or "" when none is left.
func forExample(planRange string, avoid []netip.Addr) string {
	var peers []string
	for _, a := range avoid {
		peers = append(peers, a.String())
	}
	if example := config.SuggestedDocumentationRange(planRange, peers); example != "" {
		return ", for example " + example
	}
	return ""
}

// CheckSandboxNetwork refuses a sandbox network that would take over part of
// the node's real network: a range that overlaps (equals, contains, or lies
// inside) a network of the node's main routing table other than the default
// route, a network an interface address of the node belongs to, or that
// holds a gateway the node's routes go through, or a probe address that is an
// address of the node. Once the probe address is on the sandbox bridge the
// node has a connected route for the whole range, and the traffic of the real
// network it overlaps goes into the sandbox. ignoreInterface, when set, is an
// interface whose routes and addresses are not the node's real networks: the
// plan's own VNet when it is pre-provisioned (its probe address lives there).
func CheckSandboxNetwork(network config.Network, ignoreInterface string, nodeNetworks NodeNetworks) error {
	sandbox, ok, err := sandboxPrefix(network)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	skip := func(iface string) bool { return ignoreInterface != "" && iface == ignoreInterface }

	type overlap struct {
		prefix netip.Prefix
		iface  string
		table  string
	}
	var (
		networks       []overlap
		seenNetwork    = map[netip.Prefix]bool{}
		gateways       []string // the clause for each gateway inside the range
		seenGateway    = map[netip.Addr]bool{}
		ownAddresses   []string
		interfacesUsed []string
	)
	addNetwork := func(prefix netip.Prefix, iface, table string) {
		prefix = prefix.Masked()
		if seenNetwork[prefix] {
			return
		}
		seenNetwork[prefix] = true
		networks = append(networks, overlap{prefix, iface, table})
		interfacesUsed = append(interfacesUsed, iface)
	}
	addGateway := func(gateway netip.Addr, clause string) {
		if seenGateway[gateway] {
			return
		}
		seenGateway[gateway] = true
		gateways = append(gateways, clause)
	}
	for _, route := range nodeNetworks.Routes {
		if skip(route.Interface) {
			continue
		}
		if route.Gateway.IsValid() && sandbox.Contains(route.Gateway) {
			if isDefaultRoute(route.Destination) {
				addGateway(route.Gateway, fmt.Sprintf("contains the node's default gateway %s", route.Gateway))
			} else {
				addGateway(route.Gateway, fmt.Sprintf("contains the gateway %s of the node's route to %s", route.Gateway, route.Destination))
			}
		}
		// The default route holds every address: it is what the node reaches
		// the rest of the network by, not a network of its own.
		if isDefaultRoute(route.Destination) {
			continue
		}
		if route.Destination.Overlaps(sandbox) {
			addNetwork(route.Destination, route.Interface, route.Table)
		}
	}
	for _, address := range nodeNetworks.Addresses {
		// Loopback is plan validation's: it refuses a range that overlaps it.
		if skip(address.Interface) || address.Prefix.Addr().IsLoopback() {
			continue
		}
		if address.Prefix.Bits() == 32 {
			if sandbox.Contains(address.Prefix.Addr()) {
				ownAddresses = append(ownAddresses, fmt.Sprintf("contains the node's own address %s (on interface %s)", address.Prefix.Addr(), address.Interface))
				interfacesUsed = append(interfacesUsed, address.Interface)
			}
		} else if address.Prefix.Masked().Overlaps(sandbox) {
			addNetwork(address.Prefix, address.Interface, "")
		}
	}

	var clauses []string
	switch {
	case len(networks) == 1:
		clauses = append(clauses, fmt.Sprintf("overlaps the node's real network %s (%s)", networks[0].prefix, routeWhere(networks[0].iface, networks[0].table)))
	case len(networks) > 1:
		listed := make([]string, 0, 3)
		for _, n := range networks[:min(len(networks), 3)] {
			listed = append(listed, fmt.Sprintf("%s (%s)", n.prefix, routeWhere(n.iface, n.table)))
		}
		list := strings.Join(listed, ", ")
		if more := len(networks) - len(listed); more > 0 {
			list += fmt.Sprintf(" and %d more", more)
		} else if len(listed) > 1 {
			last := len(listed) - 1
			list = strings.Join(listed[:last], ", ") + " and " + listed[last]
		}
		clauses = append(clauses, "overlaps the node's real networks "+list)
	}
	clauses = append(clauses, gateways...)
	clauses = append(clauses, ownAddresses...)

	var message []string
	if len(clauses) > 0 {
		// What goes into the sandbox once the probe address is on its bridge:
		// the traffic of what the range holds.
		what := "that traffic"
		switch {
		case len(networks) == 1 && len(gateways) == 0 && len(ownAddresses) == 0:
			what = networks[0].prefix.String() + "'s traffic"
		case len(networks) > 1 && len(gateways) == 0 && len(ownAddresses) == 0:
			what = "their traffic"
		case len(networks) == 0 && len(ownAddresses) == 0:
			what = "its traffic through that gateway"
		case len(networks) == 0 && len(gateways) == 0:
			what = "the traffic for that address"
		}
		lost := ""
		if len(gateways) > 0 {
			lost = ", and lose its way out of this network"
		}
		sentence := fmt.Sprintf("network.ip_range %s %s: once the probe address is on the sandbox bridge, the node would route %s into the sandbox%s.", sandbox, strings.Join(clauses, " and "), what, lost)
		// The plan's own VNet, found with the range already on it, is what a
		// run that did not finish left: another range does not help, and
		// removing what the run left does.
		ownVNet, elsewhere := false, false
		for _, iface := range interfacesUsed {
			if network.VNetID != "" && iface == network.VNetID {
				ownVNet = true
			} else {
				elsewhere = true
			}
		}
		if ownVNet {
			sentence += fmt.Sprintf(" Interface %s is the plan's own VNet, so a run that did not finish probably left it. Recovery removes what a run left: "+recoverhint.Recover+". Then check again.", network.VNetID)
		}
		if !ownVNet || elsewhere {
			sentence += " " + chooseAnotherRange(network.IPRange)
		}
		for _, n := range networks {
			if n.table != "" {
				sentence += " Routes of the node's other routing tables are listed by `ip route show table all`."
				break
			}
		}
		message = append(message, sentence)
	}
	message = append(message, heldAddressMessages(network, sandbox, nodeNetworks.Held)...)
	if network.ProbeIP != "" {
		if probe, err := netip.ParseAddr(network.ProbeIP); err != nil {
			// Never "nothing to judge": an address that cannot be read has not been
			// compared with the node's own.
			message = append(message, fmt.Sprintf("network.probe_ip %q is not an IP address, so it was not compared with the node's addresses: write it as an unused IPv4 address inside network.ip_range %s.", network.ProbeIP, sandbox))
		} else {
			probe = probe.Unmap()
			for _, address := range nodeNetworks.Addresses {
				if skip(address.Interface) || address.Prefix.Addr().IsLoopback() || address.Prefix.Addr() != probe {
					continue
				}
				message = append(message, fmt.Sprintf("network.probe_ip %s is an address of the node itself (on interface %s): the probe address is added to the sandbox bridge, so it must be an address the node does not already have. Choose an unused address inside network.ip_range %s.", probe, address.Interface, sandbox))
				break
			}
		}
	}
	if len(message) == 0 {
		return nil
	}
	return errors.New(strings.Join(message, " "))
}

// isDefaultRoute is whether a route's destination is the default route: all of
// IPv4, or one of the two halves (0.0.0.0/1, 128.0.0.0/1) a VPN client installs
// in its place. A /1 is no network anyone has.
func isDefaultRoute(destination netip.Prefix) bool { return destination.Bits() <= 1 }

// routeWhere says where a route is: the interface it leaves by and, outside the
// main table, its routing table. A route with no interface (a blackhole) says so
// instead of naming an interface that is not there.
func routeWhere(iface, table string) string {
	where := "on interface " + iface
	if iface == "" {
		where = "a route with no interface"
	}
	if table != "" {
		where += ", routing table " + table
	}
	return where
}

// listAddresses names up to three of addrs, with how many more there are.
func listAddresses(addrs []netip.Addr) string {
	shown := make([]string, 0, 3)
	for _, addr := range addrs[:min(len(addrs), 3)] {
		shown = append(shown, addr.String())
	}
	switch {
	case len(addrs) > len(shown):
		return fmt.Sprintf("%s and %d more", strings.Join(shown, ", "), len(addrs)-len(shown))
	case len(shown) > 1:
		return strings.Join(shown[:len(shown)-1], ", ") + " and " + shown[len(shown)-1]
	}
	return shown[0]
}

// heldAddressMessages judge the addresses of others that the node reaches
// something at, each kind with a message of its own: the SSH client the work was
// started from, the DNS servers of /etc/resolv.conf, and the VXLAN peers of the
// plan's zone. Once the probe address is on the sandbox bridge the node has a
// connected route for the whole range, so traffic to an address inside it goes
// into the sandbox.
func heldAddressMessages(network config.Network, sandbox netip.Prefix, held []HeldAddress) []string {
	var sshClients, dnsServers, peers []netip.Addr
	for _, h := range held {
		if !h.Address.Is4() || !sandbox.Contains(h.Address) {
			continue
		}
		switch h.Kind {
		case HeldSSHClient:
			sshClients = append(sshClients, h.Address)
		case HeldDNSServer:
			dnsServers = append(dnsServers, h.Address)
		}
	}
	if strings.EqualFold(strings.TrimSpace(network.Mode), "vxlan") {
		for _, text := range strings.Split(network.Peers, ",") {
			if peer, err := netip.ParseAddr(strings.TrimSpace(text)); err == nil {
				if peer = peer.Unmap(); peer.Is4() && sandbox.Contains(peer) {
					peers = append(peers, peer)
				}
			}
		}
	}
	var messages []string
	if len(sshClients) > 0 {
		messages = append(messages, fmt.Sprintf("network.ip_range %s contains %s, the address this SSH session reaches the node from (the controller): once the probe address is on the sandbox bridge, the node would send the replies of the SSH connection into the sandbox and the controller would lose the node. Choose a range that does not contain it%s.", sandbox, listAddresses(sshClients), forExample(network.IPRange, sshClients)))
	}
	if len(dnsServers) > 0 {
		what := "a DNS server"
		if len(dnsServers) > 1 {
			what = "DNS servers"
		}
		messages = append(messages, fmt.Sprintf("network.ip_range %s contains %s, %s in /etc/resolv.conf: once the probe address is on the sandbox bridge, the node would send its name lookups to them into the sandbox. Choose a range that does not contain them%s.", sandbox, listAddresses(dnsServers), what, forExample(network.IPRange, dnsServers)))
	}
	if len(peers) > 0 {
		what := "a VXLAN peer"
		if len(peers) > 1 {
			what = "VXLAN peers"
		}
		messages = append(messages, fmt.Sprintf("network.ip_range %s contains %s, %s in network.peers: once the probe address is on the sandbox bridge, the node's tunnel to it would run into the sandbox instead of the cluster network. Choose a range that holds no peer%s.", sandbox, listAddresses(peers), what, forExample(network.IPRange, peers)))
	}
	return messages
}

// VerifySandboxNetwork is CheckSandboxNetwork with the node's networks read by
// read. When they cannot be read nothing was checked: the warning says so, and
// what to do by hand, and is never a pass. A plan with no range to judge reads
// nothing.
func VerifySandboxNetwork(network config.Network, ignoreInterface string, read func() (NodeNetworks, error)) (warning string, err error) {
	sandbox, ok, err := sandboxPrefix(network)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	nodeNetworks, readErr := read()
	if readErr != nil {
		return fmt.Sprintf("could not check the node's routes (%v): network.ip_range %s was not compared with the networks the node really uses. Before you run, list them with `ip -4 route` on the node and confirm that none overlaps %s.", readErr, sandbox, sandbox), nil
	}
	if err := CheckSandboxNetwork(network, ignoreInterface, nodeNetworks); err != nil {
		return "", err // an overlap in the part that was read outweighs what was not
	}
	if len(nodeNetworks.Unread) > 0 {
		return fmt.Sprintf("could not check the node's routes in full (%s): network.ip_range %s was not compared with them. Before you run, list the node's routes with `ip route show table all` and its addresses with `ip -4 -o address` on the node and confirm that none overlaps %s.", strings.Join(nodeNetworks.Unread, "; "), sandbox, sandbox), nil
	}
	return "", nil
}
