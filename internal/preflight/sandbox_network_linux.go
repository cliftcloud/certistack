// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"time"
)

// procNetRoute is the kernel's listing of the main IPv4 routing table.
const procNetRoute = "/proc/net/route"

// maxRouteTableBytes bounds what is read of the routing table: a node's table
// is a few lines, and one that is not is not one to read whole.
// A variable so that a test can lower it.
var maxRouteTableBytes int64 = 16 << 20

// resolvConf is the node's resolver configuration.
const resolvConf = "/etc/resolv.conf"

// maxExtraBytes bounds what is read of the output of `ip route show table all`
// and of resolv.conf.
const maxExtraBytes = 4 << 20

// ReadNodeNetworks reads this node's IPv4 routes (the main routing table) and
// the IPv4 addresses of all its interfaces. A table or an interface it cannot
// read is an error and no networks: nothing partial is ever compared. Beside
// them it reads, as far as it can, the routes of the node's other routing
// tables (`ip route show table all`), the DNS servers of /etc/resolv.conf and
// the address of the SSH client; what it cannot read of those is named in
// Unread, and the rest is still returned (review R2-06).
func ReadNodeNetworks() (NodeNetworks, error) {
	nodeNetworks, err := readNodeNetworks(procNetRoute, net.Interfaces, func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() })
	if err != nil {
		return NodeNetworks{}, err
	}
	readExtraNetworks(&nodeNetworks, extraSources{ipRoutes: ipRouteShowTableAll, resolvConf: resolvConf, sshClient: SSHClientAddress})
	return nodeNetworks, nil
}

// extraSources are where readExtraNetworks reads from; a test gives it others.
type extraSources struct {
	// ipRoutes is the output of `ip -4 -o route show table all`.
	ipRoutes   func() (string, error)
	resolvConf string
	sshClient  func() (netip.Addr, bool)
}

// readExtraNetworks adds to nodeNetworks what the main table and the interface
// addresses do not hold. Each source is read on its own: one that fails is
// named in Unread with its cause, and does not stop the others.
func readExtraNetworks(nodeNetworks *NodeNetworks, sources extraSources) {
	if output, err := sources.ipRoutes(); err != nil {
		nodeNetworks.Unread = append(nodeNetworks.Unread, fmt.Sprintf("the routes of the other routing tables (%v)", err))
	} else {
		routes, unread := ParseIPRouteTables(output)
		nodeNetworks.Routes = append(nodeNetworks.Routes, routes...)
		nodeNetworks.Unread = append(nodeNetworks.Unread, unread...)
	}
	if addr, ok := sources.sshClient(); ok {
		nodeNetworks.Held = append(nodeNetworks.Held, HeldAddress{Address: addr, Kind: HeldSSHClient})
	}
	switch text, err := readBounded(sources.resolvConf); {
	case err == nil:
		for _, server := range ParseResolvConfNameservers(text) {
			nodeNetworks.Held = append(nodeNetworks.Held, HeldAddress{Address: server, Kind: HeldDNSServer})
		}
	case errors.Is(err, os.ErrNotExist):
		// A node with no resolv.conf has no name server to lose.
	default:
		nodeNetworks.Unread = append(nodeNetworks.Unread, fmt.Sprintf("the DNS servers of /etc/resolv.conf (%v)", err))
	}
}

// readBounded reads a file of at most maxExtraBytes.
func readBounded(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxExtraBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxExtraBytes {
		return "", fmt.Errorf("%s is larger than %d bytes", path, maxExtraBytes)
	}
	return string(data), nil
}

// ipPaths are where iproute2 puts ip. They are tried before PATH: a worker
// started under sudo or as a service has a PATH of its own, and one that was
// narrowed (a test, a hardened unit) would otherwise not find a tool that is
// there.
var ipPaths = []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"}

// findIP is the ip command of this node.
func findIP() (string, error) {
	for _, candidate := range ipPaths {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return exec.LookPath("ip")
}

// ipRouteShowTableAll runs `ip -4 -o route show table all`, with a time limit
// and a bound on its output.
func ipRouteShowTableAll() (string, error) {
	ip, err := findIP()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, ip, "-4", "-o", "route", "show", "table", "all")
	stdout, err := command.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := command.Start(); err != nil {
		return "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, maxExtraBytes+1))
	if len(data) > maxExtraBytes {
		cancel()
		_ = command.Wait()
		return "", fmt.Errorf("ip route show table all printed more than %d bytes", maxExtraBytes)
	}
	waitErr := command.Wait()
	if readErr != nil {
		return "", readErr
	}
	if waitErr != nil {
		return "", fmt.Errorf("ip route show table all: %w", waitErr)
	}
	return string(data), nil
}

func readNodeNetworks(routeFile string, interfaces func() ([]net.Interface, error), addresses func(net.Interface) ([]net.Addr, error)) (NodeNetworks, error) {
	file, err := os.Open(routeFile)
	if err != nil {
		return NodeNetworks{}, fmt.Errorf("open %s: %w", routeFile, err)
	}
	defer file.Close()
	// One byte past the limit shows that the table goes on: a table cut at a
	// line boundary would otherwise parse as a complete, shorter one.
	table, err := io.ReadAll(io.LimitReader(file, maxRouteTableBytes+1))
	if err != nil {
		return NodeNetworks{}, fmt.Errorf("read %s: %w", routeFile, err)
	}
	if int64(len(table)) > maxRouteTableBytes {
		return NodeNetworks{}, fmt.Errorf("%s is larger than the %d bytes that are read of a routing table, so it was not read whole", routeFile, maxRouteTableBytes)
	}
	routes, err := ParseProcNetRoute(bytes.NewReader(table))
	if err != nil {
		return NodeNetworks{}, fmt.Errorf("%s: %w", routeFile, err)
	}
	nodeNetworks := NodeNetworks{Routes: routes}
	all, err := interfaces()
	if err != nil {
		return NodeNetworks{}, fmt.Errorf("list the node's interfaces: %w", err)
	}
	for _, iface := range all {
		addrs, err := addresses(iface)
		if err != nil {
			return NodeNetworks{}, fmt.Errorf("list the addresses of interface %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			if ip = ip.Unmap(); !ip.Is4() {
				continue // IPv6 is not a sandbox's business
			}
			ones, size := ipNet.Mask.Size()
			if size == 128 {
				ones -= 96 // an IPv4 address with a 16-byte mask
			}
			if ones < 0 || ones > 32 {
				return NodeNetworks{}, fmt.Errorf("interface %s: address %s has a mask that is not a network mask", iface.Name, ip)
			}
			nodeNetworks.Addresses = append(nodeNetworks.Addresses, NodeAddress{Prefix: netip.PrefixFrom(ip, ones), Interface: iface.Name})
		}
	}
	return nodeNetworks, nil
}
