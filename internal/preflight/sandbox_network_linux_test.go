// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeInterfaces(names ...string) func() ([]net.Interface, error) {
	return func() ([]net.Interface, error) {
		var all []net.Interface
		for i, name := range names {
			all = append(all, net.Interface{Index: i + 1, Name: name})
		}
		return all, nil
	}
}

func ipNet(cidr string) net.Addr {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	network.IP = ip
	return network
}

func routeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The node's routes and the addresses of all its interfaces come back together,
// IPv4 only, each address with the interface it is on.
func TestReadNodeNetworksReadsRoutesAndEveryInterfacesAddresses(t *testing.T) {
	path := routeFile(t, procRouteHeader+procRoute("vmbr0", "0.0.0.0", 0, "10.42.20.1")+procRoute("vmbr0", "10.42.20.0", 24, ""))
	addrs := map[string][]net.Addr{
		"lo":    {ipNet("127.0.0.1/8"), ipNet("::1/128")},
		"vmbr0": {ipNet("10.42.20.36/24"), ipNet("fe80::1/64"), &net.IPAddr{IP: net.ParseIP("10.9.9.9")}},
		"dummy": {ipNet("192.0.2.77/32")},
	}
	got, err := readNodeNetworks(path, fakeInterfaces("lo", "vmbr0", "dummy"), func(iface net.Interface) ([]net.Addr, error) { return addrs[iface.Name], nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Routes) != 2 || got.Routes[1].Destination != netip.MustParsePrefix("10.42.20.0/24") {
		t.Errorf("routes = %+v", got.Routes)
	}
	want := []NodeAddress{
		{Prefix: netip.MustParsePrefix("127.0.0.1/8"), Interface: "lo"},
		{Prefix: netip.MustParsePrefix("10.42.20.36/24"), Interface: "vmbr0"},
		{Prefix: netip.MustParsePrefix("192.0.2.77/32"), Interface: "dummy"},
	}
	if len(got.Addresses) != len(want) {
		t.Fatalf("addresses = %+v, want %+v", got.Addresses, want)
	}
	for i := range want {
		if got.Addresses[i] != want[i] {
			t.Errorf("address %d = %+v, want %+v", i, got.Addresses[i], want[i])
		}
	}
}

// Nothing partial is ever compared: a table or an interface that cannot be read
// makes the whole read fail, and the check reports that it could not be made.
func TestReadNodeNetworksFailsWholeWhenAnyPartCannotBeRead(t *testing.T) {
	good := routeFile(t, procRouteHeader+procRoute("vmbr0", "10.42.20.0", 24, ""))
	noAddresses := func(net.Interface) ([]net.Addr, error) { return nil, nil }
	for name, call := range map[string]func() error{
		"no routing table": func() error {
			_, err := readNodeNetworks(filepath.Join(t.TempDir(), "absent"), fakeInterfaces("lo"), noAddresses)
			return err
		},
		"an unparsable routing table": func() error {
			_, err := readNodeNetworks(routeFile(t, "garbage\n"), fakeInterfaces("lo"), noAddresses)
			return err
		},
		"interfaces cannot be listed": func() error {
			_, err := readNodeNetworks(good, func() ([]net.Interface, error) { return nil, errors.New("netlink: operation not permitted") }, noAddresses)
			return err
		},
		"one interface's addresses cannot be listed": func() error {
			_, err := readNodeNetworks(good, fakeInterfaces("lo", "eth0"), func(iface net.Interface) ([]net.Addr, error) {
				if iface.Name == "eth0" {
					return nil, errors.New("no such device")
				}
				return nil, nil
			})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("read succeeded")
			}
		})
	}
	_, err := readNodeNetworks(good, fakeInterfaces("eth0"), func(net.Interface) ([]net.Addr, error) { return nil, errors.New("no such device") })
	if err == nil || !strings.Contains(err.Error(), "eth0") {
		t.Errorf("the error does not name the interface: %v", err)
	}
}

// Review R2-05/R2-15: a routing table longer than what is read is not read whole.
// Cut at a line boundary it parsed as a complete (shorter) table, and the route
// that overlaps could be in the part that was never read.
func TestReadNodeNetworksRefusesATableLongerThanItReads(t *testing.T) {
	var table strings.Builder
	table.WriteString(procRouteHeader)
	for i := 0; i < 20; i++ {
		table.WriteString(procRoute("eth0", "10.0.1.0", 24, ""))
	}
	path := routeFile(t, table.String())
	noAddresses := func(net.Interface) ([]net.Addr, error) { return nil, nil }

	previous := maxRouteTableBytes
	t.Cleanup(func() { maxRouteTableBytes = previous })
	// The limit falls on a line boundary: the part before it is a valid table.
	maxRouteTableBytes = int64(len(procRouteHeader) + 3*len(procRoute("eth0", "10.0.1.0", 24, "")))
	if _, err := readNodeNetworks(path, fakeInterfaces("lo"), noAddresses); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("a table cut at a line boundary: error = %v, want a refusal that says it is larger than what is read", err)
	}
	// A table that is exactly the limit is whole.
	maxRouteTableBytes = int64(table.Len())
	if _, err := readNodeNetworks(path, fakeInterfaces("lo"), noAddresses); err != nil {
		t.Errorf("a table of exactly the limit: %v", err)
	}
}

// Review R2-06: the routes of the other routing tables, the SSH client and the
// DNS servers are read beside the main table. A source that cannot be read is
// named in Unread and the others are still read.
func TestReadExtraNetworksReadsTheOtherTablesTheSSHClientAndTheDNSServers(t *testing.T) {
	resolv := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolv, []byte("nameserver 198.51.100.53\nnameserver 127.0.0.53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nodeNetworks := NodeNetworks{}
	readExtraNetworks(&nodeNetworks, extraSources{
		ipRoutes: func() (string, error) {
			return "192.168.1.0/24 dev tailscale0 table 52\n10.42.20.0/24 dev vmbr0\n", nil
		},
		resolvConf: resolv,
		sshClient:  func() (netip.Addr, bool) { return netip.MustParseAddr("203.0.113.7"), true },
	})
	if len(nodeNetworks.Routes) != 1 || nodeNetworks.Routes[0].Table != "52" || nodeNetworks.Routes[0].Interface != "tailscale0" {
		t.Errorf("routes = %+v, want the one route of table 52", nodeNetworks.Routes)
	}
	want := []HeldAddress{{Address: netip.MustParseAddr("203.0.113.7"), Kind: HeldSSHClient}, {Address: netip.MustParseAddr("198.51.100.53"), Kind: HeldDNSServer}}
	if len(nodeNetworks.Held) != len(want) || nodeNetworks.Held[0] != want[0] || nodeNetworks.Held[1] != want[1] {
		t.Errorf("held = %+v, want %+v", nodeNetworks.Held, want)
	}
	if len(nodeNetworks.Unread) != 0 {
		t.Errorf("unread = %q, want none", nodeNetworks.Unread)
	}

	// Each source that fails is named, and the others are still read.
	failed := NodeNetworks{}
	readExtraNetworks(&failed, extraSources{
		ipRoutes:   func() (string, error) { return "", errors.New("exec: \"ip\": executable file not found in $PATH") },
		resolvConf: filepath.Join(t.TempDir(), "absent"), // no resolv.conf is not a failure
		sshClient:  func() (netip.Addr, bool) { return netip.Addr{}, false },
	})
	if len(failed.Unread) != 1 || !strings.Contains(failed.Unread[0], "other routing tables") || !strings.Contains(failed.Unread[0], "executable file not found") {
		t.Errorf("unread = %q, want only the routes of the other routing tables, with the cause", failed.Unread)
	}
	if len(failed.Held) != 0 {
		t.Errorf("held = %+v, want none", failed.Held)
	}

	// A resolv.conf that exists and cannot be read is named.
	directory := t.TempDir()
	unreadable := NodeNetworks{}
	readExtraNetworks(&unreadable, extraSources{
		ipRoutes:   func() (string, error) { return "", nil },
		resolvConf: directory, // reading a directory fails
		sshClient:  func() (netip.Addr, bool) { return netip.Addr{}, false },
	})
	if len(unreadable.Unread) != 1 || !strings.Contains(unreadable.Unread[0], "/etc/resolv.conf") {
		t.Errorf("unread = %q, want the DNS servers named", unreadable.Unread)
	}

	// A table with lines that cannot be read is named with its table.
	partial := NodeNetworks{}
	readExtraNetworks(&partial, extraSources{
		ipRoutes:   func() (string, error) { return "192.168.1.0/24 dev tailscale0 table 52\ngarbage table 99\n", nil },
		resolvConf: filepath.Join(t.TempDir(), "absent"),
		sshClient:  func() (netip.Addr, bool) { return netip.Addr{}, false },
	})
	if len(partial.Routes) != 1 || len(partial.Unread) != 1 || !strings.Contains(partial.Unread[0], "routing table 99") {
		t.Errorf("routes %+v, unread %q: want table 52 read and table 99 named", partial.Routes, partial.Unread)
	}
}

// The SSH client is the address the controller told the worker, else the
// worker's own SSH_CONNECTION.
func TestTheSSHClientIsToldOrReadFromTheEnvironment(t *testing.T) {
	t.Cleanup(func() { SetSSHClient("") })
	t.Setenv("SSH_CONNECTION", "198.51.100.7 51234 192.0.2.10 22")
	SetSSHClient("")
	if addr, ok := SSHClientAddress(); !ok || addr != netip.MustParseAddr("198.51.100.7") {
		t.Errorf("from the environment: %v %v", addr, ok)
	}
	SetSSHClient("203.0.113.9")
	if addr, ok := SSHClientAddress(); !ok || addr != netip.MustParseAddr("203.0.113.9") {
		t.Errorf("told by the controller: %v %v", addr, ok)
	}
	SetSSHClient("not an address")
	if addr, ok := SSHClientAddress(); !ok || addr != netip.MustParseAddr("198.51.100.7") {
		t.Errorf("an unreadable told address falls back to the environment: %v %v", addr, ok)
	}
	t.Setenv("SSH_CONNECTION", "")
	if addr, ok := SSHClientAddress(); ok {
		t.Errorf("nothing known, got %v", addr)
	}
}

// On this machine the real files read, and the loopback address is among them.
func TestReadNodeNetworksReadsThisMachine(t *testing.T) {
	got, err := ReadNodeNetworks()
	if err != nil {
		t.Skipf("this machine's networks cannot be read here: %v", err)
	}
	found := false
	for _, address := range got.Addresses {
		found = found || (address.Interface == "lo" && address.Prefix.Addr() == netip.MustParseAddr("127.0.0.1"))
	}
	if !found {
		t.Errorf("addresses = %+v, want the loopback address 127.0.0.1 on lo", got.Addresses)
	}
}
