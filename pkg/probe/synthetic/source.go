// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// Source pins a wire probe to the isolated sandbox network. Subnet checks on
// the target alone are not enough: an ordinary host socket follows the host
// routing table, so a loopback target or a host route overlapping the sandbox
// range would be answered by something other than the restored guest. A
// bound probe leaves only through Interface, from Address, or not at all.
type Source struct {
	Interface string // sandbox VNet interface on the worker host
	Address   string // host probe address assigned to Interface
}

// annotate records the source a wire probe is bound to in its result: the
// sandbox interface and the host probe address the guest sees the probe come
// from. An unbound source records nothing.
func (s Source) annotate(res *probe.Result) {
	res.SourceInterface, res.SourceAddress = s.Interface, s.Address
}

// IsZero reports an unbound source. Only unit tests that probe local
// listeners run wire probes without one.
func (s Source) IsZero() bool {
	return s.Interface == "" && s.Address == ""
}

// localAddresses lists the worker host's interface addresses; tests replace
// it, and checkTargetNotLocal, to exercise interface binding on its own.
var (
	localAddresses      = net.InterfaceAddrs
	checkTargetNotLocal = CheckTargetNotLocal
)

// CheckTargetNotLocal refuses a wire-probe target that is an address of the
// worker host itself. Binding a socket to the sandbox interface does not stop
// the kernel from answering for its own addresses, so a host listener on such
// an address (for example a second host address on a preprovisioned VNet)
// would pass the probe with no restored guest present.
func CheckTargetNotLocal(target string) error {
	ip := net.ParseIP(strings.TrimSpace(target))
	if ip == nil {
		return fmt.Errorf("probe target %q is not an IP address", target)
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return fmt.Errorf("probe target %s is an address of the worker host, not of the restored guest", ip)
	}
	addresses, err := localAddresses()
	if err != nil {
		return fmt.Errorf("list worker host addresses to check probe target %s: %w", ip, err)
	}
	for _, address := range addresses {
		var local net.IP
		switch value := address.(type) {
		case *net.IPNet:
			local = value.IP
		case *net.IPAddr:
			local = value.IP
		}
		if local != nil && local.Equal(ip) {
			return fmt.Errorf("probe target %s is an address of the worker host, not of the restored guest", ip)
		}
	}
	return nil
}

// dialer returns a dialer for network ("tcp" or "udp") that originates from
// the source, or an unbound dialer for the zero Source.
func (s Source) dialer(network string, timeout time.Duration) (*net.Dialer, error) {
	d := &net.Dialer{Timeout: timeout}
	if s.IsZero() {
		return d, nil
	}
	if s.Interface == "" || s.Address == "" {
		return nil, errors.New("probe source needs both the sandbox interface and the host probe address")
	}
	ip := net.ParseIP(s.Address)
	if ip == nil {
		return nil, fmt.Errorf("probe source address %q is not an IP address", s.Address)
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		d.LocalAddr = &net.TCPAddr{IP: ip}
	case "udp", "udp4", "udp6":
		d.LocalAddr = &net.UDPAddr{IP: ip}
	default:
		return nil, fmt.Errorf("probe source cannot bind network %q", network)
	}
	bind := bindToDevice(s.Interface)
	// Checked on every attempt, against the address actually being dialed,
	// so an address the host gained after the pre-run check is refused too.
	d.Control = func(network, address string, conn syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("probe target %q: %w", address, err)
		}
		if err := checkTargetNotLocal(host); err != nil {
			return err
		}
		return bind(network, address, conn)
	}
	return d, nil
}
