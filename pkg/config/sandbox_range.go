// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// SandboxRangeError is why a sandbox range was refused.
type SandboxRangeError struct {
	// IPv6 is set when the range was refused for being an IPv6 range.
	IPv6 bool
	// Message completes "network.ip_range ...": it names the text, what is wrong
	// with it and, where there is one, the spelling to use instead.
	Message string
}

func (e *SandboxRangeError) Error() string { return e.Message }

func sandboxRangeRefusal(format string, args ...any) *SandboxRangeError {
	return &SandboxRangeError{Message: fmt.Sprintf(format, args...)}
}

// ParseSandboxRange reads network.ip_range. It is the only reader of that text:
// plan validation, the node-side overlap judgment, the controller's staging of
// a worker and the engine's use of the range (the address put on the sandbox
// bridge, the subnet created in PVE) all call it, so they cannot read one text
// as two networks.
//
// Two parsers of the standard library read some spellings differently
// (net.ParseCIDR accepts a prefix length with leading zeros such as
// 10.0.0.0/08, netip.ParsePrefix does not), so a range is accepted only when
// both read it, as the same network, and when it is written exactly the way
// that network is written (no spaces, no leading zeros, no zone, no sign). The
// network is an IPv4 network with no host bits set. Any other text is refused,
// and the canonical spelling is named where there is one.
func ParseSandboxRange(text string) (netip.Prefix, error) {
	if strings.Contains(text, ":") {
		// Any range with a colon: a sandbox is an IPv4 network (the probe
		// address, the guest's recovered address and the subnet are all IPv4).
		err := sandboxRangeRefusal("%q is an IPv6 range, and IPv6 sandbox ranges are not supported: use an IPv4 CIDR such as 192.0.2.0/24", text)
		err.IPv6 = true
		return netip.Prefix{}, err
	}
	strict, strictErr := netip.ParsePrefix(text)
	lenient, lenientErr := lenientIPv4Network(text)
	switch {
	case strictErr != nil && lenientErr != nil:
		return netip.Prefix{}, sandboxRangeRefusal("%q is not a valid IPv4 CIDR: write it as a network address and a prefix length, such as 192.0.2.0/24", text)
	case strictErr != nil:
		// Only the lenient parser reads it, as a leading zero in the prefix
		// length does: the other tools that read the range may not.
		return netip.Prefix{}, sandboxRangeRefusal("%q is not written in its canonical form (a leading zero or another spelling that the tools reading the range do not all read the same way): write it as %s", text, lenient)
	case lenientErr != nil || !strict.Addr().Is4():
		return netip.Prefix{}, sandboxRangeRefusal("%q is not a valid IPv4 CIDR: write it as a network address and a prefix length, such as 192.0.2.0/24", text)
	}
	if lenient != strict.Masked() {
		return netip.Prefix{}, sandboxRangeRefusal("%q is read as %s by one tool and as %s by another: write it as %s", text, strict.Masked(), lenient, strict.Masked())
	}
	if strict != strict.Masked() {
		// 192.0.2.5/24 names a host inside the network, not the network.
		return netip.Prefix{}, sandboxRangeRefusal("%s has host bits set: it names a host inside the network, not the network itself; did you mean %s?", text, strict.Masked())
	}
	if strict.String() != text {
		return netip.Prefix{}, sandboxRangeRefusal("%q is not written in its canonical form: write it as %s", text, strict)
	}
	return strict, nil
}

// lenientIPv4Network is the network net.ParseCIDR reads in text.
func lenientIPv4Network(text string) (netip.Prefix, error) {
	_, network, err := net.ParseCIDR(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	address, ok := netip.AddrFromSlice(network.IP.To4())
	ones, bits := network.Mask.Size()
	if !ok || bits != 32 {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 network", text)
	}
	return netip.PrefixFrom(address, ones), nil
}

// ipNet is the prefix as the net package holds a network.
func ipNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
}

// ipv4OnlyProblem is what is wrong with an address written for the sandbox when
// it is not a plain IPv4 address, or "" when nothing is. A sandbox is an IPv4
// network, but net.ParseIP reads an IPv4-mapped IPv6 address (::ffff:192.0.2.1)
// as IPv4, so such an address would pass a plain parse and be refused later
// and elsewhere. The message completes "<field> ..." and names the address to
// write.
func ipv4OnlyProblem(value string) string {
	if !strings.Contains(value, ":") {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return fmt.Sprintf("%q is an IPv4-mapped IPv6 address, and sandbox addresses are plain IPv4: write it as %s", value, v4)
		}
	}
	return fmt.Sprintf("%q is an IPv6 address, and IPv6 sandbox addresses are not supported: use an IPv4 address inside network.ip_range", value)
}
