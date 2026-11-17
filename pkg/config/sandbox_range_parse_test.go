// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"errors"
	"strings"
	"testing"
)

// The spellings of a sandbox range that two parsers of the standard library
// read differently (net.ParseCIDR accepts a prefix length with leading zeros,
// netip.ParsePrefix does not) or that carry more than the range (spaces, zones,
// an IPv4-mapped IPv6 form). Accepted, 10.0.0.0/08 would be unreadable to the
// node-side overlap check and put on the sandbox bridge as 10.x.x.x/8.
var nonCanonicalSandboxRanges = []struct{ text, canonical string }{
	{"10.0.0.0/08", "10.0.0.0/8"},
	{"10.42.15.0/024", "10.42.15.0/24"},
	{"10.42.15.0/0024", "10.42.15.0/24"},
	{"10.42.15.0/00", "0.0.0.0/0"},
	{"192.0.2.0/008", "192.0.0.0/8"},
	{"10.42.15.0/+24", ""},
	{"10.42.015.0/24", ""},
	{"010.42.15.0/24", ""},
	{"10.042.15.0/24", ""},
	{" 10.42.15.0/24", ""},
	{"10.42.15.0/24 ", ""},
	{"10.42.15.0/24\n", ""},
	{"\t10.42.15.0/24", ""},
	{"10.42.15.0 /24", ""},
	{"10.42.15.0/ 24", ""},
	{"10.42.15.0", ""},
	{"10.42.15.0/", ""},
	{"/24", ""},
	{"", ""},
	{"10.42.15.0/33", ""},
	{"10.42.15.0/-1", ""},
	{"10.42.15.0/24/24", ""},
	{"10.42.15.0%eth0/24", ""},
	{"0xa.0.0.0/8", ""},
	{"10.1/16", ""},
	{"10.0.0.0/0x8", ""},
	{"10.0.0.0/8.0", ""},
	{"10.0.0.0/2_4", ""},
	{"10.42.15.0/２４", ""},
	{"１０.42.15.0/24", ""},
	{"::ffff:10.42.15.0/120", ""},
	{"::FFFF:10.42.15.0/120", ""},
	{"::ffff:a2a:f00/120", ""},
	{"fe80::1%eth0/64", ""},
	{"FD00::/64", ""},
}

func TestParseSandboxRangeRefusesEveryNonCanonicalSpelling(t *testing.T) {
	for _, tc := range nonCanonicalSandboxRanges {
		t.Run(tc.text, func(t *testing.T) {
			prefix, err := ParseSandboxRange(tc.text)
			if err == nil {
				t.Fatalf("ParseSandboxRange(%q) = %s, want a refusal", tc.text, prefix)
			}
			if tc.canonical != "" && !strings.Contains(err.Error(), "write it as "+tc.canonical) {
				t.Errorf("ParseSandboxRange(%q) = %q, want it to name the canonical form %s", tc.text, err, tc.canonical)
			}
		})
	}
}

func TestParseSandboxRangeAcceptsOnlyTheCanonicalSpelling(t *testing.T) {
	for _, text := range []string{"192.0.2.0/24", "10.0.0.0/8", "10.100.0.128/25", "172.16.0.0/12", "198.51.100.8/29", "203.0.113.4/30"} {
		prefix, err := ParseSandboxRange(text)
		if err != nil {
			t.Errorf("ParseSandboxRange(%q): %v", text, err)
			continue
		}
		if prefix.String() != text {
			t.Errorf("ParseSandboxRange(%q) = %s, want the same network", text, prefix)
		}
	}
}

// A range with host bits set names a host, not the network: the refusal keeps
// the wording the plan has always used.
func TestParseSandboxRangeNamesTheNetworkOfAHostRange(t *testing.T) {
	_, err := ParseSandboxRange("192.0.2.5/24")
	if err == nil {
		t.Fatal("192.0.2.5/24 was accepted")
	}
	for _, want := range []string{"192.0.2.5/24", "host bits", "did you mean 192.0.2.0/24?"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err, want)
		}
	}
}

func TestParseSandboxRangeSaysIPv6IsNotSupported(t *testing.T) {
	_, err := ParseSandboxRange("fd00::/64")
	var rangeErr *SandboxRangeError
	if !errors.As(err, &rangeErr) || !rangeErr.IPv6 {
		t.Fatalf("fd00::/64 = %v, want a SandboxRangeError with IPv6 set", err)
	}
	for _, want := range []string{"IPv6", "not supported", "IPv4 CIDR", "192.0.2.0/24"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err, want)
		}
	}
}

// Validate refuses a non-canonical spelling with the canonical form named, once,
// on network.ip_range.
func TestValidateRefusesANonCanonicalSandboxRangeAndNamesTheCanonicalForm(t *testing.T) {
	for _, tc := range []struct{ text, probe, canonical string }{
		{"10.0.0.0/08", "10.42.15.1", "10.0.0.0/8"},
		{"10.42.15.0/024", "10.42.15.1", "10.42.15.0/24"},
		{"10.100.0.0/0024", "10.100.0.1", "10.100.0.0/24"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			p := validPlan()
			p.Network.IPRange = tc.text
			p.Network.ProbeIP = tc.probe
			p.Tiers[0].VMs[0].Probes[0].TargetIP = tc.probe
			errs := networkRangeErrors(Validate(p))
			if len(errs) != 1 {
				t.Fatalf("network.ip_range errors for %q = %v, want exactly one", tc.text, errs)
			}
			if !strings.Contains(errs[0].Message, "write it as "+tc.canonical) {
				t.Errorf("message %q does not name the canonical form %s", errs[0].Message, tc.canonical)
			}
		})
	}
}

// The engine reads the range with the same parser: a spelling validation
// refuses is never put on the sandbox bridge.
func TestTheEngineRefusesWhatValidationRefuses(t *testing.T) {
	for _, text := range []string{"10.0.0.0/08", "10.42.15.0/024", " 10.42.15.0/24"} {
		network := Network{IPRange: text, ProbeIP: "10.42.15.1"}
		if got, err := network.ProbeAddressCIDR(); err == nil {
			t.Errorf("ProbeAddressCIDR with ip_range %q = %q, want a refusal", text, got)
		}
		vm := VM{}
		if _, _, err := vm.SandboxAddress(network); err == nil {
			t.Errorf("SandboxAddress with ip_range %q was accepted", text)
		}
	}
}
