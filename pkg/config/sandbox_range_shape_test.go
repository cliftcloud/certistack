// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"strings"
	"testing"
)

// networkRangeErrors are the errors Validate reports for network.ip_range.
func networkRangeErrors(errs []ValidationError) []ValidationError {
	var out []ValidationError
	for _, err := range errs {
		if err.Field == "network.ip_range" {
			out = append(out, err)
		}
	}
	return out
}

// An IPv6 range is the mistake, so the range is what validation names, once,
// with the way out, not only that probe_ip must be within ip_range, which is
// true of the probe address and says nothing of the cause.
func TestValidateExplainsAnIPv6SandboxRange(t *testing.T) {
	for _, tc := range []struct{ ipRange, probeIP, target string }{
		{"fd00::/64", "fd00::1", "fd00::10"},
		{"fd00::/64", "10.100.0.1", "10.100.0.10"},
		{"2001:db8::/32", "2001:db8::1", "2001:db8::10"},
		{"::ffff:10.100.0.0/120", "10.100.0.1", "10.100.0.10"},
	} {
		t.Run(tc.ipRange+" probe "+tc.probeIP, func(t *testing.T) {
			p := validPlan()
			p.Network.IPRange = tc.ipRange
			p.Network.ProbeIP = tc.probeIP
			p.Tiers[0].VMs[0].Probes[0].TargetIP = tc.target
			errs := Validate(p)
			rangeErrs := networkRangeErrors(errs)
			if len(rangeErrs) != 1 {
				t.Fatalf("network.ip_range errors = %v, want exactly one:\n%s", rangeErrs, validationFields(errs))
			}
			for _, want := range []string{"IPv6", "not supported", "IPv4 CIDR", "192.0.2.0/24"} {
				if !strings.Contains(rangeErrs[0].Message, want) {
					t.Errorf("message %q lacks %q", rangeErrs[0].Message, want)
				}
			}
			if errs[0].Field != "network.ip_range" {
				t.Errorf("the first error names %s, want network.ip_range (the cause), in:\n%s", errs[0].Field, validationFields(errs))
			}
			if len(errs) != 1 {
				t.Errorf("the IPv6 range also caused follow-on errors that hide the cause:\n%s", validationFields(errs))
			}
		})
	}
}

// 192.0.2.5/24 names a host inside the network, not the network: the subnet
// CertiStack would create is 192.0.2.0/24, and the plan must say so rather
// than pass the range on to PVE as written.
func TestValidateRefusesARangeWithHostBitsSet(t *testing.T) {
	for _, tc := range []struct{ ipRange, canonical string }{
		{"10.100.0.5/24", "10.100.0.0/24"},
		{"10.100.0.1/24", "10.100.0.0/24"},
		{"10.100.0.255/24", "10.100.0.0/24"},
		{"10.100.0.130/25", "10.100.0.128/25"},
		{"10.100.7.0/16", "10.100.0.0/16"},
		{"10.100.0.1/31", "10.100.0.0/31"},
	} {
		t.Run(tc.ipRange, func(t *testing.T) {
			p := validPlan()
			p.Network.IPRange = tc.ipRange
			p.Network.ProbeIP = "10.100.0.1"
			p.Tiers[0].VMs[0].Probes[0].TargetIP = "10.100.0.10"
			rangeErrs := networkRangeErrors(Validate(p))
			if len(rangeErrs) != 1 {
				t.Fatalf("network.ip_range errors = %v, want exactly one", rangeErrs)
			}
			for _, want := range []string{tc.ipRange, "host bits", "did you mean " + tc.canonical + "?"} {
				if !strings.Contains(rangeErrs[0].Message, want) {
					t.Errorf("message %q lacks %q", rangeErrs[0].Message, want)
				}
			}
		})
	}
}

// What stays valid: a network address with any mask, a single host, and the
// documentation range the examples use.
func TestValidateAcceptsCanonicalIPv4Ranges(t *testing.T) {
	for _, tc := range []struct{ ipRange, probeIP, target string }{
		{"10.100.0.0/24", "10.100.0.1", "10.100.0.10"},
		{"192.0.2.0/24", "192.0.2.1", "192.0.2.10"},
		{"10.100.0.128/25", "10.100.0.129", "10.100.0.130"},
		{"10.96.0.0/16", "10.96.0.1", "10.96.0.10"},
		{"10.100.0.0/29", "10.100.0.1", "10.100.0.2"},
	} {
		p := validPlan()
		p.Network.IPRange = tc.ipRange
		p.Network.ProbeIP = tc.probeIP
		p.Tiers[0].VMs[0].Probes[0].TargetIP = tc.target
		if errs := networkRangeErrors(Validate(p)); len(errs) != 0 {
			t.Errorf("ip_range %s refused: %v", tc.ipRange, errs)
		}
	}
}

// source_pbs.storage_id is genuinely optional when the plan names the VM's
// source_vmid or a storage.pbs_repository: the loader fills in "pbs", which is
// the only value a run accepts (docs/plan-reference.md). Only a plan with
// neither has nothing to fill it from, and that one is refused.
func TestValidateStorageIDIsOptionalOnlyWhereTheLoaderCanFillItIn(t *testing.T) {
	// The loader's defaulting is what makes it optional.
	p := validPlan()
	p.Tiers[0].VMs[0].SourcePBS.StorageID = ""
	p.Tiers[0].VMs[0].SourceVMID = 100
	p.Normalize()
	if got := p.Tiers[0].VMs[0].SourcePBS.StorageID; got != "pbs" {
		t.Fatalf("storage_id left out with source_vmid set is %q after loading, want pbs", got)
	}
	if hasFieldError(Validate(p), "tiers[0].vms[0].source_pbs.storage_id") {
		t.Errorf("an omitted storage_id with source_vmid set was refused")
	}
	// Nothing to fill it from: refused.
	q := validPlan()
	q.Tiers[0].VMs[0].SourcePBS.StorageID = ""
	q.Tiers[0].VMs[0].SourceVMID = 0
	q.Normalize()
	if !hasFieldError(Validate(q), "tiers[0].vms[0].source_pbs.storage_id") {
		t.Errorf("an omitted storage_id with no source_vmid and no storage.pbs_repository was accepted")
	}
}

// CertiStack tracks the ids of the zone and VNet it creates in one
// set, so an ephemeral sandbox needs two different ids. A pre-provisioned
// sandbox names a zone and VNet that already exist in PVE (which allows one id
// for both): the plan has to carry the ids they have, so the rule cannot apply.
func TestZoneAndVNetIDsMayShareAnIDOnlyForAPreprovisionedSandbox(t *testing.T) {
	vnetErrors := func(errs []ValidationError) []ValidationError {
		var out []ValidationError
		for _, err := range errs {
			if err.Field == "network.vnet_id" {
				out = append(out, err)
			}
		}
		return out
	}
	for _, lifecycle := range []string{"", "ephemeral"} {
		p := validPlan()
		p.Network.Lifecycle = lifecycle
		p.Network.ZoneID, p.Network.VNetID = "csSbMin1", "csSbMin1"
		errs := vnetErrors(Validate(p))
		if len(errs) != 1 || !strings.Contains(errs[0].Message, "must differ from network.zone_id") {
			t.Errorf("ephemeral sandbox (lifecycle %q) with one id for zone and VNet: errors = %v, want the must-differ refusal", lifecycle, errs)
		}
	}
	for _, vnet := range []string{"csSbMin1", "CSSBMIN1"} {
		p := validPlan()
		p.Network.Lifecycle = "preprovisioned"
		p.Network.ZoneID, p.Network.VNetID = "csSbMin1", vnet
		if errs := vnetErrors(Validate(p)); len(errs) != 0 {
			t.Errorf("preprovisioned sandbox with zone csSbMin1 and VNet %s: %v, want none (the ids name existing objects)", vnet, errs)
		}
	}
}

// An IPv4-mapped IPv6 address (::ffff:192.0.2.1) is read as IPv4 by
// net.ParseIP, so a plan with one as probe_ip would pass a plain parse and be
// refused by `certistack check` at layer 4 ("not an IPv4 address") with the
// wrong fix. Validation says it first, with the address to write instead.
func TestValidateRefusesAMappedOrIPv6SandboxAddress(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Plan)
		field  string
		want   string
	}{
		{"mapped probe_ip", func(p *Plan) { p.Network.ProbeIP = "::ffff:10.100.0.1" }, "network.probe_ip", "write it as 10.100.0.1"},
		{"mapped probe_ip in hex", func(p *Plan) { p.Network.ProbeIP = "::ffff:a64:1" }, "network.probe_ip", "write it as 10.100.0.1"},
		{"IPv6 probe_ip", func(p *Plan) { p.Network.ProbeIP = "fd00::1" }, "network.probe_ip", "IPv6"},
		{"mapped target_ip", func(p *Plan) { p.Tiers[0].VMs[0].Probes[0].TargetIP = "::ffff:10.100.0.10" }, "tiers[0].vms[0].probes[0].target_ip", "write it as 10.100.0.10"},
		{"IPv6 target_ip", func(p *Plan) { p.Tiers[0].VMs[0].Probes[0].TargetIP = "fd00::10" }, "tiers[0].vms[0].probes[0].target_ip", "IPv6"},
		{"mapped sandbox_ip", func(p *Plan) { p.Tiers[0].VMs[0].NetworkRecovery.SandboxIP = "::ffff:10.100.0.10" }, "tiers[0].vms[0].network_recovery", "write it as 10.100.0.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validPlan()
			tc.mutate(p)
			var found []ValidationError
			for _, err := range Validate(p) {
				if strings.HasPrefix(err.Field, tc.field) {
					found = append(found, err)
				}
			}
			if len(found) != 1 || !strings.Contains(found[0].Message, tc.want) || !strings.Contains(found[0].Message, "IPv4") {
				t.Fatalf("errors on %s = %v, want one that says the sandbox is IPv4 and contains %q", tc.field, found, tc.want)
			}
		})
	}
	// A plain IPv4 plan is untouched.
	if errs := Validate(validPlan()); len(errs) != 0 {
		t.Errorf("the valid plan: %v", errs)
	}
}

// The peers of a VXLAN zone are real addresses of other cluster nodes. A peer
// inside network.ip_range is refused: with the probe address on the sandbox
// bridge the zone's tunnel to such a peer would run into the sandbox.
func TestValidateRefusesAVXLANPeerInsideTheSandboxRange(t *testing.T) {
	vxlan := func(ipRange, probe, target, peers string) *Plan {
		p := validPlan()
		p.Network.Mode, p.Network.Tag, p.Network.Peers = "vxlan", 100, peers
		p.Network.IPRange, p.Network.ProbeIP = ipRange, probe
		p.Tiers[0].VMs[0].Probes[0].TargetIP = target
		return p
	}
	peerErrors := func(p *Plan) []ValidationError {
		var out []ValidationError
		for _, err := range Validate(p) {
			if err.Field == "network.peers" {
				out = append(out, err)
			}
		}
		return out
	}
	errs := peerErrors(vxlan("192.0.2.0/24", "192.0.2.1", "192.0.2.10", "203.0.113.4, 192.0.2.9"))
	if len(errs) != 1 || !strings.Contains(errs[0].Message, "192.0.2.9") || !strings.Contains(errs[0].Message, "network.ip_range 192.0.2.0/24") || !strings.Contains(errs[0].Message, "tunnel") {
		t.Fatalf("peer errors = %v, want one naming 192.0.2.9 and the range", errs)
	}
	if strings.Contains(errs[0].Message, "203.0.113.4") {
		t.Errorf("a peer outside the range is named: %v", errs)
	}
	if errs := peerErrors(vxlan("192.0.2.0/24", "192.0.2.1", "192.0.2.10", "203.0.113.4,203.0.113.5")); len(errs) != 0 {
		t.Errorf("peers outside the range: %v", errs)
	}
}

// The message names a documentation range to move to, and never the plan's own:
// "for example 192.0.2.0/24" for a plan whose range is 192.0.2.0/24 sent the
// reader round in a circle. It names the first range that neither overlaps the
// plan's range nor holds a peer, and none when each does.
func TestVXLANPeerMessageSuggestsARangeOtherThanThePlans(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		ipRange, probe, peers string
		want                  string // the range after "for example"; "" for no suggestion
	}{
		{"a private range", "10.0.0.0/24", "10.0.0.1", "10.0.0.9", "192.0.2.0/24"},
		{"the first documentation range", "192.0.2.0/24", "192.0.2.1", "192.0.2.9", "198.51.100.0/24"},
		{"the second documentation range", "198.51.100.0/24", "198.51.100.1", "198.51.100.9", "192.0.2.0/24"},
		{"a range that holds the first", "192.0.0.0/16", "192.0.0.1", "192.0.2.9", "198.51.100.0/24"},
		{"a peer in the next candidate", "192.0.2.0/24", "192.0.2.1", "192.0.2.9,198.51.100.7", "203.0.113.0/24"},
		{"nothing left", "192.0.2.0/24", "192.0.2.1", "192.0.2.9,198.51.100.7,203.0.113.7", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validPlan()
			p.Network.Mode, p.Network.Tag, p.Network.Peers = "vxlan", 100, tc.peers
			p.Network.IPRange, p.Network.ProbeIP = tc.ipRange, tc.probe
			p.Tiers[0].VMs[0].Probes[0].TargetIP = tc.probe[:strings.LastIndex(tc.probe, ".")+1] + "10"
			var message string
			for _, err := range Validate(p) {
				if err.Field == "network.peers" {
					message = err.Message
					break
				}
			}
			if message == "" {
				t.Fatal("a peer inside the range was accepted")
			}
			const marker = ", for example "
			index := strings.Index(message, marker)
			switch {
			case tc.want == "" && index >= 0:
				t.Errorf("a suggestion was made when none is left: %s", message)
			case tc.want != "" && (index < 0 || message[index+len(marker):] != tc.want):
				t.Errorf("message = %q, want it to end %q%s", message, marker, tc.want)
			}
			if index >= 0 && strings.HasSuffix(message, tc.ipRange) {
				t.Errorf("the plan's own range is suggested: %s", message)
			}
		})
	}
}
