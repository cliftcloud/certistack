// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"strings"
	"testing"
)

// A dns probe's name (its domain, or its path when the domain is left out)
// that a DNS query cannot carry would be refused by the probe only once the VM
// had been restored and booted ("invalid label", "name exceeds 253 octets"),
// failing a guest that was never asked. validate refuses the name the probe
// could not send, and accepts every name it can.
func TestADNSNameTheProbeCannotSendIsRefused(t *testing.T) {
	long := strings.Repeat("a", 63)
	for name, tc := range map[string]struct {
		domain, path string
		refused      bool
	}{
		"a name":                       {domain: "example.com"},
		"a name with its root dot":     {domain: "example.com."},
		"an SRV owner":                 {domain: "_ldap._tcp.dc._msdcs.example.com"},
		"the root":                     {domain: "."},
		"no name (a listener check)":   {},
		"63-octet labels, 253 in all":  {domain: strings.Join([]string{long, long, long, strings.Repeat("b", 61)}, ".")},
		"two dots in a row":            {domain: "a..example.com", refused: true},
		"a dot first":                  {domain: ".example.com", refused: true},
		"two dots at the end":          {domain: "example.com..", refused: true},
		"a 64-octet label":             {domain: strings.Repeat("a", 64) + ".com", refused: true},
		"254 octets":                   {domain: strings.Join([]string{long, long, long, strings.Repeat("b", 62)}, "."), refused: true},
		"the path read as the domain":  {path: "a..example.com", refused: true},
		"a good path read as a domain": {path: "example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			plan := validPlan()
			plan.Tiers[0].VMs[0].Probes = append(plan.Tiers[0].VMs[0].Probes, Probe{
				Type: "dns", TargetIP: "10.100.0.10", Port: 53, Domain: tc.domain, Path: tc.path, TimeoutSec: 10, Description: "dns",
			})
			var problems []string
			for _, problem := range Validate(plan) {
				problems = append(problems, problem.Error())
			}
			field := "tiers[0].vms[0].probes[1].domain"
			if tc.domain == "" && tc.path != "" {
				field = "tiers[0].vms[0].probes[1].path"
			}
			named := strings.Contains(strings.Join(problems, "\n"), field+":")
			if named != tc.refused {
				t.Fatalf("domain %q, path %q: refused at %s = %v, want %v (%v)", tc.domain, tc.path, field, named, tc.refused, problems)
			}
		})
	}
}
