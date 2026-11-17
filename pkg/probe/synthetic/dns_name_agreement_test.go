// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// validate refuses a dns probe's name exactly when the probe could not put it
// in a query: a name validate accepts never fails the probe after the VM has
// booted, and validate refuses no name the probe can send.
func FuzzDNSNameValidateAgreesWithTheQuery(f *testing.F) {
	for _, seed := range []string{"", ".", "example.com", "example.com.", " example.com ", "a..b", ".a", "a..", "_ldap._tcp.example.com",
		strings.Repeat("a", 63) + ".com", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127), strings.Repeat("ab.", 85), "a\x00b.com", "\t"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, domain string) {
		// The name as the run asks for it: NewDNSProber trims it, and Probe asks
		// for the root when nothing is left.
		name := NewDNSProber("192.0.2.10", 53, domain, "udp", 0, "").QueryDomain
		if name == "" {
			name = "."
		}
		_, _, queryErr := buildDNSQuery(name, dnsTypeA)
		problem := config.DNSQueryNameProblem(domain)
		if (problem == "") != (queryErr == nil) {
			t.Fatalf("domain %q: validate says %q, the query says %v", domain, problem, queryErr)
		}
	})
}
