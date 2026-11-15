// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"math"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/ldapdn"
)

// probeErrors validates a plan whose only probe is probe and returns the
// validation errors on that probe, as "field: message" lines.
func probeErrors(probe Probe) []string {
	p := validPlan()
	p.Tiers[0].VMs[0].NetworkRecovery.Mode = "preserve"
	p.Tiers[0].VMs[0].Probes = []Probe{probe}
	var lines []string
	for _, err := range Validate(p) {
		if strings.Contains(err.Field, ".probes[0]") {
			lines = append(lines, err.Field+": "+err.Message)
		}
	}
	return lines
}

func hasProbeError(lines []string, field, containing string) bool {
	for _, line := range lines {
		if strings.Contains(line, ".probes[0]."+field+":") && strings.Contains(line, containing) {
			return true
		}
	}
	return false
}

// wireProbes are one otherwise valid probe of every type that dials a port.
func wireProbes() map[string]Probe {
	return map[string]Probe{
		"tcp":   {Type: "tcp", TargetIP: "10.100.0.10", Port: 389, TimeoutSec: 5, Description: "tcp"},
		"http":  {Type: "http", TargetIP: "10.100.0.10", Port: 80, ExpectedStatus: 200, TimeoutSec: 5, Description: "http"},
		"dns":   {Type: "dns", TargetIP: "10.100.0.10", Port: 53, TimeoutSec: 5, Description: "dns"},
		"ldap":  {Type: "ldap", TargetIP: "10.100.0.10", Port: 389, TimeoutSec: 5, Description: "ldap"},
		"mssql": {Type: "mssql", TargetIP: "10.100.0.10", Port: 1433, TimeoutSec: 5, Description: "mssql"},
		"smb":   {Type: "smb", TargetIP: "10.100.0.10", Port: 445, TimeoutSec: 5, Description: "smb"},
	}
}

// A TCP or UDP port is 1 to 65535. Port 65536 was accepted by all six
// wire probes and failed only when a run was under way, as "invalid port".
func TestValidationRejectsPortsOutsideOneToSixtyFiveThousand(t *testing.T) {
	for name, probe := range wireProbes() {
		for _, port := range []int{1, 22, 65535} {
			probe.Port = port
			if lines := probeErrors(probe); len(lines) != 0 {
				t.Errorf("%s probe on port %d: %v", name, port, lines)
			}
		}
		for port, want := range map[int]string{0: "must be set", -1: "between 1 and 65535", 65536: "between 1 and 65535", 70000: "between 1 and 65535", math.MaxInt: "between 1 and 65535"} {
			probe.Port = port
			if lines := probeErrors(probe); !hasProbeError(lines, "port", want) {
				t.Errorf("%s probe on port %d: errors %v, want one on port mentioning %q", name, port, lines, want)
			}
		}
	}
}

// The aliases http_get and tcp_handshake are the same probes.
func TestValidationRejectsAnOutOfRangePortOnProbeAliases(t *testing.T) {
	for _, probe := range []Probe{
		{Type: "http_get", TargetIP: "10.100.0.10", Port: 65536, ExpectedStatus: 200, TimeoutSec: 5, Description: "alias"},
		{Type: "tcp_handshake", TargetIP: "10.100.0.10", Port: 65536, TimeoutSec: 5, Description: "alias"},
	} {
		if lines := probeErrors(probe); !hasProbeError(lines, "port", "between 1 and 65535") {
			t.Errorf("%s: errors %v", probe.Type, lines)
		}
	}
}

// HTTP status codes are 100 to 599, and the one GET this probe sends is
// answered with a final status, so a 1xx status can never be seen. The
// reporter's 99, 600, 999 and 1000 were all accepted.
func TestValidationRequiresAnHTTPStatusFrom200To599(t *testing.T) {
	probe := wireProbes()["http"]
	for _, status := range []int{200, 201, 204, 301, 302, 404, 503, 599} {
		probe.ExpectedStatus = status
		if lines := probeErrors(probe); len(lines) != 0 {
			t.Errorf("expected_status %d: %v", status, lines)
		}
	}
	for _, status := range []int{-1, 1, 99, 100, 101, 199, 600, 999, 1000, math.MaxInt} {
		probe.ExpectedStatus = status
		if lines := probeErrors(probe); !hasProbeError(lines, "expected_status", "from 200 to 599") {
			t.Errorf("expected_status %d: errors %v, want one on expected_status", status, lines)
		}
	}
	probe.ExpectedStatus = 0
	if lines := probeErrors(probe); !hasProbeError(lines, "expected_status", "must be set") {
		t.Errorf("no expected_status: errors %v", lines)
	}
}

// base_dn and naming_context are sent to the server, so each must be a
// distinguished name of a length the request carries. The first four are the
// reporter's plans, all of which validated.
func TestValidationRejectsMalformedAndOversizedLDAPDNs(t *testing.T) {
	ldap := wireProbes()["ldap"]
	for _, tc := range []struct {
		name, field, value, want string
	}{
		{"base_dn that is no DN", "base_dn", "not-a-distinguished-name", "no '=' and value"},
		{"a 65,538-byte base_dn", "base_dn", "dc=" + strings.Repeat("a", 65535), "at most 1024"},
		{"naming_context ending in a backslash", "naming_context", `CN=broken\`, "escapes nothing"},
		{"naming_context with a plus and no assertion", "naming_context", "CN=value+", "attribute type was expected"},
		{"base_dn with an unescaped semicolon", "base_dn", "cn=a;b,dc=example", "requires it escaped"},
		{"base_dn with an invalid attribute type", "base_dn", "1cn=x,dc=example", "numeric OID"},
		{"base_dn with an empty RDN", "base_dn", "dc=example,,dc=com", "attribute type was expected"},
		{"base_dn of spaces", "base_dn", "   ", "not only spaces"},
		{"a base_dn one byte over the limit", "base_dn", "cn=" + strings.Repeat("a", ldapdn.MaxLength-2), "at most 1024"},
		{"naming_context of invalid UTF-8", "naming_context", "cn=\xff,dc=example", "UTF-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := ldap
			if tc.field == "base_dn" {
				probe.BaseDN = tc.value
			} else {
				probe.NamingContext = tc.value
			}
			if lines := probeErrors(probe); !hasProbeError(lines, tc.field, tc.want) {
				t.Fatalf("errors %v, want one on %s mentioning %q", lines, tc.field, tc.want)
			}
		})
	}
}

// Controls: every plan that was valid and asserted a real DN still
// loads, "auto" stays the one reserved value, and the size limit is exact.
func TestValidationAcceptsDistinguishedNamesAndAuto(t *testing.T) {
	ldap := wireProbes()["ldap"]
	for _, baseDN := range []string{
		"auto", "AUTO", " auto ",
		"dc=example,dc=com", "DC=certistack, DC=test", "dc = example , dc = com",
		`CN=Smith\, John,OU=Sales,DC=example,DC=com`, `OU=Smith\2C John,DC=example,DC=com`,
		"CN=J. Smith+OU=Sales,DC=example,DC=com", "CN=André,DC=example,DC=com",
		"2.5.4.3=#0403616263,DC=example",
		"cn=" + strings.Repeat("a", ldapdn.MaxLength-3),
	} {
		probe := ldap
		probe.BaseDN = baseDN
		if lines := probeErrors(probe); len(lines) != 0 {
			t.Errorf("base_dn %.60q: %v", baseDN, lines)
		}
	}
	for _, context := range []string{"DC=certistack, DC=test", `OU=Smith\, John,DC=example,DC=com`, "CN=Configuration,DC=example,DC=com"} {
		probe := ldap
		probe.NamingContext = context
		if lines := probeErrors(probe); len(lines) != 0 {
			t.Errorf("naming_context %q: %v", context, lines)
		}
	}
	// "auto" is not a naming context: it is reserved for base_dn alone.
	probe := ldap
	probe.NamingContext = "auto"
	if lines := probeErrors(probe); !hasProbeError(lines, "naming_context", "distinguished name") {
		t.Errorf("naming_context auto: %v", lines)
	}
	if got := ldapDNProblem("dc=example,dc=com"); got != "" {
		t.Errorf("a DN has problem %q", got)
	}
}
