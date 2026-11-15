// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/probe"
)

func wireRecord(vmid int, results ...probe.Result) probe.VMValidationRecord {
	return probe.VMValidationRecord{VMID: vmid, ProbeResults: results}
}

func passed(probeType, target string) probe.Result {
	return probe.Result{Type: probeType, Target: target, Passed: true}
}

func TestRecordedTargetAddress(t *testing.T) {
	for target, want := range map[string]string{
		"10.100.0.10:389":                        "10.100.0.10",
		"http://10.100.0.10:8080/health":         "10.100.0.10",
		"https://10.100.0.10:443/":               "10.100.0.10",
		"udp://10.100.0.10:53":                   "10.100.0.10",
		"tcp://10.100.0.10:53":                   "10.100.0.10",
		"[::ffff:10.100.0.10]:389":               "10.100.0.10",
		"[fd00::10]:389":                         "fd00::10",
		"https://[fd00::10]:443/a?b=c":           "fd00::10",
		"http://10.100.0.10:80/a%2Fb":            "10.100.0.10",
		"10.100.0.10":                            "10.100.0.10",
		"mssql.example:1433":                     "",
		"systemctl is-active postgresql@16-main": "",
		"":                                       "",
	} {
		got, ok := recordedTargetAddress(target)
		if got != want || ok != (want != "") {
			t.Errorf("recordedTargetAddress(%q) = %q, %t; want %q", target, got, ok, want)
		}
	}
}

// What the rule finds in a report's records, and what it leaves alone.
func TestSharedWireTargetProblems(t *testing.T) {
	cases := []struct {
		name    string
		records []probe.VMValidationRecord
		want    []string // substrings, one per problem
	}{
		{"no records", nil, nil},
		{"distinct targets", []probe.VMValidationRecord{
			wireRecord(1, passed("tcp", "10.0.0.10:80")), wireRecord(2, passed("tcp", "10.0.0.11:80")),
		}, nil},
		{"one VM, several services on one address", []probe.VMValidationRecord{
			wireRecord(1, passed("tcp", "10.0.0.10:80"), passed("http", "http://10.0.0.10:80/"), passed("dns", "udp://10.0.0.10:53")),
		}, nil},
		{"the reporter's case: two VMs, one tcp target", []probe.VMValidationRecord{
			wireRecord(9200, passed("tcp", "10.100.0.10:389")), wireRecord(9201, passed("tcp", "10.100.0.10:389")),
		}, []string{"VMs 9200, 9201 each record a passing wire probe of 10.100.0.10"}},
		{"the same address through different probe types and ports", []probe.VMValidationRecord{
			wireRecord(2, passed("http", "https://10.0.0.10:443/health")), wireRecord(1, passed("ldap", "10.0.0.10:389")),
		}, []string{"VMs 1, 2 each record a passing wire probe of 10.0.0.10"}},
		{"the IPv4-mapped spelling is the same address", []probe.VMValidationRecord{
			wireRecord(1, passed("tcp", "10.0.0.10:80")), wireRecord(2, passed("tcp", "[::ffff:10.0.0.10]:80")),
		}, []string{"VMs 1, 2"}},
		{"IPv6 addresses", []probe.VMValidationRecord{
			wireRecord(1, passed("tcp", "[fd00::10]:80")), wireRecord(2, passed("smb", "[fd00::10]:445")),
		}, []string{"VMs 1, 2 each record a passing wire probe of fd00::10"}},
		{"three VMs and a second address", []probe.VMValidationRecord{
			wireRecord(3, passed("tcp", "10.0.0.10:80"), passed("tcp", "10.0.0.20:80")),
			wireRecord(1, passed("tcp", "10.0.0.10:80")),
			wireRecord(2, passed("tcp", "10.0.0.10:81"), passed("tcp", "10.0.0.20:81")),
		}, []string{"VMs 1, 2, 3 each record a passing wire probe of 10.0.0.10", "VMs 2, 3 each record a passing wire probe of 10.0.0.20"}},
		{"a failed probe credits no one", []probe.VMValidationRecord{
			wireRecord(1, passed("tcp", "10.0.0.10:80")),
			wireRecord(2, probe.Result{Type: "tcp", Target: "10.0.0.10:80", Passed: false}),
		}, nil},
		{"a skipped probe credits no one", []probe.VMValidationRecord{
			wireRecord(1, passed("tcp", "10.0.0.10:80")),
			wireRecord(2, probe.Result{Type: "tcp", Target: "10.0.0.10:80", Passed: true, Skipped: true}),
		}, nil},
		{"guest-agent and hypervisor probes are not wire probes", []probe.VMValidationRecord{
			wireRecord(1, passed("qga", "10.0.0.10:80"), passed("qmp", "/var/run/qemu-server/9001.qmp")),
			wireRecord(2, passed("qga", "10.0.0.10:80"), passed("qmp", "/var/run/qemu-server/9001.qmp")),
		}, nil},
		{"a VM recorded twice is not two VMs", []probe.VMValidationRecord{
			wireRecord(1, passed("tcp", "10.0.0.10:80")), wireRecord(1, passed("tcp", "10.0.0.10:80")),
		}, nil},
	}
	for _, tc := range cases {
		got := SharedWireTargetProblems(tc.records)
		if len(got) != len(tc.want) {
			t.Errorf("%s: problems = %q, want %d", tc.name, got, len(tc.want))
			continue
		}
		for i, want := range tc.want {
			if !strings.Contains(got[i], want) {
				t.Errorf("%s: problem %d = %q, want it to contain %q", tc.name, i, got[i], want)
			}
		}
	}
}
