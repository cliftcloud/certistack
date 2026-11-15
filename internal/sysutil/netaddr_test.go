// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"strings"
	"testing"
)

func TestValidateInterfaceAddress(t *testing.T) {
	if err := validateInterfaceAddress("csVn70", "10.60.70.1/24"); err != nil {
		t.Fatalf("valid interface address rejected: %v", err)
	}
	for _, tc := range []struct {
		iface string
		cidr  string
	}{
		{iface: "", cidr: "10.60.70.1/24"},
		{iface: "cs Vn70", cidr: "10.60.70.1/24"},
		{iface: "csVn70", cidr: "not-a-cidr"},
	} {
		if err := validateInterfaceAddress(tc.iface, tc.cidr); err == nil {
			t.Errorf("validateInterfaceAddress(%q, %q) unexpectedly succeeded", tc.iface, tc.cidr)
		}
	}
}

func TestInterfaceAddressAlreadyAbsent(t *testing.T) {
	for _, output := range []string{
		"Cannot find device \"csVn70\"",
		"RTNETLINK answers: Cannot assign requested address",
		"Error: ipv4: Address not found.",
	} {
		if !interfaceAddressAlreadyAbsent(output) {
			t.Fatalf("already-absent address result was not recognized: %q", output)
		}
	}
	if interfaceAddressAlreadyAbsent("permission denied") {
		t.Fatal("unexpectedly accepted a non-idempotent address removal failure")
	}
}

func TestIsolationTableNameAndScript(t *testing.T) {
	table := isolationTableName("csVn70", "10.60.70.1/24")
	if !strings.HasPrefix(table, "csiso_") {
		t.Fatalf("table name = %q, want csiso_ prefix", table)
	}
	if len(table) > 31 {
		t.Fatalf("table name = %q, exceeds nft identifier budget", table)
	}
	script := isolationNFTScript(table, "csVn70")
	for _, want := range []string{
		"add table inet " + table,
		`iifname "csVn70" ct state established,related accept`,
		`iifname "csVn70" drop`,
		`forward iifname "csVn70" drop`,
		`forward oifname "csVn70" drop`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("isolation script does not contain %q:\n%s", want, script)
		}
	}
}

func TestNftObjectAlreadyAbsent(t *testing.T) {
	if !nftObjectAlreadyAbsent(&Result{Stderr: []byte("Error: table does not exist")}) {
		t.Fatal("missing nft table was not treated as already absent")
	}
	if nftObjectAlreadyAbsent(&Result{Stderr: []byte("permission denied")}) {
		t.Fatal("permission failure was incorrectly treated as already absent")
	}
}
