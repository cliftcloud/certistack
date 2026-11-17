// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

import "testing"

// The text a run journals before it adds the host probe address, and the strict
// reading of it that recovery settles from. The text is "host probe address
// <cidr> on <interface>", which journals already on a node carry, so it must
// not change; anything else is not read.
func TestHostAddressPendingRoundTripsAndReadsNothingElse(t *testing.T) {
	record := Record{AllocationPending: HostAddressPending("10.100.0.1/24", "csVn01")}
	if record.AllocationPending != "host probe address 10.100.0.1/24 on csVn01" {
		t.Fatalf("the text changed: %q (journals already written carry this one)", record.AllocationPending)
	}
	if iface, cidr, ok := record.PendingHostAddressAllocation(); !ok || iface != "csVn01" || cidr != "10.100.0.1/24" {
		t.Fatalf("read back (%q, %q, %v)", iface, cidr, ok)
	}
	if record.SDNAllocationPending() {
		t.Error("a host address was taken for an SDN object")
	}
	for _, text := range []string{
		"", "SDN zone csSb01", "SDN VNet csVn01", "VM 9123 creation",
		"host probe address", "host probe address 10.100.0.1/24", "host probe address 10.100.0.1/24 on",
		"host probe address 10.100.0.1/24 at csVn01", "host probe address 10.100.0.1/24 on csVn01 extra",
		"host probe address  on csVn01", "host probe address 10.100.0.1/24 on ", " host probe address 10.100.0.1/24 on csVn01",
	} {
		if _, _, ok := (&Record{AllocationPending: text}).PendingHostAddressAllocation(); ok {
			t.Errorf("%q was read as a host probe address", text)
		}
	}
}
