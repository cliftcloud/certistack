// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package macaddr

import (
	"net"
	"strings"
	"testing"
)

// Four values (zero, broadcast, an IPv4 multicast address and an IPv6
// multicast address) pass net.ParseMAC as six octets, and Linux refuses all of
// them on a real interface. Each is refused here, in every spelling, and a
// locally administered unicast control passes.
func TestParseRefusesWhatNoInterfaceCanHold(t *testing.T) {
	refused := map[string]string{
		"00:00:00:00:00:00": "all-zero",
		"FF:FF:FF:FF:FF:FF": "broadcast",
		"ff:ff:ff:ff:ff:ff": "broadcast",
		"ff-ff-ff-ff-ff-ff": "broadcast",
		"ffff.ffff.ffff":    "broadcast",
		"0000.0000.0000":    "all-zero",
		"01:00:5E:00:00:01": "multicast",
		"33:33:00:00:00:01": "multicast",
		"01:00:00:00:00:00": "multicast",
		"03:00:00:00:00:00": "multicast",
		"AB:00:00:00:00:00": "multicast",
		"fd:11:22:33:44:55": "multicast",
	}
	for mac, word := range refused {
		if _, err := Parse(mac); err == nil || !strings.Contains(err.Error(), word) {
			t.Errorf("Parse(%q) = %v, want an error naming the %s address", mac, err, word)
		}
		if Valid(mac) {
			t.Errorf("Valid(%q) = true", mac)
		}
		if _, err := Canonical(mac); err == nil {
			t.Errorf("Canonical(%q) succeeded", mac)
		}
	}
}

func TestParseRefusesWhatIsNotSixOctets(t *testing.T) {
	for _, mac := range []string{
		"", " ", "not-a-mac", "02:AA:BB:CC:DD", "02:AA:BB:CC:DD:EE:FF", "02:AA:BB:CC:DD:EG",
		" 02:AA:BB:CC:DD:EE", "02:AA:BB:CC:DD:EE ", "02:AA:BB:CC:DD:EE,bridge=vmbr0",
		"02:AA:BB:CC:DD:EE\n", "0200.5e10.0000.0001", // an EUI-64 and an eight-octet address
		"02:00:5e:10:00:00:00:01", "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
		"2:AA:BB:CC:DD:EE", "02:AA:BB:CC:DD:EE:", "0xAABBCCDDEEFF",
	} {
		if _, err := Parse(mac); err == nil || !strings.Contains(err.Error(), "six-octet") {
			t.Errorf("Parse(%q) = %v, want a six-octet error", mac, err)
		}
	}
}

func TestParseAcceptsIndividualAddressesInEverySpelling(t *testing.T) {
	for _, mac := range []string{
		"02:AA:BB:CC:DD:EE", "02:aa:bb:cc:dd:ee", "02-AA-BB-CC-DD-EE", "02aa.bbcc.ddee",
		"BC:24:11:D8:F8:DD", "00:11:22:33:44:55", "FE:FF:FF:FF:FF:FF", "00:00:00:00:00:01",
		"52:54:00:12:34:56", "FC:FF:FF:FF:FF:FF",
	} {
		got, err := Parse(mac)
		if err != nil || len(got) != 6 {
			t.Errorf("Parse(%q) = %v, %v", mac, got, err)
		}
	}
}

// Every one of the 256 first octets: a group address is exactly an odd one.
func TestParseFirstOctetGroupBit(t *testing.T) {
	for first := 0; first < 256; first++ {
		mac := net.HardwareAddr{byte(first), 0x11, 0x22, 0x33, 0x44, 0x55}.String()
		if got, want := Valid(mac), first&1 == 0; got != want {
			t.Errorf("Valid(%s) = %t, want %t", mac, got, want)
		}
	}
}

func TestCanonicalIsPVEsSpelling(t *testing.T) {
	for in, want := range map[string]string{
		"02:aa:bb:cc:dd:ee": "02:AA:BB:CC:DD:EE",
		"02-aa-bb-cc-dd-ee": "02:AA:BB:CC:DD:EE",
		"02aa.bbcc.ddee":    "02:AA:BB:CC:DD:EE",
		"02:AA:BB:CC:DD:EE": "02:AA:BB:CC:DD:EE",
	} {
		if got, err := Canonical(in); err != nil || got != want {
			t.Errorf("Canonical(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
}

func TestEqualComparesTheAddressNotTheSpelling(t *testing.T) {
	if !Equal("02:aa:bb:cc:dd:ee", "02-AA-BB-CC-DD-EE") {
		t.Error("the same address in two spellings is not equal")
	}
	if Equal("02:AA:BB:CC:DD:EE", "02:AA:BB:CC:DD:EF") {
		t.Error("two addresses are equal")
	}
	// An unusable value is not the same address as anything, itself included:
	// two zero addresses are not "the same NIC".
	if Equal("00:00:00:00:00:00", "00:00:00:00:00:00") || Equal("", "") || Equal("junk", "junk") {
		t.Error("an unusable value equals itself")
	}
}

// The registry sees through case and spelling, reports who holds the
// address, and keeps the first holder.
func TestRegistryRefusesASecondHolderInAnySpelling(t *testing.T) {
	var registry Registry
	if prior, ok := registry.Claim("02:AA:BB:CC:DD:EE", "VM 9900 net0"); !ok || prior != "" {
		t.Fatalf("first claim: %q %t", prior, ok)
	}
	for _, again := range []string{"02:AA:BB:CC:DD:EE", "02:aa:bb:cc:dd:ee", "02-AA-BB-CC-DD-EE", "02aa.bbcc.ddee"} {
		prior, ok := registry.Claim(again, "VM 9901 net0")
		if ok || prior != "VM 9900 net0" {
			t.Errorf("Claim(%q) = %q, %t, want the first holder and false", again, prior, ok)
		}
	}
	if prior, ok := registry.Claim("02:AA:BB:CC:DD:EF", "VM 9901 net0"); !ok || prior != "" {
		t.Errorf("a distinct address was refused: %q %t", prior, ok)
	}
	// A refused claim recorded nothing: the first holder keeps the address.
	if prior, _ := registry.Claim("02:AA:BB:CC:DD:EE", "VM 9902 net0"); prior != "VM 9900 net0" {
		t.Errorf("holder after refused claims = %q", prior)
	}
}

// What is not an acceptable address is the caller's to refuse, not a
// collision: two unusable values are two errors, not one duplicate.
func TestRegistryTreatsAnUnusableAddressAsFree(t *testing.T) {
	var registry Registry
	for i := 0; i < 2; i++ {
		if prior, ok := registry.Claim("00:00:00:00:00:00", "owner"); !ok || prior != "" {
			t.Fatalf("claim %d of an unusable address: %q %t", i, prior, ok)
		}
	}
}
