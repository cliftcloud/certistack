// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package ifname

import (
	"strings"
	"testing"
)

// "." and ".." passed the character allowlist, but the kernel
// refuses them, so a guest could never give its NIC either name.
func TestValid(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"eth0", true},
		{"ens18", true},
		{"enp6s18", true},
		{"eth0.100", true},
		{"my-nic_1", true},
		{"A", true},
		{"-", true},
		{"..a", true},
		{"a..", true},
		{strings.Repeat("a", 15), true},
		{strings.Repeat("a", 16), false},
		{"", false},
		{"lo", false},
		{"Lo", true}, // Linux names are case-sensitive; only "lo" is the loopback
		{".", false},
		{"..", false},
		{"...", true},
		{"a/b", false},
		{"a:b", false},
		{"a b", false},
		{"a\tb", false},
		{"a\nb", false},
		{"eth0;bad", false},
		{"eth0\x00", false},
		{"é", false},
		{"ens18é", false},
		{"eth$0", false},
		{"eth*", false},
		{"eth0\\", false},
	}
	for _, tc := range cases {
		if got := Valid(tc.name); got != tc.want {
			t.Errorf("Valid(%q) = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// Every allowed punctuation character is accepted inside a name and nothing
// else in the printable ASCII range is.
func TestValidPunctuation(t *testing.T) {
	for c := byte(0x20); c < 0x7f; c++ {
		name := "a" + string(c) + "b"
		allowed := c == '_' || c == '-' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if got := Valid(name); got != allowed {
			t.Errorf("Valid(%q) = %t, want %t", name, got, allowed)
		}
	}
}
