// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package ifname decides which names CertiStack accepts for the Linux network
// interface of a restored guest (network_recovery.interface_name). The plan
// validator and the guest-network adapter share this one rule, so a name the
// plan accepts is a name the adapter writes and the other way round.
//
// Linux's own rule (net/core/dev.c, dev_valid_name) is looser: one to fifteen
// bytes, not "." or "..", and no "/", ":" or white space. CertiStack accepts a
// subset of it, because the name is written into an ifupdown stanza, an
// ifcfg file name and a systemd .link file: ASCII letters, digits, "_", "-"
// and ".", and never the loopback name "lo".
package ifname

// MaxLength is the longest interface name Linux accepts (IFNAMSIZ is 16,
// including the terminating NUL).
const MaxLength = 15

// Describe is the rule in words, for validation errors and documents.
const Describe = "1 to 15 characters from letters, digits, '_', '-' and '.'; not \"lo\", \".\" or \"..\""

// Valid reports whether name is an interface name CertiStack writes into a
// guest. "." and ".." pass a character allowlist but are the two names the
// kernel refuses outright (RTNETLINK answers: Invalid argument), so the guest
// could never give its NIC that name.
func Valid(name string) bool {
	if name == "" || len(name) > MaxLength || name == "lo" || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}
