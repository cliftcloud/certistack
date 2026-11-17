// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package qgacommand

import (
	"strings"
	"testing"
)

func TestAllowed(t *testing.T) {
	for command, want := range map[string]bool{
		"hostname":                               true,
		"guest-get-host-name":                    true,
		"ping":                                   true,
		"guest-ping":                             true,
		"  guest-ping\t":                         true, // the prober trims, so the list does
		"systemctl is-active postgresql":         true,
		"systemctl is-active postgresql@16-main": true,
		"systemctl is-active nginx.service":      true,
		"sc query W3SVC":                         true,
		"sc query MSSQL$SQLEXPRESS":              true,
		"sc query LanmanServer":                  true,

		// Anything else reaches /bin/sh -c in the guest.
		"":                                    false,
		"   ":                                 false,
		"printf audit-qga-alias-marker":       false,
		"id":                                  false,
		"hostname; id":                        false,
		"ping -c1 192.0.2.1":                  false,
		"systemctl is-active":                 false,
		"systemctl is-active ssh; id":         false,
		"systemctl is-active ssh && id":       false,
		"systemctl is-active $(id)":           false,
		"systemctl is-active `id`":            false,
		"systemctl is-active ssh\nid":         false,
		"systemctl is-active -- ssh":          false,
		"systemctl is-active -q ssh":          false,
		"systemctl is-active a b":             false,
		"systemctl stop ssh":                  false,
		"systemctl  is-active ssh":            false,
		"SYSTEMCTL is-active ssh":             false,
		"sc query W3SVC & whoami":             false,
		"sc query W3SVC; shutdown /s":         false,
		"sc query \"W3SVC\"":                  false,
		"sc query":                            false,
		"sc stop W3SVC":                       false,
		"sc query W3SVC\r\nwhoami":            false,
		"powershell.exe -Command Get-Service": false,
		"systemctl is-active " + strings.Repeat("a", 129): false,
		"sc query " + strings.Repeat("a", 257):            false,
	} {
		if got := Allowed(command); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", command, got, want)
		}
	}
}
