// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"testing"
)

func TestNetworkCompetitorsIncludeEverySystemdDirectory(t *testing.T) {
	for _, dir := range []string{"/etc/systemd/network", "/run/systemd/network", "/usr/local/lib/systemd/network", "/usr/lib/systemd/network", "/lib/systemd/network"} {
		t.Run(dir, func(t *testing.T) {
			guest := newMemGuest(t, map[string]string{
				dir + "/00-other.network": "[Match]\nMACAddress=" + recoveryMAC + "\n[Network]\nDHCP=yes\n",
			}, systemdNetworkdDir)
			d := newDetection(&Adapter{run: guest.run}, []string{"/synthetic/overlay"}, recoveryMAC)
			names, err := d.systemdFilesBefore(context.Background(), ".network", "")
			if err != nil {
				t.Fatal(err)
			}
			if len(names) != 1 || names[0] != "00-other.network" {
				t.Fatalf("competitors in %s: %v", dir, names)
			}
		})
	}
}

func TestNetworkNameMatchesExcludeOtherInterfaces(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		matches bool
	}{
		{"host0", false}, {"ve-*", false}, {"en*", true}, {"ens18", true}, {"eth0 ens18", true}, {"", true}, {"!host0", true},
	} {
		if got := systemdMayMatchForName("[Match]\nName="+tc.pattern+"\n", recoveryMAC, "ens18"); got != tc.matches {
			t.Errorf("Name=%s: %v, want %v", tc.pattern, got, tc.matches)
		}
	}
	if !systemdMayMatchForName("[Match]\nName=host0\n", recoveryMAC, "") {
		t.Fatal("an unknown offline name was guessed")
	}
}

func TestOwnershipScanKeepsItsDirectoryScopeSeparateFromCompetitors(t *testing.T) {
	g := newMemGuest(t, map[string]string{
		"/usr/lib/systemd/network/80-container.network": "[Match]\nMACAddress=" + recoveryMAC + "\n",
	}, systemdNetworkdDir)
	d := newDetection(&Adapter{run: g.run}, []string{"/synthetic/overlay"}, recoveryMAC)
	all, err := d.systemdFilesBefore(context.Background(), ".network", "")
	if err != nil {
		t.Fatal(err)
	}
	local, err := d.systemdFilesBeforeIn(context.Background(), ".network", "", []string{systemdNetworkdDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || len(local) != 0 {
		t.Fatalf("all=%v local=%v; scan scopes shared a cache entry", all, local)
	}
}
