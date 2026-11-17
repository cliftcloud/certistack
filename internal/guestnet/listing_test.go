// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"slices"
	"strings"
	"testing"
)

const enforcingLabel = "system_u:object_r:NetworkManager_etc_rw_t:s0"

func TestListingEntriesKeepEveryNameWhole(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   []string
	}{
		{"empty directory", "", nil},
		{"only a newline", "\n", nil},
		{"one entry, trailing newline", "a.nmconnection\n", []string{"a.nmconnection"}},
		{"one entry, none", "a.nmconnection", []string{"a.nmconnection"}},
		{"a space in the name", "Wired connection 1.nmconnection\n", []string{"Wired connection 1.nmconnection"}},
		{"several spaces and a trailing one", "a  b .nmconnection \n", []string{"a  b .nmconnection "}},
		{"leading spaces", " lead.nmconnection\n", []string{" lead.nmconnection"}},
		{"a tab", "tab\tname.nmconnection\n", []string{"tab\tname.nmconnection"}},
		{"a leading dash", "-dash.nmconnection\n", []string{"-dash.nmconnection"}},
		{"unicode", "Ünï cödé 日本.nmconnection\n", []string{"Ünï cödé 日本.nmconnection"}},
		{"several entries", "Wired connection 1.nmconnection\nb.nmconnection\n", []string{"Wired connection 1.nmconnection", "b.nmconnection"}},
		{"blank lines between entries", "a\n\nb\n", []string{"a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := listingEntries(tc.output); !slices.Equal(got, tc.want) {
				t.Fatalf("listingEntries(%q) = %q, want %q", tc.output, got, tc.want)
			}
		})
	}
}

func TestSafeEntryName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"a.nmconnection", true},
		{"Wired connection 1.nmconnection", true},
		{"tab\tname", true},
		{"-leading-dash", true},
		{"Ünï cödé 日本", true},
		{".hidden", true},
		{"", false},
		{".", false},
		{"..", false},
		{"a/b", false},
		{"../x", false},
		{"a\nb", false},
		{"a\rb", false},
		{"a\x00b", false},
		{"a\x1bb", false},
		{"a\x7fb", false},
		{"a\xffb", false},
	}
	for _, tc := range cases {
		if got := safeEntryName(tc.name); got != tc.want {
			t.Errorf("safeEntryName(%q) = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// The only profile of a NetworkManager guest is the automatically named
// "Wired connection 1.nmconnection". Split on spaces it would read as "Wired",
// "connection" and "1.nmconnection", and the seed copy would go to
// /etc/NetworkManager/system-connections/1.nmconnection, which does not exist.
// The name with hyphens is the control.
func TestApplySeedsFromANetworkManagerProfileWithSpacesInItsName(t *testing.T) {
	for _, name := range []string{"Wired connection 1.nmconnection", "Wired-connection-1.nmconnection"} {
		t.Run(name, func(t *testing.T) {
			seed := networkManagerDir + "/" + name
			guest := newMemGuest(t, map[string]string{seed: "[connection]\nid=Wired connection 1\n"}, networkManagerDir)
			// On an enforcing SELinux guest only a copy of the guest's own profile
			// has the label NetworkManager is allowed to read.
			guest.attrs[seed] = memAttr{label: enforcingLabel}
			cfg := multiDiskConfig(bootOverlayPath)
			cfg.Mode = modeNetworkManager
			if _, err := guest.adapter().Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			batch := lastBatch(guest.calls)
			if !batchHasCommand(batch, "cp-a", seed, networkManagerProfile) {
				t.Fatalf("the batch did not copy the whole seed path %q: %#v", seed, batch)
			}
			if got := guest.attrs[networkManagerProfile].label; got != enforcingLabel {
				t.Fatalf("the recovery profile's label = %q, want the seed's %q", got, enforcingLabel)
			}
		})
	}
}

// Several candidates, one of them with a name that cannot be used: the first
// usable one is chosen whole.
func TestProfileSeedChoiceAmongNamesWithSpacesAndOddCharacters(t *testing.T) {
	cases := []struct {
		name    string
		entries []string
		want    string
	}{
		{"a spaced name first", []string{"Wired connection 1.nmconnection", "other.nmconnection"}, "Wired connection 1.nmconnection"},
		{"a tab in the name", []string{"tab\tname.nmconnection"}, "tab\tname.nmconnection"},
		{"a leading dash", []string{"-first.nmconnection", "second.nmconnection"}, "-first.nmconnection"},
		{"unicode", []string{"Ünï cödé 日本.nmconnection"}, "Ünï cödé 日本.nmconnection"},
		{"the recovery profile itself is not a seed", []string{"90-certistack-recovery.nmconnection", "b b.nmconnection"}, "b b.nmconnection"},
		{"files of another kind are not seeds", []string{"README", "x y.keyfile", "z z.nmconnection"}, "z z.nmconnection"},
		{"a control character", []string{"a\x1bb.nmconnection", "ok one.nmconnection"}, "ok one.nmconnection"},
		{"nothing usable", []string{"a\x1bb.nmconnection"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			for _, entry := range tc.entries {
				files[networkManagerDir+"/"+entry] = "[connection]\n"
			}
			guest := newMemGuest(t, files, networkManagerDir)
			detect := newDetection(guest.adapter(), []string{bootOverlayPath}, ownerMAC)
			got, err := guest.adapter().profileSeedSource(context.Background(), detect, modeNetworkManager, networkManagerProfile)
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if tc.want != "" {
				want = networkManagerDir + "/" + tc.want
			}
			if got != want {
				t.Fatalf("seed = %q, want %q", got, want)
			}
		})
	}
}

// The same split hurt every other place a directory listing is read.
func TestListingsWithSpacedNamesDoNotBreakOtherBackends(t *testing.T) {
	t.Run("legacy ifcfg profile names are matched whole", func(t *testing.T) {
		// "ifcfg-my nic" is no interface name; it must not become "ifcfg-my"
		// and "nic" (read as files that are not there) on the way to eth0.
		files := map[string]string{
			ifcfgDir + "/ifcfg-my nic": "HWADDR=ff:ff:ff:ff:ff:ff\n",
			ifcfgDir + "/ifcfg-eth0":   "DEVICE=eth0\nHWADDR=BC:24:11:90:01:01\n",
		}
		guest := newMemGuest(t, files, ifcfgDir)
		profile, found, err := guest.adapter().ifcfgProfileForMAC(context.Background(), []string{bootOverlayPath}, "BC:24:11:90:01:01")
		if err != nil || !found || profile.iface != "eth0" || profile.file != ifcfgDir+"/ifcfg-eth0" {
			t.Fatalf("ifcfgProfileForMAC = %+v, %t, %v; want eth0 from ifcfg-eth0", profile, found, err)
		}
	})
	t.Run("a netplan file with spaces in its name is read", func(t *testing.T) {
		files := map[string]string{
			"/etc/netplan/50 cloud init.yaml": "network:\n  version: 2\n  ethernets:\n    ens18:\n      match:\n        macaddress: 'bc:24:11:90:01:01'\n      dhcp4: true\n",
		}
		guest := newMemGuest(t, files, netplanDir)
		cfg := multiDiskConfig(bootOverlayPath)
		cfg.Mode = modeNetplan
		cfg.OnlyNIC = true
		result, err := guest.adapter().Apply(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if result.Strategy != modeNetplan {
			t.Fatalf("strategy = %q, want netplan", result.Strategy)
		}
	})
	t.Run("a systemd-networkd file with spaces in its name is read", func(t *testing.T) {
		// The name sorts before the recovery file's, so it is read; its second
		// word is itself a plausible file name, which a split on spaces would read.
		files := map[string]string{
			"/etc/systemd/network/00-a 00-b.network": "[Match]\nMACAddress=ff:ff:ff:ff:ff:ff\n\n[Network]\nDHCP=yes\n",
		}
		guest := newMemGuest(t, files, systemdNetworkdDir)
		cfg := multiDiskConfig(bootOverlayPath)
		cfg.Mode = modeSystemdNetworkd
		result, err := guest.adapter().Apply(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if result.Strategy != modeSystemdNetworkd {
			t.Fatalf("strategy = %q, want systemd-networkd", result.Strategy)
		}
	})
	t.Run("a firewalld zone file with a space is refused for its name", func(t *testing.T) {
		files := map[string]string{
			firewalldZoneDir + "/public.xml":  "<zone>\n</zone>\n",
			firewalldZoneDir + "/my zone.xml": "<zone>\n</zone>\n",
		}
		guest := newMemGuest(t, files, firewalldDir, firewalldZoneDir)
		_, err := guest.adapter().readGuestZones(context.Background(), []string{bootOverlayPath})
		if err == nil || !strings.Contains(err.Error(), "my zone.xml") || !strings.Contains(err.Error(), "safe zone name") {
			t.Fatalf("readGuestZones = %v, want the spaced zone file named as unsafe", err)
		}
	})
}
