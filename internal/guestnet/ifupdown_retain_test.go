// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"strings"
	"testing"
)

const secondaryNICSource = `auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 198.51.100.10/24
    gateway 198.51.100.1

auto eth1
iface eth1 inet static
    address 198.51.100.20/24
`

func ifupdownAttachAllConfig(name string) Config {
	cfg := multiDiskConfig(bootOverlayPath)
	cfg.Mode, cfg.InterfaceName, cfg.OnlyNIC = modeIfupdown, name, false
	return cfg
}

func applyIfupdown(t *testing.T, files map[string]string, cfg Config) (*memGuest, Result, error) {
	t.Helper()
	guest := newMemGuest(t, files, ifupdownDir)
	result, err := guest.adapter().Apply(context.Background(), cfg)
	return guest, result, err
}

// The reported case. attach_all_nics attaches the source's other
// NICs and the documentation says they keep the guest's configuration, but the
// replacement file held only loopback and the recovered NIC's stanza: eth1 lost
// its address.
func TestIfupdownRecoveryKeepsTheStanzasOfTheOtherNICs(t *testing.T) {
	guest, result, err := applyIfupdown(t, map[string]string{ifupdownConfig: secondaryNICSource}, ifupdownAttachAllConfig("eth0"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeIfupdown {
		t.Fatalf("strategy = %q", result.Strategy)
	}
	replacement := guest.files[ifupdownConfig]
	for _, want := range []string{
		"auto eth0\niface eth0 inet static\n    address 10.100.0.10/24\n", // the recovery stanza
		"auto eth1\n", "iface eth1 inet static\n    address 198.51.100.20/24", // the secondary NIC, as it was
	} {
		if !strings.Contains(replacement, want) {
			t.Fatalf("the replacement lacks %q:\n%s", want, replacement)
		}
	}
	for _, forbidden := range []string{"198.51.100.10", "gateway 198.51.100.1", "source"} {
		if strings.Contains(replacement, forbidden) {
			t.Fatalf("the replacement keeps %q of the recovered NIC's own configuration:\n%s", forbidden, replacement)
		}
	}
	if strings.Count(replacement, "iface lo inet loopback") != 1 || strings.Count(replacement, "auto lo") != 1 {
		t.Fatalf("loopback is declared more than once:\n%s", replacement)
	}
	if guest.files[ifupdownOriginal] != secondaryNICSource {
		t.Fatalf("the original was not kept beside the replacement:\n%s", guest.files[ifupdownOriginal])
	}
}

// With the only NIC the replacement is the flat file it always was.
func TestIfupdownRecoveryWithTheOnlyNICStaysFlat(t *testing.T) {
	cfg := ifupdownAttachAllConfig("eth0")
	cfg.OnlyNIC = true
	guest, _, err := applyIfupdown(t, map[string]string{ifupdownConfig: secondaryNICSource}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if replacement := guest.files[ifupdownConfig]; strings.Contains(replacement, "eth1") || strings.Contains(replacement, "198.51.100") {
		t.Fatalf("with the only NIC every other interface is a stale name for it:\n%s", replacement)
	}
}

func TestIfupdownRecoveryKeepsWhatIncludedFilesDefineForOtherNICs(t *testing.T) {
	files := map[string]string{
		ifupdownConfig:                 "source /etc/network/interfaces.d/*\nauto lo\niface lo inet loopback\n",
		ifupdownFragments + "/10-eth0": "auto eth0\niface eth0 inet static\n    address 198.51.100.10/24\n    gateway 198.51.100.1\n    dns-nameservers 198.51.100.53\n",
		ifupdownFragments + "/20-eth1": "# the data network\nallow-hotplug eth1\niface eth1 inet static\n    address 198.51.100.20/24\n    post-up ip route add 203.0.113.0/24 \\\n        via 198.51.100.254\n",
		ifupdownFragments + "/30-eth1": "iface eth1 inet6 static\n    address 2001:db8::20/64\n",
	}
	guest, _, err := applyIfupdown(t, files, ifupdownAttachAllConfig("eth0"))
	if err != nil {
		t.Fatal(err)
	}
	replacement := guest.files[ifupdownConfig]
	for _, want := range []string{
		"allow-hotplug eth1\n",
		"iface eth1 inet static\n    address 198.51.100.20/24\n    post-up ip route add 203.0.113.0/24 \\\n        via 198.51.100.254\n", // a continued line, as written
		"iface eth1 inet6 static\n    address 2001:db8::20/64\n",
		"auto eth0\niface eth0 inet static\n    address 10.100.0.10/24\n",
	} {
		if !strings.Contains(replacement, want) {
			t.Fatalf("the replacement lacks %q:\n%s", want, replacement)
		}
	}
	for _, forbidden := range []string{"198.51.100.10", "gateway 198.51.100.1", "dns-nameservers", "source", "the data network"} {
		if strings.Contains(replacement, forbidden) {
			t.Fatalf("the replacement holds %q:\n%s", forbidden, replacement)
		}
	}
	for _, fragment := range []string{"10-eth0", "20-eth1", "30-eth1"} {
		if guest.mutated() && guest.files[ifupdownFragments+"/"+fragment] != files[ifupdownFragments+"/"+fragment] {
			t.Fatalf("the fragment %s was changed", fragment)
		}
	}
}

func TestIfupdownRecoveryDropsOnlyTheRecoveredNICFromListLines(t *testing.T) {
	files := map[string]string{ifupdownConfig: `auto lo eth0 eth1
allow-hotplug eth0
allow-hotplug eth2 eth0
iface lo inet loopback
iface eth0 inet dhcp
iface eth0 inet6 auto
iface eth1 inet dhcp
iface eth2 inet manual
`}
	guest, _, err := applyIfupdown(t, files, ifupdownAttachAllConfig("eth0"))
	if err != nil {
		t.Fatal(err)
	}
	replacement := guest.files[ifupdownConfig]
	// After the header the file declares the recovery stanza, then eth1 and eth2 as they were.
	for _, want := range []string{"auto eth1\n", "allow-hotplug eth2\n", "iface eth1 inet dhcp\n", "iface eth2 inet manual\n"} {
		if !strings.Contains(replacement, want) {
			t.Fatalf("the replacement lacks %q:\n%s", want, replacement)
		}
	}
	for _, forbidden := range []string{"allow-hotplug eth0", "eth0 inet dhcp", "eth0 inet6", "auto lo eth", "eth1 eth0"} {
		if strings.Contains(replacement, forbidden) {
			t.Fatalf("the replacement keeps %q:\n%s", forbidden, replacement)
		}
	}
	if strings.Count(replacement, "iface eth0 ") != 1 {
		t.Fatalf("the recovered NIC must have exactly its recovery stanza:\n%s", replacement)
	}
}

func TestIfupdownRecoveryNamesTheNICFromTheGuestWhenThereIsOne(t *testing.T) {
	guest, _, err := applyIfupdown(t, map[string]string{ifupdownConfig: "auto lo\niface lo inet loopback\nauto ens18\niface ens18 inet dhcp\n"}, ifupdownAttachAllConfig(""))
	if err != nil {
		t.Fatal(err)
	}
	if replacement := guest.files[ifupdownConfig]; !strings.Contains(replacement, "iface ens18 inet static") || strings.Contains(replacement, "dhcp") || strings.Contains(replacement, "guest's own stanzas") {
		t.Fatalf("replacement:\n%s", replacement)
	}
	// Several interfaces and several NICs: the recovered one has to be named.
	_, _, err = applyIfupdown(t, map[string]string{ifupdownConfig: secondaryNICSource}, ifupdownAttachAllConfig(""))
	if err == nil || !strings.Contains(err.Error(), "interface_name") {
		t.Fatalf("Apply = %v, want interface_name asked for", err)
	}
}

// A kept stanza built on the recovered NIC, or one CertiStack cannot interpret,
// is refused before anything is written: the alternative is the success the
// reporter found, with the guest's layout silently changed.
func TestIfupdownRecoveryRefusesWhatItCannotKeep(t *testing.T) {
	head := "auto lo\niface lo inet loopback\nauto eth0\niface eth0 inet manual\nauto eth1\niface eth1 inet static\n    address 198.51.100.20/24\n"
	cases := []struct {
		name    string
		extra   string
		wantErr string
	}{
		{"a bridge over the recovered NIC", "auto br0\niface br0 inet static\n    address 198.51.100.30/24\n    bridge_ports eth0 eth1\n", "br0"},
		{"a bridge over every NIC", "auto br0\niface br0 inet static\n    address 198.51.100.30/24\n    bridge-ports all\n", "br0"},
		{"a bridge over a pattern that matches it", "auto br0\niface br0 inet manual\n    bridge_ports eth*\n", "br0"},
		{"a bond with the recovered NIC as a member", "auto bond0\niface bond0 inet static\n    address 198.51.100.30/24\n    bond-slaves eth0 eth1\n", "bond0"},
		{"a VLAN named after the recovered NIC", "auto eth0.100\niface eth0.100 inet static\n    address 198.51.100.30/24\n", "eth0.100"},
		{"a VLAN on the recovered NIC", "auto vlan100\niface vlan100 inet static\n    address 198.51.100.30/24\n    vlan-raw-device eth0\n", "vlan100"},
		{"a mapping stanza", "mapping eth*\n    script /usr/local/bin/map\n    map HOME eth1\n", "mapping"},
		{"a rename stanza", "rename eth9=lan0\n", "rename"},
		{"a template stanza", "template eth5\n", "template"},
		{"an option outside any stanza", "auto eth2\n    address 1.2.3.4\n", "not in an iface or mapping stanza"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest, _, err := applyIfupdown(t, map[string]string{ifupdownConfig: head + tc.extra}, ifupdownAttachAllConfig("eth0"))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "attach_all_nics") {
				t.Fatalf("Apply = %v, want it refused naming %q and attach_all_nics", err, tc.wantErr)
			}
			if guest.mutated() {
				t.Fatal("something was written")
			}
		})
	}
	// A bridge over the other NIC does not depend on the recovered one.
	files := map[string]string{ifupdownConfig: head + "auto br0\niface br0 inet static\n    address 198.51.100.30/24\n    bridge_ports eth1\n"}
	guest, _, err := applyIfupdown(t, files, ifupdownAttachAllConfig("eth0"))
	if err != nil {
		t.Fatal(err)
	}
	if replacement := guest.files[ifupdownConfig]; !strings.Contains(replacement, "bridge_ports eth1") || !strings.Contains(replacement, "iface br0 inet static") {
		t.Fatalf("a bridge over the other NIC is not the recovered NIC's:\n%s", replacement)
	}
}

func TestParseIfupdownStanzasKeepsLinesAsWritten(t *testing.T) {
	stanzas, err := parseIfupdownStanzas("# top\n\nauto eth1 eth2\niface eth1 inet static\n\taddress 1.2.3.4/24 # not a comment in ifupdown\n  # a comment\n\tpre-up echo \\\n\t  hi\niface eth2 inet dhcp\nsource-directory /etc/x\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(stanzas) != 4 {
		t.Fatalf("stanzas = %+v", stanzas)
	}
	if got := strings.Join(stanzas[1].lines, "|"); got != "iface eth1 inet static|\taddress 1.2.3.4/24 # not a comment in ifupdown|\tpre-up echo \\\n\t  hi" {
		t.Fatalf("lines = %q", got)
	}
	if stanzas[0].keyword != "auto" || strings.Join(stanzas[0].fields, ",") != "auto,eth1,eth2" || stanzas[3].keyword != "source-directory" {
		t.Fatalf("stanzas = %+v", stanzas)
	}
}
