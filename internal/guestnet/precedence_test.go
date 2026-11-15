// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"strings"
	"testing"
	"time"
)

const recoveryMAC = "02:00:00:00:00:61"

func recoveryConfig() Config {
	return Config{VMID: 990061, Overlays: []string{"/synthetic/overlay.qcow2"}, MAC: recoveryMAC, Address: "192.0.2.10", CIDR: "192.0.2.0/24", OnlyNIC: true}
}

// ubuntuNetplanGuest is a Ubuntu server layout: netplan files, networkd
// enabled the way `systemctl enable` does it, an empty /etc/systemd/network.
func ubuntuNetplanGuest(t *testing.T, netplan map[string]string, extra map[string]string) *memGuest {
	t.Helper()
	files := map[string]string{
		"/etc/systemd/system/multi-user.target.wants/systemd-networkd.service": "-> /lib/systemd/system/systemd-networkd.service",
		"/etc/systemd/system/dbus-org.freedesktop.network1.service":            "-> /lib/systemd/system/systemd-networkd.service",
		"/lib/systemd/system/systemd-networkd.service":                         "[Unit]\nDescription=Network Configuration\n",
	}
	for name, contents := range netplan {
		files["/etc/netplan/"+name] = contents
	}
	for name, contents := range extra {
		files[name] = contents
	}
	return newMemGuest(t, files, "/etc/systemd/network")
}

const cloudInitStaticAll = `network:
  version: 2
  renderer: networkd
  ethernets:
    all:
      match:
        macaddress: '02:00:00:00:00:61'
      addresses: [198.51.100.10/24]
      routes:
        - to: default
          via: 198.51.100.1
      nameservers:
        addresses: [203.0.113.53]
`

// An existing definition whose networkd file sorts first would keep
// the guest's old address, route and DNS, whatever the recovery file is
// called. The recovery definition takes an ID that sorts before every
// definition that can match the recovered NIC, and the guest's own generator
// then selects it.
func TestNetplanRecoveryDefinitionIsTheOneNetworkdApplies(t *testing.T) {
	sorted := func(id string) string { return "10-netplan-" + id + ".network" }
	cases := []struct {
		name    string
		netplan map[string]string
		wantID  string
	}{
		{
			// The reported case: ID "all" sorts before "certistack-recovery".
			name:    "existing definition sorts first",
			netplan: map[string]string{"50-cloud-init.yaml": cloudInitStaticAll},
			wantID:  "Certistack-recovery",
		},
		{
			// The reporter's control: the same definition named ens18.
			name:    "existing definition sorts after",
			netplan: map[string]string{"50-cloud-init.yaml": strings.Replace(cloudInitStaticAll, "    all:", "    ens18:", 1)},
			wantID:  "certistack-recovery",
		},
		{
			// One ID defined in two files (cloud-init's, then an
			// administrator's) is one definition: the MAC comes from the
			// second file. Another definition is bound to another NIC.
			name: "definition merged across files",
			netplan: map[string]string{
				"50-cloud-init.yaml": "network:\n  version: 2\n  ethernets:\n    alpha:\n      dhcp4: true\n",
				"60-static.yaml":     "network:\n  version: 2\n  ethernets:\n    alpha:\n      match:\n        macaddress: 02:00:00:00:00:61\n      addresses: [198.51.100.10/24]\n      routes:\n        - to: default\n          via: 198.51.100.1\n",
				"70-other.yaml":      "network:\n  version: 2\n  ethernets:\n    aaa:\n      match:\n        macaddress: 02:00:00:00:00:99\n      dhcp4: true\n",
			},
			wantID: "Certistack-recovery",
		},
		{
			// Bound to another NIC's MAC: it cannot select this NIC, so the
			// recovery definition keeps its usual ID.
			name:    "definition for another NIC is ignored",
			netplan: map[string]string{"50-cloud-init.yaml": strings.Replace(cloudInitStaticAll, "02:00:00:00:00:61", "02:00:00:00:00:99", 1)},
			wantID:  "certistack-recovery",
		},
		{
			// Matched by name or driver, not by MAC: it can select this NIC.
			name:    "definition matched by name may select the NIC",
			netplan: map[string]string{"50-cloud-init.yaml": "network:\n  version: 2\n  ethernets:\n    all:\n      match:\n        name: 'en*'\n      dhcp4: true\n"},
			wantID:  "Certistack-recovery",
		},
		{
			// Bonds, bridges and VLANs are not selected by the NIC's MAC.
			name:    "other definition types are not competitors",
			netplan: map[string]string{"50-cloud-init.yaml": "network:\n  version: 2\n  ethernets:\n    ens19: {}\n    ens20: {}\n  bonds:\n    aaa:\n      interfaces: [ens19, ens20]\n      addresses: [198.51.100.11/24]\n"},
			wantID:  "certistack-recovery",
		},
		{
			// A capital sorts before lowercase IDs but not before a digit.
			name:    "definition starting with a digit",
			netplan: map[string]string{"50-cloud-init.yaml": "network:\n  version: 2\n  ethernets:\n    0abc:\n      dhcp4: true\n"},
			wantID:  "0-certistack-recovery",
		},
		{
			// An ID that sorts before "0-certistack-recovery" too.
			name:    "definition starting with a symbol",
			netplan: map[string]string{"50-cloud-init.yaml": "network:\n  version: 2\n  ethernets:\n    -dhcp:\n      dhcp4: true\n"},
			wantID:  "-certistack-recovery",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest := ubuntuNetplanGuest(t, tc.netplan, nil)
			original := map[string]string{}
			for name, contents := range guest.files {
				original[name] = contents
			}
			result, err := guest.adapter().Apply(context.Background(), recoveryConfig())
			if err != nil {
				t.Fatal(err)
			}
			if result.Strategy != modeNetplan || result.Files[0] != netplanProfile {
				t.Fatalf("result = %+v", result)
			}
			for name, contents := range original {
				if guest.files[name] != contents {
					t.Fatalf("the guest's own %s changed", name)
				}
			}
			if profile := guest.files[netplanProfile]; !strings.Contains(profile, "\n    "+tc.wantID+":\n") {
				t.Fatalf("recovery definition is not %q:\n%s", tc.wantID, profile)
			}
			name, contents := guest.networkdSelection(recoveryMAC)
			if name != sorted(tc.wantID) {
				t.Fatalf("the guest's generator has networkd apply %s first, want the recovery definition %s", name, sorted(tc.wantID))
			}
			if !strings.Contains(contents, "Address=192.0.2.10/24") || strings.Contains(contents, "198.51.100") || strings.Contains(contents, "Gateway=") || strings.Contains(contents, "DNS=") {
				t.Fatalf("the file networkd selects is not the isolated recovery profile:\n%s", contents)
			}
		})
	}
}

// The netplan renderer decides which backend reads a definition; a
// networkd recovery file never overrides a NetworkManager connection.
func TestNetplanRecoveryRefusesWhatNetworkdWouldNotApply(t *testing.T) {
	cases := []struct {
		name    string
		netplan map[string]string
		extra   map[string]string
		want    string
	}{
		{
			name:    "global renderer NetworkManager for the NIC's definition",
			netplan: map[string]string{"50-cloud-init.yaml": "network:\n  version: 2\n  renderer: NetworkManager\n  ethernets:\n    ens18:\n      dhcp4: true\n"},
			want:    "ens18 (NetworkManager)",
		},
		{
			name:    "renderer of the ethernets section",
			netplan: map[string]string{"50-cloud-init.yaml": "network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    renderer: NetworkManager\n    ens18:\n      dhcp4: true\n"},
			want:    "ens18 (NetworkManager)",
		},
		{
			name:    "renderer of the definition",
			netplan: map[string]string{"50-cloud-init.yaml": "network:\n  version: 2\n  ethernets:\n    ens18:\n      renderer: NetworkManager\n      match:\n        macaddress: 02:00:00:00:00:61\n"},
			want:    "ens18 (NetworkManager)",
		},
		{
			// A global renderer set in a later file applies to every file.
			name: "global renderer set by a later file",
			netplan: map[string]string{
				"50-cloud-init.yaml": "network:\n  version: 2\n  ethernets:\n    ens18:\n      dhcp4: true\n",
				"99-desktop.yaml":    "network:\n  version: 2\n  renderer: NetworkManager\n",
			},
			want: "ens18 (NetworkManager)",
		},
		{
			name:    "a file netplan cannot read",
			netplan: map[string]string{"50-cloud-init.yaml": "network:\n  version: 2\n  ethernets: [unbalanced\n"},
			want:    "/etc/netplan/50-cloud-init.yaml cannot be read",
		},
		{
			// networkd applies its own file first, and it sorts before every
			// netplan-generated one.
			name:    "a networkd file that sorts before netplan's",
			netplan: map[string]string{"50-cloud-init.yaml": strings.Replace(cloudInitStaticAll, "    all:", "    ens18:", 1)},
			extra:   map[string]string{"/etc/systemd/network/05-wired.network": "[Match]\nName=ens*\n\n[Network]\nDHCP=yes\n"},
			want:    "05-wired.network",
		},
		{
			name:    "definition IDs that sort before every recovery ID",
			netplan: map[string]string{"50-cloud-init.yaml": "network:\n  version: 2\n  ethernets:\n    -aaa:\n      dhcp4: true\n"},
			want:    "netplan definition -aaa",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest := ubuntuNetplanGuest(t, tc.netplan, tc.extra)
			cfg := recoveryConfig()
			cfg.Mode = modeNetplan
			_, err := guest.adapter().Apply(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to name %q", err, tc.want)
			}
			if guest.mutated() {
				t.Fatal("the overlay was written although the recovery definition would not apply")
			}
		})
	}
}

// NetworkManager renders a guest that names the renderer globally, and
// the recovery definition names networkd itself so that it is not handed to
// NetworkManager with the rest.
func TestNetplanRecoveryNamesNetworkdUnderAGlobalNetworkManagerRenderer(t *testing.T) {
	guest := ubuntuNetplanGuest(t, map[string]string{
		"01-network-manager-all.yaml": "network:\n  version: 2\n  renderer: NetworkManager\n",
		"50-static.yaml":              "network:\n  version: 2\n  ethernets:\n    ens18:\n      renderer: networkd\n      match:\n        macaddress: 02:00:00:00:00:61\n      addresses: [198.51.100.10/24]\n",
	}, nil)
	cfg := recoveryConfig()
	cfg.Mode = modeNetplan
	if _, err := guest.adapter().Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if profile := guest.files[netplanProfile]; !strings.Contains(profile, "      renderer: networkd\n") {
		t.Fatalf("the recovery definition would be rendered by the global renderer:\n%s", profile)
	}
	name, contents := guest.generatedSelection(recoveryMAC, 8*time.Second, true)
	if name != "10-netplan-certistack-recovery.network" || !strings.Contains(contents, "Address=192.0.2.10/24") {
		t.Fatalf("networkd applies %s:\n%s", name, contents)
	}
}

// Without a global renderer other than networkd the definition is what was
// verified: no renderer key.
func TestNetplanRecoveryDefinitionIsUnchangedForNetworkdGuests(t *testing.T) {
	guest := ubuntuNetplanGuest(t, map[string]string{"50-cloud-init.yaml": strings.Replace(cloudInitStaticAll, "    all:", "    ens18:", 1)}, nil)
	if _, err := guest.adapter().Apply(context.Background(), recoveryConfig()); err != nil {
		t.Fatal(err)
	}
	want := `network:
  version: 2
  ethernets:
    certistack-recovery:
      match:
        macaddress: 02:00:00:00:00:61
      addresses:
        - 192.0.2.10/24
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
`
	if got := guest.files[netplanProfile]; got != want {
		t.Fatalf("recovery definition:\n%s\nwant:\n%s", got, want)
	}
}

// The renderer of a definition, as netplan resolves it: its own, else its
// section's (where it was first defined), else the last global renderer of
// any file, else networkd.
func TestNetplanEffectiveRenderer(t *testing.T) {
	load := func(files ...string) *netplanConfig {
		config := &netplanConfig{definitions: map[string]*netplanDefinition{}}
		for _, contents := range files {
			if err := config.add(contents); err != nil {
				t.Fatal(err)
			}
		}
		return config
	}
	renderers := func(config *netplanConfig) string {
		var got []string
		for _, id := range []string{"a", "b", "c"} {
			if definition := config.definitions[id]; definition != nil {
				got = append(got, id+"="+config.effectiveRenderer(definition))
			}
		}
		return strings.Join(got, " ")
	}
	cases := []struct {
		name  string
		files []string
		want  string
	}{
		{"default", []string{"network:\n  ethernets:\n    a: {}\n"}, "a=networkd"},
		{"global", []string{"network:\n  renderer: NetworkManager\n  ethernets:\n    a: {}\n"}, "a=NetworkManager"},
		{"global from a later file", []string{"network:\n  ethernets:\n    a: {}\n", "network:\n  renderer: NetworkManager\n"}, "a=NetworkManager"},
		{"section", []string{"network:\n  renderer: networkd\n  ethernets:\n    renderer: NetworkManager\n    a: {}\n", "network:\n  ethernets:\n    b: {}\n"}, "a=NetworkManager b=networkd"},
		{"definition", []string{"network:\n  renderer: NetworkManager\n  ethernets:\n    a:\n      renderer: networkd\n    b: {}\n"}, "a=networkd b=NetworkManager"},
		{"definition overridden by a later file", []string{"network:\n  ethernets:\n    a:\n      renderer: networkd\n", "network:\n  ethernets:\n    a:\n      renderer: NetworkManager\n"}, "a=NetworkManager"},
	}
	for _, tc := range cases {
		if got := renderers(load(tc.files...)); got != tc.want {
			t.Errorf("%s: renderers = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestEscapeNetplanID(t *testing.T) {
	for id, want := range map[string]string{"ens18": "ens18", "-a": "-a", "a b": "a%20b", "é": "é", "a/b": "a%2Fb", "a:b": "a%3Ab"} {
		if got := escapeNetplanID(id); got != want {
			t.Errorf("escapeNetplanID(%q) = %q, want %q", id, got, want)
		}
	}
}

// systemd-networkd guests: networkd applies the first .network file
// in name order whose [Match] selects the link, so the recovery file's name
// must sort before every file that can select the recovered NIC.
func TestNetworkdRecoveryFileSortsBeforeFilesThatMatchTheNIC(t *testing.T) {
	networkd := func(files map[string]string) *memGuest {
		all := map[string]string{
			"/etc/systemd/system/multi-user.target.wants/systemd-networkd.service": "-> /lib/systemd/system/systemd-networkd.service",
		}
		for name, contents := range files {
			all["/etc/systemd/network/"+name] = contents
		}
		return newMemGuest(t, all, "/etc/systemd/network")
	}
	cfg := recoveryConfig()
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no other file", nil, networkdProfile},
		{"a file that sorts after", map[string]string{"10-wired.network": "[Match]\nName=ens18\n[Network]\nDHCP=yes\n"}, networkdProfile},
		{"a file that sorts first and can match", map[string]string{"00-a-wired.network": "[Match]\nName=ens*\n[Network]\nDHCP=yes\n"}, systemdNetworkdDir + "/0-certistack-recovery.network"},
		{"a file for another MAC", map[string]string{"00-a-wired.network": "[Match]\nMACAddress=02:00:00:00:00:99\n[Network]\nDHCP=yes\n"}, networkdProfile},
		{"a file for this MAC", map[string]string{"00-a-wired.network": "[Match]\nMACAddress=02:00:00:00:00:61\n[Network]\nDHCP=yes\n"}, systemdNetworkdDir + "/0-certistack-recovery.network"},
		{"a file with a drop-in directory", map[string]string{"00-a-wired.network": "[Match]\nMACAddress=02:00:00:00:00:99\n", "00-a-wired.network.d/override.conf": "[Match]\nName=*\n"}, systemdNetworkdDir + "/0-certistack-recovery.network"},
		{"files that sort before both alternatives", map[string]string{"00-a-wired.network": "[Match]\nName=*\n", "0-a.network": "[Match]\nName=*\n"}, systemdNetworkdDir + "/-certistack-recovery.network"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest := networkd(tc.files)
			cfg := cfg
			cfg.Mode = modeSystemdNetworkd
			result, err := guest.adapter().Apply(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if result.Strategy != modeSystemdNetworkd || result.Files[0] != tc.want {
				t.Fatalf("result = %+v, want the profile %s", result, tc.want)
			}
			if _, written := guest.files[tc.want]; !written {
				t.Fatalf("%s was not written", tc.want)
			}
		})
	}

	guest := networkd(map[string]string{"00-a-wired.network": "[Match]\nName=*\n", "0-a.network": "[Match]\nName=*\n", "-a.network": "[Match]\nName=*\n"})
	cfg.Mode = modeSystemdNetworkd
	if _, err := guest.adapter().Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "-a.network") || guest.mutated() {
		t.Fatalf("error = %v, mutated = %v; want a refusal naming the files, before any write", err, guest.mutated())
	}
}

// The interface-name .link file is ordered the same way.
func TestInterfaceLinkFileSortsBeforeFilesThatMatchTheNIC(t *testing.T) {
	guest := newMemGuest(t, map[string]string{
		"/etc/systemd/network/00-a-rename.link":                                "[Match]\nOriginalName=*\n[Link]\nNamePolicy=keep\n",
		"/etc/systemd/network/10-wired.network":                                "[Match]\nName=eth0\n[Network]\nDHCP=yes\n",
		"/etc/systemd/system/multi-user.target.wants/systemd-networkd.service": "-> /lib/systemd/system/systemd-networkd.service",
	}, "/etc/systemd/network")
	cfg := recoveryConfig()
	cfg.Mode = modeSystemdNetworkd
	cfg.InterfaceName = "eth0"
	result, err := guest.adapter().Apply(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	link := systemdNetworkdDir + "/0-certistack-recovery.link"
	if len(result.Files) != 2 || result.Files[1] != link {
		t.Fatalf("files = %v, want the link file %s", result.Files, link)
	}
	if !strings.Contains(guest.files[link], "Name=eth0") {
		t.Fatalf("link file:\n%s", guest.files[link])
	}
}

func TestSystemdMayMatch(t *testing.T) {
	cases := []struct {
		contents string
		want     bool
	}{
		{"[Match]\nMACAddress=02:00:00:00:00:61\n", true},
		{"[Match]\nMACAddress=02:00:00:00:00:99\n", false},
		{"[Match]\nMACAddress=02:00:00:00:00:99 02:00:00:00:00:61\n", true},
		{"[Match]\nPermanentMACAddress=02:00:00:00:00:99\n", false},
		{"[Match]\nMACAddress=!02:00:00:00:00:99\n", true},
		{"[Match]\nName=ens18\n", true},
		{"[Match]\nKind=bridge\n", false},
		{"[Match]\nType=wlan\n", false},
		{"[Match]\nType=ether\n", true},
		{"[Match]\nMACAddress=02:00:00:00:00:99\nMACAddress=\n", true},
		{"[Network]\nMACAddress=02:00:00:00:00:99\n", true},
		{"", true},
	}
	for _, tc := range cases {
		if got := systemdMayMatch(tc.contents, recoveryMAC); got != tc.want {
			t.Errorf("systemdMayMatch(%q) = %v, want %v", tc.contents, got, tc.want)
		}
	}
}

// systemd joins a line that ends in a backslash with the next one (the
// backslash becomes a space) before it parses the assignment, so a [Match]
// list can continue on the next physical line (audit F113).
func TestSystemdMayMatchJoinsBackslashContinuedLines(t *testing.T) {
	cases := []struct {
		name     string
		contents string
		iface    string
		want     bool
	}{
		{"the restored MAC on the continuation line", "[Match]\nMACAddress=02:00:00:00:00:99 \\\n 02:00:00:00:00:61\n", "", true},
		{"only foreign MACs across the continuation", "[Match]\nMACAddress=02:00:00:00:00:99 \\\n 02:00:00:00:00:98\n", "", false},
		{"a continued Name= list names the NIC", "[Match]\nName=host0 \\\n ens18\n", "ens18", true},
		{"a continued Name= list names only other NICs", "[Match]\nName=host0 \\\n ve-*\n", "ens18", false},
		{"a continuation with no leading space on the next line", "[Match]\nMACAddress=02:00:00:00:00:99 \\\n02:00:00:00:00:61\n", "", true},
		{"a continuation across two backslashes in a row", "[Match]\nMACAddress=02:00:00:00:00:99 \\\n 02:00:00:00:00:98 \\\n 02:00:00:00:00:61\n", "", true},
		{"a comment line inside a continuation is skipped", "[Match]\nMACAddress=02:00:00:00:00:99 \\\n# a note\n 02:00:00:00:00:61\n", "", true},
		{"CRLF line ends", "[Match]\r\nMACAddress=02:00:00:00:00:99 \\\r\n 02:00:00:00:00:61\r\n", "", true},
		{"an escaped backslash at the end is not a continuation", "[Match]\nMACAddress=02:00:00:00:00:99 \\\\\nName=ens18\n", "", false},
		{"a continuation pending at the end of the file", "[Match]\nMACAddress=02:00:00:00:00:99 \\", "", false},
		{"a Type= continued onto the next line", "[Match]\nType=wlan \\\n ether\n", "", true},
	}
	for _, tc := range cases {
		if got := systemdMayMatchForName(tc.contents, recoveryMAC, tc.iface); got != tc.want {
			t.Errorf("%s: systemdMayMatchForName(%q, iface %q) = %v, want %v", tc.name, tc.contents, tc.iface, got, tc.want)
		}
	}
}
