// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"strings"
	"testing"
)

const (
	ownerMAC     = "02:00:00:00:00:75"
	networkdLink = "-> /lib/systemd/system/systemd-networkd.service"
	nmLink       = "-> /usr/lib/systemd/system/NetworkManager.service"
)

func ownerConfig() Config {
	return Config{VMID: 990075, Overlays: []string{"/synthetic/owner-overlay.qcow2"}, MAC: ownerMAC, Address: "10.100.0.10", CIDR: "10.100.0.0/24", OnlyNIC: true}
}

// A source definition: ens18, bound to the restored MAC, with the source's
// isolated-guest address, rendered by networkd.
const netplanNetworkdSource = "network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    ens18:\n      match:\n        macaddress: '02:00:00:00:00:75'\n      addresses: [198.51.100.10/24]\n      dhcp4: false\n"

func withFiles(base map[string]string, more map[string]string) map[string]string {
	all := map[string]string{}
	for name, contents := range base {
		all[name] = contents
	}
	for name, contents := range more {
		all[name] = contents
	}
	return all
}

// A guest that keeps /etc/NetworkManager while NetworkManager is
// masked and networkd (with netplan renderer: networkd) runs. Auto must
// choose the backend in charge, and what it writes must be what the guest's
// own generator gives networkd.
func TestAutoFollowsTheBackendInChargeNotTheDirectory(t *testing.T) {
	source := map[string]string{
		"/etc/netplan/50-source.yaml":                                          netplanNetworkdSource,
		"/etc/systemd/system/NetworkManager.service":                           "-> /dev/null",
		"/lib/systemd/system/systemd-networkd.service":                         "[Unit]\nDescription=Offline fixture unit; never started\n[Install]\nWantedBy=multi-user.target\n",
		"/etc/systemd/system/multi-user.target.wants/systemd-networkd.service": networkdLink,
	}
	for _, tc := range []struct {
		name string
		mode string
		dirs []string
	}{
		{"auto, NetworkManager directory present and unit masked", modeAuto, []string{networkManagerDir, "/etc/systemd/network"}},
		{"explicit netplan, same guest", modeNetplan, []string{networkManagerDir, "/etc/systemd/network"}},
		{"auto, NetworkManager directory absent", modeAuto, []string{"/etc/systemd/network"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guest := newMemGuest(t, source, tc.dirs...)
			cfg := ownerConfig()
			cfg.Mode = tc.mode
			result, err := guest.adapter().Apply(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if result.Strategy != modeNetplan || result.Files[0] != netplanProfile {
				t.Fatalf("result = %+v, want the netplan recovery profile", result)
			}
			if _, wrote := guest.files[networkManagerProfile]; wrote {
				t.Fatal("a profile was written for the masked NetworkManager")
			}
			name, contents := guest.networkdSelection(ownerMAC)
			if name != "10-netplan-certistack-recovery.network" || !strings.Contains(contents, "Address=10.100.0.10/24") || strings.Contains(contents, "198.51.100.10") {
				t.Fatalf("networkd applies %s:\n%s", name, contents)
			}
		})
	}
}

// The backend in charge for the guest shapes the auto detection
// answers. Directory presence alone decides nothing.
func TestAutoDetectionOwnership(t *testing.T) {
	ifcfg := "/etc/sysconfig/network-scripts/ifcfg-eth0"
	networkdEnabled := map[string]string{
		"/lib/systemd/system/systemd-networkd.service":                         "[Unit]\n",
		"/etc/systemd/system/multi-user.target.wants/systemd-networkd.service": networkdLink,
	}
	networkManagerEnabled := map[string]string{
		"/usr/lib/systemd/system/NetworkManager.service":                     "[Unit]\n",
		"/etc/systemd/system/multi-user.target.wants/NetworkManager.service": nmLink,
	}
	cases := []struct {
		name    string
		files   map[string]string
		dirs    []string
		want    string
		wantErr string
	}{
		{
			name:  "NetworkManager enabled through multi-user.target",
			files: withFiles(networkManagerEnabled, map[string]string{ifcfg: "DEVICE=eth0\n"}),
			dirs:  []string{networkManagerDir},
			want:  modeNetworkManager,
		},
		{
			name: "NetworkManager enabled through its D-Bus alias",
			files: map[string]string{
				"/etc/systemd/system/dbus-org.freedesktop.NetworkManager.service": nmLink,
				ifcfg: "DEVICE=eth0\n",
			},
			dirs: []string{networkManagerDir},
			want: modeNetworkManager,
		},
		{
			// No unit evidence either way: the guest's own NetworkManager
			// files are the best evidence (this is the RHEL image default).
			name:  "NetworkManager with no enablement evidence and no other backend",
			files: map[string]string{ifcfg: "DEVICE=eth0\n"},
			dirs:  []string{networkManagerDir},
			want:  modeNetworkManager,
		},
		{
			name:  "NetworkManager installed but disabled, networkd enabled",
			files: withFiles(networkdEnabled, nil),
			dirs:  []string{networkManagerDir, "/etc/systemd/network"},
			want:  modeSystemdNetworkd,
		},
		{
			name: "NetworkManager installed but disabled, ifupdown enabled",
			files: map[string]string{
				"/etc/network/interfaces": "auto lo\niface lo inet loopback\nauto ens18\niface ens18 inet dhcp\n",
				"/etc/systemd/system/multi-user.target.wants/networking.service": "-> /lib/systemd/system/networking.service",
			},
			dirs: []string{networkManagerDir},
			want: modeIfupdown,
		},
		{
			name:  "NetworkManager masked, legacy network scripts remain",
			files: map[string]string{"/etc/systemd/system/NetworkManager.service": "-> /dev/null", ifcfg: "DEVICE=eth0\n"},
			dirs:  []string{networkManagerDir},
			want:  modeIfcfg,
		},
		{
			name:  "NetworkManager masked, networkd enabled with its own files",
			files: withFiles(networkdEnabled, map[string]string{"/etc/systemd/system/NetworkManager.service": "-> /dev/null", "/etc/systemd/network/10-wired.network": "[Match]\nName=ens18\n"}),
			dirs:  []string{networkManagerDir},
			want:  modeSystemdNetworkd,
		},
		{
			name:    "NetworkManager masked and nothing else configures the network",
			files:   map[string]string{"/etc/systemd/system/NetworkManager.service": "-> /dev/null"},
			dirs:    []string{networkManagerDir},
			wantErr: "masked services (NetworkManager.service)",
		},
		{
			name: "NetworkManager and networkd both masked with netplan files",
			files: map[string]string{
				"/etc/systemd/system/NetworkManager.service":   "-> /dev/null",
				"/etc/systemd/system/systemd-networkd.service": "-> /dev/null",
				"/etc/netplan/50-source.yaml":                  netplanNetworkdSource,
			},
			dirs:    []string{networkManagerDir},
			wantErr: "NetworkManager.service, systemd-networkd.service",
		},
		{
			// netplan hands the NIC to networkd and marks it unmanaged for
			// NetworkManager, which stays enabled beside it.
			name: "NetworkManager enabled but netplan renders the NIC with networkd",
			files: withFiles(withFiles(networkManagerEnabled, networkdEnabled), map[string]string{
				"/etc/netplan/50-source.yaml": netplanNetworkdSource,
			}),
			dirs: []string{networkManagerDir},
			want: modeNetplan,
		},
		{
			name: "NetworkManager enabled, netplan only names it as renderer",
			files: withFiles(networkManagerEnabled, map[string]string{
				"/etc/netplan/01-network-manager-all.yaml": "network:\n  version: 2\n  renderer: NetworkManager\n",
			}),
			dirs: []string{networkManagerDir},
			want: modeNetworkManager,
		},
		{
			name: "NetworkManager enabled, netplan networkd definition is for another NIC",
			files: withFiles(networkManagerEnabled, map[string]string{
				"/etc/netplan/50-other.yaml": strings.Replace(netplanNetworkdSource, "02:00:00:00:00:75", "02:00:00:00:00:99", 1),
			}),
			dirs: []string{networkManagerDir},
			want: modeNetworkManager,
		},
		{
			name: "NetworkManager and networkd both enabled and networkd files can match",
			files: withFiles(withFiles(networkManagerEnabled, networkdEnabled), map[string]string{
				"/etc/systemd/network/10-wired.network": "[Match]\nName=ens18\n[Network]\nDHCP=yes\n",
			}),
			dirs:    []string{networkManagerDir},
			wantErr: "cannot tell which one configures it",
		},
		{
			name: "NetworkManager and networkd both enabled, networkd files are for another NIC",
			files: withFiles(withFiles(networkManagerEnabled, networkdEnabled), map[string]string{
				"/etc/systemd/network/10-wired.network": "[Match]\nMACAddress=02:00:00:00:00:99\n[Network]\nDHCP=yes\n",
			}),
			dirs: []string{networkManagerDir},
			want: modeNetworkManager,
		},
		{
			name:  "netplan with networkd masked is not the network's configuration",
			files: map[string]string{"/etc/netplan/50-source.yaml": netplanNetworkdSource, "/etc/systemd/system/systemd-networkd.service": "-> /dev/null", ifcfg: "DEVICE=eth0\n"},
			want:  modeIfcfg,
		},
		{
			name:  "Debian: networkd directory, ifupdown in charge",
			files: map[string]string{"/etc/network/interfaces": "auto ens18\niface ens18 inet dhcp\n", "/etc/systemd/system/multi-user.target.wants/networking.service": "-> /lib/systemd/system/networking.service"},
			dirs:  []string{"/etc/systemd/network"},
			want:  modeIfupdown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest := newMemGuest(t, tc.files, tc.dirs...)
			cfg := ownerConfig()
			result, err := guest.adapter().Apply(context.Background(), cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				if guest.mutated() {
					t.Fatal("the overlay was written although no backend could be chosen")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Strategy != tc.want {
				t.Fatalf("strategy = %q, want %q (files %v)", result.Strategy, tc.want, result.Files)
			}
		})
	}
}

// An explicit mode is honored unless the guest shows it would not be
// read: a masked unit never starts.
func TestExplicitModeRefusesAMaskedBackend(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  string
		files map[string]string
		dirs  []string
		want  string
	}{
		{"networkmanager", modeNetworkManager, map[string]string{"/etc/systemd/system/NetworkManager.service": "-> /dev/null"}, []string{networkManagerDir}, "NetworkManager.service is masked"},
		{"systemd-networkd", modeSystemdNetworkd, map[string]string{"/etc/systemd/system/systemd-networkd.service": "-> /dev/null"}, []string{"/etc/systemd/network"}, "systemd-networkd.service is masked"},
		{"netplan", modeNetplan, map[string]string{"/etc/netplan/50-source.yaml": netplanNetworkdSource, "/etc/systemd/system/systemd-networkd.service": "-> /dev/null"}, nil, "systemd-networkd.service is masked"},
		{"ifupdown", modeIfupdown, map[string]string{"/etc/network/interfaces": "auto lo\n", "/etc/systemd/system/networking.service": "-> /dev/null"}, nil, "networking.service is masked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guest := newMemGuest(t, tc.files, tc.dirs...)
			cfg := ownerConfig()
			cfg.Mode = tc.mode
			_, err := guest.adapter().Apply(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "network_recovery.mode") {
				t.Fatalf("error = %v, want %q and the mode to use instead", err, tc.want)
			}
			if guest.mutated() {
				t.Fatal("the overlay was written for a backend that never starts")
			}
		})
	}
}

// Ifcfg profiles are read by NetworkManager or by the legacy network
// scripts, so no single mask rules the explicit mode out.
func TestExplicitIfcfgIsNotRefusedForAMaskedNetworkManager(t *testing.T) {
	guest := newMemGuest(t, map[string]string{
		"/etc/systemd/system/NetworkManager.service": "-> /dev/null",
		"/etc/sysconfig/network-scripts/ifcfg-eth0":  "DEVICE=eth0\nHWADDR=02:00:00:00:00:75\n",
	})
	cfg := ownerConfig()
	cfg.Mode = modeIfcfg
	result, err := guest.adapter().Apply(context.Background(), cfg)
	if err != nil || result.Strategy != modeIfcfg {
		t.Fatalf("result = %+v, error = %v", result, err)
	}
}

// An explicit NetworkManager mode on a guest where netplan hands the
// NIC to networkd is not applied by NetworkManager either.
func TestExplicitNetworkManagerRefusesAGuestNetworkdConfigures(t *testing.T) {
	guest := newMemGuest(t, map[string]string{
		"/etc/netplan/50-source.yaml":                                          netplanNetworkdSource,
		"/etc/systemd/system/multi-user.target.wants/NetworkManager.service":   nmLink,
		"/etc/systemd/system/multi-user.target.wants/systemd-networkd.service": networkdLink,
	}, networkManagerDir)
	cfg := ownerConfig()
	cfg.Mode = modeNetworkManager
	_, err := guest.adapter().Apply(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "configured by netplan, not NetworkManager") {
		t.Fatalf("error = %v", err)
	}
	if guest.mutated() {
		t.Fatal("the overlay was written")
	}
}

// How a mask is recognized: systemd never starts a unit whose file in
// /etc/systemd/system is a link to /dev/null or is empty.
func TestMaskedUnit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"link to /dev/null", map[string]string{"/etc/systemd/system/NetworkManager.service": "-> /dev/null"}, true},
		{"relative link to /dev/null", map[string]string{"/etc/systemd/system/NetworkManager.service": "-> ../../../dev/null"}, true},
		{"empty file", map[string]string{"/etc/systemd/system/NetworkManager.service": ""}, true},
		{"administrator's copy", map[string]string{"/etc/systemd/system/NetworkManager.service": "[Unit]\nDescription=NetworkManager\n"}, false},
		{"link to the vendor unit", map[string]string{"/etc/systemd/system/NetworkManager.service": "-> /usr/lib/systemd/system/NetworkManager.service", "/usr/lib/systemd/system/NetworkManager.service": "[Unit]\n"}, false},
		{"only a wants link", map[string]string{"/etc/systemd/system/multi-user.target.wants/NetworkManager.service": nmLink}, false},
		{"no unit directory", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guest := newMemGuest(t, tc.files)
			got, err := newDetection(guest.adapter(), []string{"/synthetic/overlay.qcow2"}, ownerMAC).masked(context.Background(), networkManagerUnit)
			if err != nil || got != tc.want {
				t.Fatalf("masked = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// A masked unit is never enabled, however many links point at it.
func TestEnabledUnit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"wants link", map[string]string{"/etc/systemd/system/multi-user.target.wants/NetworkManager.service": nmLink}, true},
		{"D-Bus alias", map[string]string{"/etc/systemd/system/dbus-org.freedesktop.NetworkManager.service": nmLink}, true},
		{"masked with a wants link", map[string]string{"/etc/systemd/system/NetworkManager.service": "-> /dev/null", "/etc/systemd/system/multi-user.target.wants/NetworkManager.service": nmLink}, false},
		{"neither", map[string]string{"/etc/systemd/system/other.service": ""}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guest := newMemGuest(t, tc.files)
			got, err := newDetection(guest.adapter(), []string{"/synthetic/overlay.qcow2"}, ownerMAC).enabled(context.Background(), networkManagerUnit)
			if err != nil || got != tc.want {
				t.Fatalf("enabled = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// An Alpine guest has no systemd: OpenRC starts its networking init script
// (ifupdown) from /etc/runlevels/boot. Its interfaces file is the recovery
// target, exactly as on Debian (refused as an
// unsupported layout before this).
const alpineInterfaces = `auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
	address 10.60.70.60/23
	gateway 10.60.70.1
`

func TestOpenRCGuestWithNetworkingInTheBootRunlevelIsAnIfupdownGuest(t *testing.T) {
	for _, level := range []string{"boot", "default", "sysinit"} {
		t.Run(level, func(t *testing.T) {
			var calls [][]string
			files := map[string]string{
				ifupdownConfig: alpineInterfaces,
				"/etc/runlevels/" + level + "/networking": "",
				"/etc/runlevels/" + level + "/sshd":       "",
			}
			dirs := []string{"/etc/runlevels", "/etc/runlevels/" + level}
			adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, dirs, files, &calls)}
			result, err := adapter.Apply(context.Background(), Config{
				VMID: 7660, Overlays: []string{"/tmp/alpine.qcow2"}, MAC: "BC:24:11:00:00:60", Address: "10.60.70.60", CIDR: "10.60.70.0/23",
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Strategy != modeIfupdown {
				t.Fatalf("strategy = %q, want ifupdown for an OpenRC guest that starts networking in %s", result.Strategy, level)
			}
			batch := lastBatch(calls)
			if !batchHasCommand(batch, "cp-a", ifupdownConfig, ifupdownOriginal) || !batchHasCommand(batch, "chmod", "420", ifupdownConfig) {
				t.Fatalf("batch = %#v, want the guest's file kept and a 0644 recovery file written", batch)
			}
		})
	}
}

// OpenRC alone proves nothing: the guest has to start the networking script,
// and have the file it reads.
func TestOpenRCGuestWithoutNetworkingOrInterfacesIsStillUnsupported(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"networking not enabled":        {ifupdownConfig: alpineInterfaces, "/etc/runlevels/boot/sshd": ""},
		"no interfaces file":            {"/etc/runlevels/boot/networking": ""},
		"enabled only in a stray level": {ifupdownConfig: alpineInterfaces, "/etc/runlevels/shutdown/networking": ""},
	} {
		t.Run(name, func(t *testing.T) {
			var calls [][]string
			dirs := []string{"/etc/runlevels", "/etc/runlevels/boot", "/etc/runlevels/shutdown"}
			adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, dirs, files, &calls)}
			_, err := adapter.Apply(context.Background(), Config{
				VMID: 7660, Overlays: []string{"/tmp/alpine.qcow2"}, MAC: "BC:24:11:00:00:60", Address: "10.60.70.60", CIDR: "10.60.70.0/23",
			})
			if err == nil || !strings.Contains(err.Error(), "unsupported guest network layout") {
				t.Fatalf("error = %v, want the unsupported-layout refusal", err)
			}
		})
	}
}

// cloud-init rewrites /etc/network/interfaces at every boot on some images
// (Alpine): with the seed gone it falls back to DHCP and the recovery stanza
// is lost (eth0 came up on 169.254.x.x). An ifupdown
// guest that has cloud-init configuration is told, in the overlay, to leave the
// network alone; one without it gets nothing extra.
func TestIfupdownRecoveryTellsCloudInitToLeaveTheNetworkAlone(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dirs  []string
		files map[string]string
		want  bool
	}{
		{"a guest with cloud-init", []string{"/etc/runlevels", "/etc/runlevels/boot", cloudConfigDir},
			map[string]string{ifupdownConfig: alpineInterfaces, "/etc/runlevels/boot/networking": "", cloudConfigDir + "/05_logging.cfg": ""}, true},
		{"a guest without cloud-init", []string{"/etc/runlevels", "/etc/runlevels/boot"},
			map[string]string{ifupdownConfig: alpineInterfaces, "/etc/runlevels/boot/networking": ""}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls [][]string
			adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, tc.dirs, tc.files, &calls)}
			result, err := adapter.Apply(context.Background(), Config{
				VMID: 7660, Overlays: []string{"/tmp/alpine.qcow2"}, MAC: "BC:24:11:00:00:60", Address: "10.60.70.60", CIDR: "10.60.70.0/23",
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Strategy != modeIfupdown {
				t.Fatalf("strategy = %q, want ifupdown", result.Strategy)
			}
			wrote := false
			for _, f := range result.Files {
				wrote = wrote || f == cloudNetworkDropIn
			}
			if wrote != tc.want {
				t.Fatalf("files %v: cloud-init drop-in written = %v, want %v", result.Files, wrote, tc.want)
			}
			if got := batchHasCommand(lastBatch(calls), "chmod", "420", cloudNetworkDropIn); got != tc.want {
				t.Fatalf("batch %v: drop-in written 0644 = %v, want %v", lastBatch(calls), got, tc.want)
			}
		})
	}
	if got := renderCloudNetworkDropIn(); !strings.Contains(got, "network: {config: disabled}") {
		t.Fatalf("drop-in = %q, want cloud-init's network: {config: disabled}", got)
	}
}
