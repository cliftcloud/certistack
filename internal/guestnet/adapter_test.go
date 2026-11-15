// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdapterApply_AutoDetectsNetworkManagerAndWritesOnlyCOWProfile(t *testing.T) {
	var progress []string
	guest := newMemGuest(t, nil, networkManagerDir)
	result, err := guest.adapter().Apply(context.Background(), Config{
		VMID: 9904, Overlays: []string{"/var/lib/certistack/vm9904-scsi0.qcow2"},
		MAC: "BC:24:11:8B:55:9A", Address: "10.70.0.15", CIDR: "10.70.0.0/24",
		Progress: func(message string) { progress = append(progress, message) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeNetworkManager || len(result.Files) != 1 || result.Files[0] != networkManagerProfile {
		t.Fatalf("unexpected result: %+v", result)
	}
	calls := guest.calls
	// networkmanager dir, systemd unit dir (masks), netplan dir, enabled
	// units dir, ifcfg dir, os-release x2, profile list, the check of the file
	// to write, the batch write, the read-back of what it wrote.
	if len(calls) != 11 {
		t.Fatalf("guestfish calls = %d, want 11: %#v", len(calls), calls)
	}
	for index, call := range calls {
		if len(call) < 6 || call[1] != keysFromStdin || call[2] != "--format=qcow2" || call[3] != "-a" || call[5] != "-i" {
			t.Fatalf("unsafe guestfish arguments: %#v", call)
		}
		wantAccess := "--ro"
		if index == len(calls)-2 {
			wantAccess = "--rw"
		}
		if call[0] != wantAccess {
			t.Fatalf("guestfish call %d access = %q, want %q: %#v", index, call[0], wantAccess, call)
		}
	}
	batch := lastBatch(calls)
	if batch[6] != "--" || !batchHasCommand(batch, "upload") || !batchHasCommand(batch, "chmod", "384", networkManagerProfile) || !batchHasCommand(batch, "chown", "0", "0", networkManagerProfile) {
		t.Fatalf("batch = %#v, want one ordered upload/chmod/chown batch", batch)
	}
	if len(progress) < 4 || progress[0] != "Detecting the guest network manager from the disposable overlay" || progress[len(progress)-1] != "COW-only network recovery profile is ready" {
		t.Fatalf("operator progress = %#v", progress)
	}
}

// lastBatch is the last mutating guestfish call of a recorded run.
func lastBatch(calls [][]string) []string {
	for i := len(calls) - 1; i >= 0; i-- {
		if len(calls[i]) > 0 && calls[i][0] == "--rw" {
			return calls[i]
		}
	}
	return nil
}

func TestAdapterApply_SeedsNetworkManagerProfileAttributes(t *testing.T) {
	guest := newMemGuest(t, map[string]string{networkManagerDir + "/existing.nmconnection": "[connection]\nid=existing\n"}, networkManagerDir)
	_, err := guest.adapter().Apply(context.Background(), Config{
		VMID: 9904, Overlays: []string{"/var/lib/certistack/vm9904-scsi0.qcow2"},
		MAC: "BC:24:11:8B:55:9A", Address: "10.70.0.15", CIDR: "10.70.0.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !batchHasCommand(lastBatch(guest.calls), "cp-a", networkManagerDir+"/existing.nmconnection", networkManagerProfile) {
		t.Fatalf("profile attributes were not seeded safely: %#v", guest.calls)
	}
}

func TestAdapterApply_AutoUpdatesMACBoundIfcfgProfile(t *testing.T) {
	guest := newMemGuest(t, map[string]string{ifcfgDir + "/ifcfg-eth0": "TYPE=Ethernet\nHWADDR=BC:24:11:8B:55:9A\n"}, networkManagerDir, ifcfgDir)
	result, err := guest.adapter().Apply(context.Background(), Config{
		VMID: 9904, Overlays: []string{"/var/lib/certistack/vm9904-scsi0.qcow2"},
		MAC: "BC:24:11:8B:55:9A", Address: "10.70.0.15", CIDR: "10.70.0.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeIfcfg || result.Files[0] != ifcfgDir+"/ifcfg-eth0" {
		t.Fatalf("auto recovery did not update its MAC-bound ifcfg profile: %+v", result)
	}
}

func TestIfcfgInterfaceForMACRejectsUnsafeGuestFilename(t *testing.T) {
	adapter := &Adapter{
		run: func(_ context.Context, args ...string) (string, error) {
			switch guestfishCommand(args)[0] {
			case "is-dir":
				return "true\n", nil
			case "ls":
				return "ifcfg-eth0;bad\n", nil
			case "cat":
				return "HWADDR=BC:24:11:8B:55:9A\n", nil
			default:
				return "", nil
			}
		},
	}

	profile, found, err := adapter.ifcfgProfileForMAC(context.Background(), []string{"/var/lib/certistack/vm9904.qcow2"}, "BC:24:11:8B:55:9A")
	if err != nil {
		t.Fatal(err)
	}
	if found || profile.iface != "" {
		t.Fatalf("unsafe guest interface filename was accepted: profile=%+v found=%t", profile, found)
	}
}

func TestIfcfgMatchesMAC(t *testing.T) {
	if !ifcfgMatchesMAC("HWADDR=\"bc:24:11:8b:55:9a\"\n", "BC:24:11:8B:55:9A") || ifcfgMatchesMAC("# HWADDR=bc:24:11:8b:55:9a", "bc:24:11:8b:55:9a") {
		t.Fatal("unexpected ifcfg MAC matching")
	}
}

func TestIsProfileSeed(t *testing.T) {
	if !isProfileSeed(modeNetworkManager, "source.nmconnection") || !isProfileSeed(modeIfcfg, "ifcfg-eth0") || isProfileSeed(modeNetworkManager, "../unsafe.nmconnection") {
		t.Fatal("unexpected profile seed classification")
	}
}

func TestFirewallProbeRulesAreNarrow(t *testing.T) {
	contents := firewallProbeRules("10.70.0.1", []FirewallPort{{Protocol: "tcp", Port: 443}, {Protocol: "udp", Port: 53}})
	for _, want := range []string{"source address=\"10.70.0.1\"", "port=\"443\" protocol=\"tcp\"", "port=\"53\" protocol=\"udp\""} {
		if !strings.Contains(contents, want) {
			t.Fatalf("firewall rule missing %q:\n%s", want, contents)
		}
	}
}

func TestWriteFirewallProbeRuleUsesConfiguredDefaultZone(t *testing.T) {
	var calls [][]string
	files := map[string]string{
		firewalldConfig:                      "# COW fixture\nDefaultZone=work\n",
		firewalldSystemZones + "/work.xml":   "<zone>\n  <short>Work</short>\n</zone>\n",
		firewalldSystemZones + "/public.xml": "<zone>\n  <short>Public</short>\n</zone>\n",
	}
	adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, []string{firewalldDir, firewalldZoneDir, firewalldSystemZones}, files, &calls)}

	got, err := adapter.writeFirewallProbeRule(context.Background(), []string{"/var/lib/certistack/vm9904.qcow2"}, t.TempDir(), "10.70.0.1", []FirewallPort{{Protocol: "tcp", Port: 443}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != firewalldZoneDir+"/work.xml" {
		t.Fatalf("firewall files = %#v", got)
	}
	if !batchHasCommand(lastBatch(calls), "cp-a", firewalldSystemZones+"/work.xml", firewalldZoneDir+"/work.xml") {
		t.Fatalf("firewall profile did not seed the configured default zone: %#v", calls)
	}
}

// The Rocky mesh member 7031 opened 8088 to its peers in its own public zone.
// The recovery rule must add the probe access, not replace that zone.
func TestFirewallProbeRulesKeepTheGuestZone(t *testing.T) {
	guestZone := `<?xml version="1.0" encoding="utf-8"?>
<zone target="default">
  <short>Public</short>
  <service name="ssh"/>
  <port port="8088" protocol="tcp"/>
</zone>
`
	merged, err := mergeFirewallProbeRules(guestZone, "10.60.70.1", []FirewallPort{{Protocol: "tcp", Port: 8088}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`<zone target="default">`, `<service name="ssh"/>`, `<port port="8088" protocol="tcp"/>`,
		`<source address="10.60.70.1"/><port port="8088" protocol="tcp"/><accept/>`} {
		if !strings.Contains(merged, want) {
			t.Fatalf("merged zone lacks %q:\n%s", want, merged)
		}
	}
	if strings.Count(merged, "</zone>") != 1 || !strings.HasSuffix(strings.TrimSpace(merged), "</zone>") {
		t.Fatalf("merged zone is not well formed:\n%s", merged)
	}
	for _, zone := range []string{`<zone/>`, `<?xml version="1.0"?>` + "\n" + `<zone target="DROP" />` + "\n"} {
		got, err := mergeFirewallProbeRules(zone, "10.60.70.1", []FirewallPort{{Protocol: "tcp", Port: 22}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got, `port="22"`) || strings.Count(got, "</zone>") != 1 || strings.Contains(got, "<zone/>") {
			t.Fatalf("self-closing zone %q merged to:\n%s", zone, got)
		}
		if strings.Contains(zone, "DROP") && !strings.Contains(got, `<zone target="DROP" >`) {
			t.Fatalf("self-closing zone lost its target:\n%s", got)
		}
	}
	// A file without a zone element is not a zone firewalld loads; it is
	// refused, not replaced by a zone of the probe rules alone.
	if got, err := mergeFirewallProbeRules("", "10.60.70.1", []FirewallPort{{Protocol: "tcp", Port: 22}}); err == nil {
		t.Fatalf("an empty zone file was accepted:\n%s", got)
	}
}

func TestWriteFirewallProbeRuleMergesExistingZone(t *testing.T) {
	var calls [][]string
	files := map[string]string{
		firewalldConfig:                  "DefaultZone=public\n",
		firewalldZoneDir + "/public.xml": "<zone>\n  <port port=\"8088\" protocol=\"tcp\"/>\n</zone>\n",
	}
	adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, []string{firewalldDir, firewalldZoneDir}, files, &calls)}
	stage := t.TempDir()
	if _, err := adapter.writeFirewallProbeRule(context.Background(), []string{"/tmp/one.qcow2"}, stage, "10.60.70.1", []FirewallPort{{Protocol: "tcp", Port: 8088}}); err != nil {
		t.Fatal(err)
	}
	read := false
	for _, call := range calls {
		if command := guestfishCommand(call); len(command) > 1 && command[0] == "cat" && command[1] == firewalldZoneDir+"/public.xml" {
			read = true
		}
	}
	if !read {
		t.Fatalf("existing guest zone was not read before the merge: %#v", calls)
	}
}

func TestFirewalldDefaultZoneRejectsUnsafeValue(t *testing.T) {
	adapter := &Adapter{
		run: func(_ context.Context, args ...string) (string, error) {
			switch guestfishCommand(args)[0] {
			case "is-file":
				return "true\n", nil
			case "cat":
				return "DefaultZone=../../unsafe\n", nil
			}
			return "", nil
		},
	}
	_, err := adapter.firewalldDefaultZone(context.Background(), []string{"/var/lib/certistack/vm9904.qcow2"})
	if err == nil || !strings.Contains(err.Error(), "safe zone name") {
		t.Fatalf("unsafe zone error = %v", err)
	}
}

func TestAdapterApply_ReportsMissingGuestfishDependency(t *testing.T) {
	adapter := &Adapter{
		scratchDir: t.TempDir(),
		run: func(_ context.Context, _ ...string) (string, error) {
			return "", errors.New("executable file not found")
		},
	}

	_, err := adapter.Apply(context.Background(), Config{
		VMID: 1, Overlays: []string{"/tmp/one.qcow2"}, MAC: "00:11:22:33:44:55",
		Address: "10.70.0.10", CIDR: "10.70.0.0/24",
	})
	if err == nil || !strings.Contains(err.Error(), "libguestfs-tools") {
		t.Fatalf("dependency error = %v", err)
	}
}

func TestAdapterApply_NetplanWaitsForAnyOnlineLink(t *testing.T) {
	guest := newMemGuest(t, map[string]string{netplanDir + "/50-cloud-init.yaml": "network:\n  version: 2\n"}, netplanDir)
	result, err := guest.adapter().Apply(context.Background(), Config{
		VMID: 97013, Overlays: []string{"/var/lib/vz/certistack-scratch/images/97013/vm-97013-disk-0.qcow2"},
		MAC: "BC:24:11:F6:A4:AB", Address: "10.70.0.13", CIDR: "10.70.0.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeNetplan || len(result.Files) != 2 || result.Files[1] != waitOnlineDropIn {
		t.Fatalf("unexpected result: %+v", result)
	}
	batch := lastBatch(guest.calls)
	if !batchHasCommand(batch, "mkdir-p", waitOnlineDropInDir) || !batchHasCommand(batch, "chmod", "420", waitOnlineDropIn) {
		t.Fatalf("wait-online drop-in was not written: %#v", batch)
	}
	// netplan resolves the MAC match to the pre-rename NIC name (ens18 after a
	// dracut initrd), so an interface list makes wait-online hang to timeout.
	dropIn := renderWaitOnlineDropIn()
	if !strings.Contains(dropIn, "ExecStart=\n") || !strings.Contains(dropIn, "--any") || strings.Contains(dropIn, " -i ") {
		t.Fatalf("drop-in must reset ExecStart and wait for any link:\n%s", dropIn)
	}
}

// fakeGuest answers guestfish calls from an in-memory filesystem (see
// memGuest) and records every call: dirs and files are paths that exist; files
// maps a path to its contents.
func fakeGuest(t *testing.T, dirs []string, files map[string]string, calls *[][]string) commandRunner {
	g := newMemGuest(t, files, dirs...)
	return func(ctx context.Context, args ...string) (string, error) {
		*calls = append(*calls, append([]string(nil), args...))
		return g.run(ctx, args...)
	}
}

// guestfishCommand is the guestfish command (or, for a write batch, the
// batch after "--") of a call, whatever number of drives it opens: access
// mode, then --format=qcow2 -a <overlay> for each drive, then -i.
func guestfishCommand(args []string) []string {
	for i, arg := range args {
		if arg == "-i" {
			return args[i+1:]
		}
	}
	return nil
}

// guestfishOverlays are the overlays a call adds with -a, in order.
func guestfishOverlays(args []string) []string {
	var overlays []string
	for i := 0; i+1 < len(args) && args[i] != "-i"; i++ {
		if args[i] == "-a" {
			overlays = append(overlays, args[i+1])
		}
	}
	return overlays
}

// The Debian 12 template 8104: ifupdown owns the network, networkd is
// disabled although /etc/systemd/network exists, and the guest's own stanza
// carries a gateway that must not survive into the sandbox.
const debianInterfaces = `source /etc/network/interfaces.d/*
auto lo
iface lo inet loopback
allow-hotplug enp6s18
iface enp6s18 inet static
	address 10.60.70.239/24
	gateway 10.60.70.1
	dns-nameservers 10.60.70.1
`

func TestAdapterApply_DebianIfupdownReplacesInterfacesWithoutGateway(t *testing.T) {
	var calls [][]string
	files := map[string]string{
		ifupdownConfig:                          debianInterfaces,
		enabledUnitsDir + "/networking.service": "",
		enabledUnitsDir + "/ssh.service":        "",
	}
	adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, []string{systemdNetworkdDir, enabledUnitsDir}, files, &calls)}
	result, err := adapter.Apply(context.Background(), Config{
		VMID: 8104, Overlays: []string{"/var/lib/vz/certistack-scratch/images/18104/vm-18104-disk-0.qcow2"},
		MAC: "02:5A:3C:10:20:81", Address: "10.60.70.46", CIDR: "10.60.70.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeIfupdown || result.Files[0] != ifupdownConfig || result.Files[1] != ifupdownOriginal {
		t.Fatalf("unexpected result: %+v", result)
	}
	batch := lastBatch(calls)
	if !batchHasCommand(batch, "cp-a", ifupdownConfig, ifupdownOriginal) || !batchHasCommand(batch, "chmod", "420", ifupdownConfig) {
		t.Fatalf("ifupdown batch = %#v, want original preserved then a 0644 replacement", batch)
	}
	_, subnet, _ := net.ParseCIDR("10.60.70.0/24")
	contents := renderIfupdown([]string{"enp6s18"}, Config{Address: "10.60.70.46"}, subnet)
	if !strings.Contains(contents, "iface enp6s18 inet static") || !strings.Contains(contents, "address 10.60.70.46/24") {
		t.Fatalf("ifupdown profile:\n%s", contents)
	}
	for _, line := range strings.Split(contents, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, forbidden := range []string{"gateway", "dns-", "source"} {
			if strings.Contains(line, forbidden) {
				t.Fatalf("recovery interfaces must not configure %q:\n%s", forbidden, contents)
			}
		}
	}
}

func TestAdapterApply_DebianWithNetworkdEnabledKeepsNetworkd(t *testing.T) {
	var calls [][]string
	files := map[string]string{
		ifupdownConfig:                                debianInterfaces,
		enabledUnitsDir + "/networking.service":       "",
		enabledUnitsDir + "/systemd-networkd.service": "",
	}
	adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, []string{systemdNetworkdDir, enabledUnitsDir}, files, &calls)}
	result, err := adapter.Apply(context.Background(), Config{
		VMID: 1, Overlays: []string{"/tmp/one.qcow2"}, MAC: "00:11:22:33:44:55", Address: "10.60.70.10", CIDR: "10.60.70.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeSystemdNetworkd {
		t.Fatalf("strategy = %q, want systemd-networkd when networkd is enabled", result.Strategy)
	}
}

// systemd-networkd reads its .network files as its own user on some distributions
// (Amazon Linux 2023: "Failed to open configuration file
// '/etc/systemd/network/00-certistack-recovery.network': Permission denied"). A
// root-only 0600 recovery profile was never read, so the guest came up on its
// cloud-init profile with no address and the probe timed out. The profile holds
// an address and a prefix, nothing secret: it is written 0644 root:root, as
// .network files conventionally are.
func TestNetworkdRecoveryProfileIsReadableByTheNetworkdUser(t *testing.T) {
	var calls [][]string
	files := map[string]string{
		enabledUnitsDir + "/systemd-networkd.service": "",
	}
	adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, []string{systemdNetworkdDir, enabledUnitsDir}, files, &calls)}
	result, err := adapter.Apply(context.Background(), Config{
		VMID: 1, Overlays: []string{"/tmp/one.qcow2"}, MAC: "00:11:22:33:44:55", Address: "10.60.70.10", CIDR: "10.60.70.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeSystemdNetworkd {
		t.Fatalf("strategy = %q, want systemd-networkd", result.Strategy)
	}
	batch := lastBatch(calls)
	if !batchHasCommand(batch, "chmod", "420", networkdProfile) || !batchHasCommand(batch, "chown", "0", "0", networkdProfile) {
		t.Fatalf("batch = %#v, want the networkd recovery profile written 0644 root:root (chmod 420)", batch)
	}
}

func TestIfupdownSeveralInterfacesNeedInterfaceNameWithSeveralNICs(t *testing.T) {
	var calls [][]string
	files := map[string]string{ifupdownConfig: debianInterfaces, ifupdownFragments + "/eth1": "iface eth1 inet dhcp\n"}
	adapter := &Adapter{run: fakeGuest(t, []string{ifupdownFragments}, files, &calls)}
	_, err := adapter.ifupdownRecoveryNames(context.Background(), []string{"/tmp/one.qcow2"}, false)
	if err == nil || !strings.Contains(err.Error(), "enp6s18, eth1") || !strings.Contains(err.Error(), "several NICs") || !strings.Contains(err.Error(), "interface_name") {
		t.Fatalf("error = %v, want both interfaces named and interface_name suggested", err)
	}
}

// A cloud-init Debian 12 guest (q35, one NIC) keeps the image's stale eth0
// stanza beside cloud-init's enp6s18. With one NIC both names can only be that
// NIC, so each gets a hotplug recovery stanza.
func TestAdapterApply_DebianCloudInitStaleStanzaWithOnlyNIC(t *testing.T) {
	var calls [][]string
	files := map[string]string{
		ifupdownConfig:                          "source /etc/network/interfaces.d/*\nauto lo\niface lo inet loopback\nallow-hotplug eth0\niface eth0 inet dhcp\n",
		ifupdownFragments + "/50-cloud-init":    "auto lo\niface lo inet loopback\n\nauto enp6s18\niface enp6s18 inet dhcp\n    dns-nameservers 10.60.70.1\n",
		enabledUnitsDir + "/networking.service": "",
	}
	guest := fakeGuest(t, []string{systemdNetworkdDir, enabledUnitsDir, ifupdownFragments}, files, &calls)
	var uploaded string
	run := func(ctx context.Context, args ...string) (string, error) {
		for i := 0; i+2 < len(args); i++ {
			if args[i] == "upload" && args[i+2] == ifupdownConfig {
				data, err := os.ReadFile(args[i+1])
				if err != nil {
					t.Fatal(err)
				}
				uploaded = string(data)
			}
		}
		return guest(ctx, args...)
	}
	cfg := Config{VMID: 7095, Overlays: []string{"/tmp/one.qcow2"}, MAC: "BC:24:11:00:70:95", Address: "10.60.70.95", CIDR: "10.60.70.0/24", OnlyNIC: true}
	result, err := (&Adapter{scratchDir: t.TempDir(), run: run}).Apply(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeIfupdown {
		t.Fatalf("strategy = %q", result.Strategy)
	}
	for _, want := range []string{
		"allow-hotplug eth0\niface eth0 inet static\n    address 10.60.70.95/24\n",
		"allow-hotplug enp6s18\niface enp6s18 inet static\n    address 10.60.70.95/24\n",
	} {
		if !strings.Contains(uploaded, want) {
			t.Fatalf("recovery interfaces lack %q:\n%s", want, uploaded)
		}
	}
	for _, line := range strings.Split(uploaded, "\n") {
		if strings.HasPrefix(line, "auto ") && line != "auto lo" {
			t.Fatalf("a missing name under auto would fail networking.service and hold network-online.target:\n%s", uploaded)
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "#") && (strings.Contains(line, "dhcp") || strings.Contains(line, "dns-") || strings.Contains(line, "source")) {
			t.Fatalf("the guest's own configuration came back:\n%s", uploaded)
		}
	}

	cfg.OnlyNIC = false
	calls = nil
	if _, err := (&Adapter{scratchDir: t.TempDir(), run: guest}).Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "eth0, enp6s18") {
		t.Fatalf("with several NICs: error = %v, want interface_name required", err)
	}
}

func TestIfupdownInterfacesSetVirtualDevicesAside(t *testing.T) {
	contents := `# comment: iface ignored0 inet dhcp
auto lo
iface lo inet loopback

iface enp6s18 inet manual
    bond-master bond0

auto bond0
iface bond0 inet static
    address 192.0.2.10/24
    bond-slaves enp6s18
iface bond0 inet6 auto

auto vmbr0
iface vmbr0 inet static
    bridge_ports enp6s19
auto enp6s18.100
iface enp6s18.100 inet dhcp
iface gre1 inet tunnel
    mode gre
allow-hotplug eth0
iface eth0 inet6 dhcp
iface eth0 inet dhcp
`
	var got []string
	for _, iface := range ifupdownInterfaces(contents) {
		got = append(got, fmt.Sprintf("%s:%v", iface.name, iface.virtual))
	}
	want := "enp6s18:false bond0:true vmbr0:true enp6s18.100:true gre1:true eth0:false"
	if strings.Join(got, " ") != want {
		t.Fatalf("interfaces = %s, want %s", strings.Join(got, " "), want)
	}

	// A bridge over the NIC: only the physical member can carry the
	// recovery address, with or without other NICs.
	var calls [][]string
	files := map[string]string{ifupdownConfig: "auto enp6s18\niface enp6s18 inet manual\nauto br0\niface br0 inet static\n    address 192.0.2.10/24\n    bridge_ports enp6s18\n"}
	names, err := (&Adapter{run: fakeGuest(t, nil, files, &calls)}).ifupdownRecoveryNames(context.Background(), []string{"/tmp/one.qcow2"}, false)
	if err != nil || strings.Join(names, ",") != "enp6s18" {
		t.Fatalf("names = %v, %v; want the bridge's physical member", names, err)
	}
	// Only virtual stanzas: keep the previous behavior and use them.
	files[ifupdownConfig] = "auto br0\niface br0 inet dhcp\n    bridge_ports enp6s18\n"
	names, err = (&Adapter{run: fakeGuest(t, nil, files, &calls)}).ifupdownRecoveryNames(context.Background(), []string{"/tmp/one.qcow2"}, false)
	if err != nil || strings.Join(names, ",") != "br0" {
		t.Fatalf("names = %v, %v; want br0", names, err)
	}
}

// One name renders exactly the profile that was verified on a Debian 12 guest.
func TestRenderIfupdownOneNameIsUnchanged(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.60.70.0/24")
	got := renderIfupdown([]string{"enp6s18"}, Config{Address: "10.60.70.46"}, subnet)
	want := `# CertiStack isolated recovery profile (disposable COW overlay only).
# The guest's original file is interfaces.certistack-original.
# No gateway and no DNS: the sandbox is air-gapped.
auto lo
iface lo inet loopback

auto enp6s18
iface enp6s18 inet static
    address 10.60.70.46/24
`
	if got != want {
		t.Fatalf("profile:\n%s\nwant:\n%s", got, want)
	}
}

// The Oracle Linux 7 template 8121: NetworkManager with a bare
// NetworkManager.conf (ifcfg-rh only) and an ifcfg-eth0 without HWADDR.
func TestAdapterApply_EL7NetworkManagerUsesIfcfgProfile(t *testing.T) {
	var calls [][]string
	files := map[string]string{
		ifcfgDir + "/ifcfg-eth0": "DEVICE=eth0\nBOOTPROTO=none\nIPADDR=10.60.70.241\nONBOOT=yes\n",
		ifcfgDir + "/ifcfg-lo":   "DEVICE=lo\n",
		osReleaseFile:            "NAME=\"Oracle Linux Server\"\nID=\"ol\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"7.9\"\n",
		networkManagerConf:       "[main]\n\n[logging]\n",
	}
	adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, []string{networkManagerDir, ifcfgDir}, files, &calls)}
	result, err := adapter.Apply(context.Background(), Config{
		VMID: 8121, Overlays: []string{"/tmp/one.qcow2"}, MAC: "EA:CE:E9:7C:8A:6F", Address: "10.60.70.53", CIDR: "10.60.70.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeIfcfg || result.Files[0] != ifcfgProfile {
		t.Fatalf("result = %+v, want a MAC-bound ifcfg profile on EL7", result)
	}
}

// The CentOS 7 template 8125 with auto recovery got a keyfile profile its
// NetworkManager 1.18 never read, and kept its own address. Its /etc/os-release
// is a symlink, and a plan may name the interface; neither may hide EL7.
func TestAdapterApply_CentOS7NetworkManagerUsesIfcfgProfile(t *testing.T) {
	for _, tc := range []struct {
		name  string
		iface string
		files map[string]string
	}{
		{"os-release symlink", "", map[string]string{
			osReleaseFile:      "-> ../usr/lib/os-release",
			osReleaseFallback:  "NAME=\"CentOS Linux\"\nID=\"centos\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"7\"\n",
			networkManagerConf: "[main]\n#plugins=ifcfg-rh\n",
		}},
		{"only /usr/lib/os-release", "", map[string]string{
			osReleaseFallback: "ID=\"centos\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"7\"\n",
		}},
		{"named interface", "eth0", map[string]string{
			osReleaseFile: "ID=\"centos\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"7\"\n",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls [][]string
			adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, []string{networkManagerDir, ifcfgDir}, tc.files, &calls)}
			result, err := adapter.Apply(context.Background(), Config{
				VMID: 8125, Overlays: []string{"/tmp/one.qcow2"}, MAC: "02:5A:3C:10:20:D8", Address: "10.60.70.58", CIDR: "10.60.70.0/24", InterfaceName: tc.iface,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Strategy != modeIfcfg {
				t.Fatalf("strategy = %q, want ifcfg: EL7's NetworkManager reads no keyfile profile", result.Strategy)
			}
		})
	}
}

func TestAdapterApply_EL8NetworkManagerKeepsKeyfile(t *testing.T) {
	var calls [][]string
	files := map[string]string{
		ifcfgDir + "/ifcfg-eth0": "DEVICE=eth0\nONBOOT=yes\n",
		osReleaseFile:            "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"8.10\"\n",
	}
	adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, []string{networkManagerDir, ifcfgDir}, files, &calls)}
	result, err := adapter.Apply(context.Background(), Config{
		VMID: 8119, Overlays: []string{"/tmp/one.qcow2"}, MAC: "BC:24:11:00:00:01", Address: "10.60.70.54", CIDR: "10.60.70.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeNetworkManager {
		t.Fatalf("strategy = %q, want networkmanager on EL8 (keyfile always loaded)", result.Strategy)
	}
}

func TestEnterpriseLinux7AndKeyfilePlugin(t *testing.T) {
	cases := map[string]bool{
		"ID=\"centos\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"7\"\n":      true,
		"ID=\"ol\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"7.9\"\n":             true,
		"ID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"8.10\"\n":          false,
		"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n":               false,
		"ID=\"amzn\"\nID_LIKE=\"centos rhel fedora\"\nVERSION_ID=\"2\"\n": false,
		"": false,
	}
	for release, want := range cases {
		if got := enterpriseLinux7(release); got != want {
			t.Errorf("enterpriseLinux7(%q) = %v, want %v", release, got, want)
		}
	}
	if loadsKeyfileAfter(t, "[main]\n") || !loadsKeyfileAfter(t, "[main]\nplugins=ifcfg-rh,keyfile\n") {
		t.Fatal("keyfile plugin detection is wrong")
	}
}

func TestGuestfishFailureNamesTheCauseNotTheInstallHint(t *testing.T) {
	stderr := []byte("guestfish: no operating system was found on this disk\n\nIf using guestfish '-i' option, remove this option and instead\n")
	reason := guestfishReason(stderr)
	if reason != "guestfish: no operating system was found on this disk" {
		t.Fatalf("reason = %q", reason)
	}
	err := dependencyError("inspect", errors.New("command failed with exit code 1: exit status 1: "+reason))
	if strings.Contains(err.Error(), "libguestfs-tools") || !strings.Contains(err.Error(), "network_recovery.mode: preserve") {
		t.Fatalf("empty-disk error must not blame a missing dependency: %v", err)
	}
	if guestfishReason([]byte("libguestfs: trace\nlibguestfs: error: mount: /dev/sda1: wrong fs type\n")) != "libguestfs: error: mount: /dev/sda1: wrong fs type" {
		t.Fatal("libguestfs error line was not selected")
	}
	if len(guestfishReason([]byte("guestfish: "+strings.Repeat("x", 500)))) > 243 {
		t.Fatal("reason is not bounded")
	}
}

func TestRenderNetplan_IsRequiredForOnlineAndAirGapped(t *testing.T) {
	_, subnet, err := net.ParseCIDR("10.70.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	contents, destination := render(modeNetplan, Config{
		VMID: 1, MAC: "BC:24:11:F6:A4:AB", Address: "10.70.0.13",
	}, subnet)
	if destination != netplanProfile || !strings.Contains(contents, "macaddress: bc:24:11:f6:a4:ab") || !strings.Contains(contents, "- 10.70.0.13/24") {
		t.Fatalf("unexpected netplan profile:\n%s", contents)
	}
	// An optional recovered link made systemd-networkd-wait-online wait for
	// its full timeout on every restored Ubuntu guest.
	if strings.Contains(contents, "optional") {
		t.Fatalf("recovered link must count toward network-online:\n%s", contents)
	}
	for _, required := range []string{"accept-ra: false", "link-local: []", "dhcp4: false", "dhcp6: false"} {
		if !strings.Contains(contents, required) {
			t.Fatalf("netplan profile lacks %q; without it networkd waits for an IPv6 RA the sandbox never sends:\n%s", required, contents)
		}
	}
	for _, forbidden := range []string{"gateway", "routes", "nameservers", "dhcp4: true"} {
		if strings.Contains(contents, forbidden) {
			t.Fatalf("recovery profile must not add %s:\n%s", forbidden, contents)
		}
	}
}

func TestRenderNetworkManager_IsAirGapped(t *testing.T) {
	_, subnet, err := net.ParseCIDR("10.70.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	contents, destination := render(modeNetworkManager, Config{
		VMID: 1, MAC: "00:11:22:33:44:55", Address: "10.70.0.10",
	}, subnet)
	if destination != networkManagerProfile || !strings.Contains(contents, "address1=10.70.0.10/24") || !strings.Contains(contents, "never-default=true") {
		t.Fatalf("unexpected NetworkManager profile:\n%s", contents)
	}
	if strings.Contains(strings.ToLower(contents), "gateway") || strings.Contains(strings.ToLower(contents), "dns") {
		t.Fatalf("recovery profile must not add routing or DNS:\n%s", contents)
	}
}

func TestRenderInterfaceLink_BindsOnlyThePreservedMAC(t *testing.T) {
	contents := renderInterfaceLink(Config{MAC: "bc:24:11:8b:55:9a", InterfaceName: "eth0"})
	if !strings.Contains(contents, "MACAddress=BC:24:11:8B:55:9A") || !strings.Contains(contents, "NamePolicy=\nName=eth0") {
		t.Fatalf("unexpected interface link:\n%s", contents)
	}
}

func TestRenderIfcfg_IsStaticAndAirGapped(t *testing.T) {
	_, subnet, err := net.ParseCIDR("10.70.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	contents := renderIfcfg(Config{
		MAC: "00:11:22:33:44:55", Address: "10.70.0.10", InterfaceName: "eth0",
	}, subnet)
	for _, expected := range []string{"DEVICE=eth0", "IPADDR=10.70.0.10", "PREFIX=24", "DEFROUTE=no", "AUTOCONNECT_PRIORITY=999"} {
		if !strings.Contains(contents, expected) {
			t.Fatalf("ifcfg profile missing %q:\n%s", expected, contents)
		}
	}
	if strings.Contains(contents, "GATEWAY=") || strings.Contains(contents, "DNS") {
		t.Fatalf("ifcfg recovery profile must not add routing or DNS:\n%s", contents)
	}
}

func TestRenderIfcfg_ReplacesNamedLegacyProfileInCOW(t *testing.T) {
	_, subnet, err := net.ParseCIDR("10.70.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, destination := render(modeIfcfg, Config{InterfaceName: "eth0"}, subnet)
	if destination != ifcfgDir+"/ifcfg-eth0" {
		t.Fatalf("ifcfg destination = %q", destination)
	}
}

func TestDiagnosticFilesAreCOWLocal(t *testing.T) {
	if diagnosticDispatcher == diagnosticOutput || diagnosticScript == diagnosticOutput || diagnosticUnit == diagnosticOutput || diagnosticLateUnit == diagnosticOutput {
		t.Fatal("diagnostic executable or unit must never overwrite captured output")
	}
}

func TestDiagnosticScriptsAreExecutable(t *testing.T) {
	guest := newMemGuest(t, nil)
	if err := guest.adapter().writeDiagnostics(context.Background(), []string{"/var/lib/certistack/vm9904.qcow2"}, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	batch := lastBatch(guest.calls)
	for _, destination := range []string{diagnosticScript, diagnosticDispatcher} {
		if !batchHasCommand(batch, "chmod", "448", destination) {
			t.Fatalf("diagnostic executable mode missing for %q; batch:\n%#v", destination, batch)
		}
	}
}

func TestGuestfishBatchArgsPreservesOperationOrder(t *testing.T) {
	args := guestfishBatchArgs([]string{"/var/lib/certistack/one.qcow2"}, [][]string{
		{"mkdir-p", "/etc/example"},
		{"upload", "/tmp/profile", "/etc/example/profile"},
		{"chmod", "384", "/etc/example/profile"},
	})
	if len(args) < 7 || args[6] != "--" {
		t.Fatalf("batch args do not separate guestfish options: %#v", args)
	}
	for _, want := range [][]string{{"mkdir-p", "/etc/example"}, {"upload", "/tmp/profile", "/etc/example/profile"}, {"chmod", "384", "/etc/example/profile"}} {
		if !batchHasCommand(args, want...) {
			t.Fatalf("batch command missing %#v from %#v", want, args)
		}
	}
}

func TestGuestfishReadArgsAreReadOnly(t *testing.T) {
	args := guestfishReadArgs([]string{"/var/lib/certistack/one.qcow2"}, "is-dir", networkManagerDir)
	if len(args) != 8 || args[0] != "--ro" || args[1] != keysFromStdin || args[6] != "is-dir" || args[7] != networkManagerDir {
		t.Fatalf("read-only guestfish arguments = %#v", args)
	}
}

func batchHasCommand(args []string, want ...string) bool {
	start := -1
	for i, arg := range args {
		if arg == "--" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return false
	}
	for start < len(args) {
		end := start
		for end < len(args) && args[end] != ":" {
			end++
		}
		if len(args[start:end]) >= len(want) {
			matches := true
			for i := range want {
				if args[start+i] != want[i] {
					matches = false
					break
				}
			}
			if matches {
				return true
			}
		}
		start = end + 1
	}
	return false
}

func TestValidate_RejectsUnsafeInterfaceName(t *testing.T) {
	_, _, err := validate(Config{
		VMID: 1, Overlays: []string{"/tmp/one.qcow2"}, MAC: "00:11:22:33:44:55",
		Address: "10.70.0.10", CIDR: "10.70.0.0/24", InterfaceName: "eth0;bad",
	})
	if err == nil || !strings.Contains(err.Error(), "interface name") {
		t.Fatalf("validation error = %v", err)
	}
}

// The adapter is the second validator of the name it writes into the
// ifupdown stanza and the systemd .link file, so it refuses "." and ".." itself
// (defence in depth behind the plan validator), writing nothing.
func TestAdapterRefusesKernelReservedInterfaceNames(t *testing.T) {
	for _, name := range []string{".", ".."} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{ifupdownConfig: "auto eth0\niface eth0 inet dhcp\n"}
			var calls [][]string
			adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, []string{ifupdownDir}, files, &calls)}
			cfg := Config{
				VMID: 9001, Overlays: []string{"/audit/boot.qcow2"}, MAC: "BC:24:11:90:01:01",
				Address: "10.100.0.10", CIDR: "10.100.0.0/24",
				Mode: modeIfupdown, InterfaceName: name,
			}
			if _, _, err := validate(cfg); err == nil || !strings.Contains(err.Error(), "interface name") {
				t.Fatalf("validate(%q) = %v, want the interface-name error", name, err)
			}
			_, err := adapter.Apply(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), "interface name") {
				t.Fatalf("Apply with interface name %q = %v, want the interface-name error", name, err)
			}
			if len(calls) != 0 {
				t.Fatalf("an invalid interface name reached guestfish: %#v", calls)
			}
		})
	}
}

// A guest's own stanza for "." or ".." cannot name a device either, so it is
// not taken for the recovered NIC.
func TestIfupdownInterfacesIgnoreKernelReservedNames(t *testing.T) {
	got := ifupdownInterfaces("auto .\niface . inet dhcp\niface .. inet static\niface eth0 inet dhcp\n")
	if len(got) != 1 || got[0].name != "eth0" {
		t.Fatalf("interfaces = %+v, want only eth0", got)
	}
}

// The offline diagnostic, like the live one, names mounts that did
// not come up and the boot's dependency and device failures, and stays
// valid shell.
func TestDiagnosticScriptNamesSkippedMounts(t *testing.T) {
	stageDir := t.TempDir()
	if _, err := diagnosticMutations(stageDir); err != nil {
		t.Fatal(err)
	}
	var script []byte
	err := filepath.Walk(stageDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if data, readErr := os.ReadFile(p); readErr == nil && strings.Contains(string(data), "[failed services]") {
				script = data
			}
		}
		return err
	})
	if err != nil || script == nil {
		t.Fatalf("diagnostic script not staged: %v", err)
	}
	for _, want := range []string{"[mounts not active]", "[dependency and device failures]", "Timed out waiting for device"} {
		if !strings.Contains(string(script), want) {
			t.Fatalf("diagnostic script lacks %q", want)
		}
	}
	if sh, lookErr := exec.LookPath("sh"); lookErr == nil {
		if output, checkErr := exec.Command(sh, "-n", "-c", string(script)).CombinedOutput(); checkErr != nil {
			t.Fatalf("diagnostic script is not valid shell: %v: %s", checkErr, output)
		}
	}
}

// The adapter writes the MAC into the guest's profile as the adapter to
// match, so it holds the address to the same rule as the plan and the PVE
// request: the all-zero, broadcast and multicast addresses are refused, writing
// nothing, and a usable address in either case passes.
func TestAdapterRefusesAnAddressNoInterfaceCanHold(t *testing.T) {
	for _, mac := range []string{"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01", "33:33:00:00:00:01", "not-a-mac", ""} {
		files := map[string]string{ifupdownConfig: "auto eth0\niface eth0 inet dhcp\n"}
		var calls [][]string
		adapter := &Adapter{scratchDir: t.TempDir(), run: fakeGuest(t, []string{ifupdownDir}, files, &calls)}
		cfg := Config{
			VMID: 9001, Overlays: []string{"/audit/boot.qcow2"}, MAC: mac,
			Address: "10.100.0.10", CIDR: "10.100.0.0/24", Mode: modeIfupdown,
		}
		if _, _, err := validate(cfg); err == nil || !strings.Contains(err.Error(), "needs a valid source MAC") {
			t.Errorf("validate accepted MAC %q: %v", mac, err)
		}
		if _, err := adapter.Apply(context.Background(), cfg); err == nil || len(calls) != 0 {
			t.Errorf("Apply with MAC %q: err %v, %d guestfish call(s)", mac, err, len(calls))
		}
	}
	for _, mac := range []string{"02:AA:BB:CC:DD:EE", "bc:24:11:90:01:01"} {
		cfg := Config{VMID: 9001, Overlays: []string{"/audit/boot.qcow2"}, MAC: mac, Address: "10.100.0.10", CIDR: "10.100.0.0/24", Mode: modeIfupdown}
		if _, _, err := validate(cfg); err != nil {
			t.Errorf("validate refused MAC %q: %v", mac, err)
		}
	}
}

// Review R2-01: the sandbox range is read by the one parser every user of it
// shares (config.ParseSandboxRange). A spelling plan validation refuses, such
// as a prefix length with a leading zero, is not read here as another network.
func TestAdapterReadsTheSandboxRangeWithTheSharedParser(t *testing.T) {
	for _, cidr := range []string{"10.100.0.0/024", "10.0.0.0/08", " 10.100.0.0/24", "10.100.0.5/24"} {
		cfg := Config{VMID: 9001, Overlays: []string{"/audit/boot.qcow2"}, MAC: "02:AA:BB:CC:DD:EE", Address: "10.100.0.10", CIDR: cidr, Mode: modeIfupdown}
		if _, _, err := validate(cfg); err == nil {
			t.Errorf("validate accepted the sandbox range %q", cidr)
		}
	}
}
