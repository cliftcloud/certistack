// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const ifcfgTestMAC = "BC:24:11:90:01:01"

func ifcfgProfileText(device string) string {
	text := "TYPE=Ethernet\nBOOTPROTO=dhcp\nHWADDR=" + ifcfgTestMAC + "\nONBOOT=yes\n"
	if device != "" {
		text = "DEVICE=" + device + "\n" + text
	}
	return text
}

// Names NetworkManager's ifcfg-rh plugin never loads, as its own
// predicate (utils_should_ignore_file with only_ifcfg, NetworkManager 1.18.8)
// decides them.
func TestIfcfgIgnoredMirrorsNetworkManager(t *testing.T) {
	for name, want := range map[string]bool{
		"ifcfg-eth0":              false,
		"ifcfg-eth0.bak":          true,
		"ifcfg-eth0.BAK":          true, // the comparison ignores case
		"ifcfg-eth0~":             true,
		"ifcfg-eth0.orig":         true,
		"ifcfg-eth0.Orig":         true,
		"ifcfg-eth0.rej":          true,
		"ifcfg-eth0.rpmnew":       true,
		"ifcfg-eth0.rpmorig":      true, // What a package upgrade leaves beside an edited profile
		"ifcfg-eth0.rpmsave":      true,
		"ifcfg-eth0.RpmSave":      true,
		"ifcfg-eth0.augnew":       true,
		"ifcfg-eth0.augsave":      true,
		"ifcfg-eth0.augtmp":       true,
		"ifcfg-eth0.rpmsaved":     false, // only the exact endings
		"ifcfg-eth0.rpmsave.d":    false,
		"ifcfg-eth0-2":            false, // a real second profile
		"ifcfg-eth0;1a2B3c4D":     true,  // rpm's temporary file: ";" and exactly 8 hex digits
		"ifcfg-eth0;1a2b3c4":      false,
		"ifcfg-eth0;1a2b3c4de":    false,
		"ifcfg-eth0;1a2b3c4g":     false,
		"ifcfg-eth0.bak.d":        false,
		"ifcfg-bak":               false, // no ".bak" ending, only the letters
		"ifcfg-eth0.baker":        false,
		"ifcfg-.bak":              true,
		"keys-eth0":               true, // not an ifcfg file
		"route-eth0":              true,
		"ifcfg":                   true,
		"IFCFG-eth0":              true, // the prefix is compared exactly
		"ifcfg-System_eth0":       false,
		"ifcfg-Wired_connection1": false,
	} {
		if got := ifcfgIgnored(name); got != want {
			t.Errorf("ifcfgIgnored(%q) = %v, want %v", name, got, want)
		}
	}
	if isProfileSeed(modeIfcfg, "ifcfg-eth0.bak") || !isProfileSeed(modeIfcfg, "ifcfg-eth0") {
		t.Error("isProfileSeed must not offer an ignored ifcfg file")
	}
}

func TestIfcfgAssignmentsReadTheFileAsTheShellDoes(t *testing.T) {
	values := ifcfgAssignments("# DEVICE=commented\nDEVICE=\"eth0\"\nHWADDR='bc:24:11:90:01:01'\nONBOOT=yes # note\nDEVICE=eth1\n  NAME = x\n\nBAD LINE\n=novalue\n")
	for key, want := range map[string]string{"DEVICE": "eth1", "HWADDR": "bc:24:11:90:01:01", "ONBOOT": "yes"} {
		if values[key] != want {
			t.Errorf("%s = %q, want %q", key, values[key], want)
		}
	}
	if _, set := values["NAME"]; set {
		t.Errorf("a key with white space around it is not an assignment: %v", values)
	}
}

// The only profile bound to the restored NIC is a leftover backup, which
// NetworkManager ignores. Choosing it, rewriting it under its own name and
// naming the NIC after it ("eth0.bak") would leave the recovery address
// unapplied while Apply reported success, so a backup is not a profile.
func TestAutoRecoveryIgnoresAnIgnoredIfcfgBackup(t *testing.T) {
	for _, suffix := range []string{".bak", "~", ".orig", ".rej", ".rpmnew", ".rpmorig", ".rpmsave", ".augnew", ".augsave", ".augtmp", ".BAK", ";1a2B3c4D"} {
		t.Run(suffix, func(t *testing.T) {
			backup := ifcfgDir + "/ifcfg-eth0" + suffix
			guest := newMemGuest(t, map[string]string{backup: ifcfgProfileText("eth0")}, networkManagerDir, ifcfgDir)
			result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
			if err != nil {
				t.Fatal(err)
			}
			if result.Strategy != modeNetworkManager || result.Files[0] != networkManagerProfile {
				t.Fatalf("result = %+v, want the NetworkManager keyfile profile: the backup is not a profile", result)
			}
			if guest.files[backup] != ifcfgProfileText("eth0") {
				t.Fatalf("the ignored file %s was rewritten:\n%s", backup, guest.files[backup])
			}
			if link, exists := guest.files[interfaceLinkProfile]; exists {
				t.Fatalf("a .link file renames the NIC after the ignored file:\n%s", link)
			}
		})
	}
}

// The active profile is what is rewritten, whatever is beside it.
func TestAutoRecoveryRewritesTheActiveIfcfgProfileBesideItsBackup(t *testing.T) {
	cases := map[string]map[string]string{
		"active alone":                     {ifcfgDir + "/ifcfg-eth0": ifcfgProfileText("eth0")},
		"active beside its backup":         {ifcfgDir + "/ifcfg-eth0": ifcfgProfileText("eth0"), ifcfgDir + "/ifcfg-eth0.bak": ifcfgProfileText("eth0")},
		"backup sorting before the active": {ifcfgDir + "/ifcfg-eth0": ifcfgProfileText("eth0"), ifcfgDir + "/ifcfg-eth0.Orig": ifcfgProfileText("eth0"), ifcfgDir + "/ifcfg-eth0~": ifcfgProfileText("eth0")},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			guest := newMemGuest(t, files, networkManagerDir, ifcfgDir)
			result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
			if err != nil {
				t.Fatal(err)
			}
			active := ifcfgDir + "/ifcfg-eth0"
			if result.Strategy != modeIfcfg || result.Files[0] != active {
				t.Fatalf("result = %+v, want the active profile %s", result, active)
			}
			if !strings.Contains(guest.files[active], "DEVICE=eth0\n") || !strings.Contains(guest.files[active], "IPADDR=10.100.0.10\n") {
				t.Fatalf("the active profile was not rewritten:\n%s", guest.files[active])
			}
			if !strings.Contains(guest.files[interfaceLinkProfile], "Name=eth0\n") {
				t.Fatalf("link file:\n%s", guest.files[interfaceLinkProfile])
			}
			for file, original := range files {
				if file != active && guest.files[file] != original {
					t.Fatalf("the ignored file %s was changed", file)
				}
			}
		})
	}
}

// The interface a profile configures is its DEVICE, as NetworkManager reads
// it, not whatever follows "ifcfg-" in its file name: NetworkManager itself
// names a profile "ifcfg-System_eth0" or "ifcfg-Wired_connection_1" for a NIC
// that is eth0. The file is still rewritten in place.
func TestAutoRecoveryTakesTheInterfaceFromTheProfilesDevice(t *testing.T) {
	file := ifcfgDir + "/ifcfg-System_eth0"
	guest := newMemGuest(t, map[string]string{file: ifcfgProfileText("eth0")}, networkManagerDir, ifcfgDir)
	result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeIfcfg || result.Files[0] != file {
		t.Fatalf("result = %+v, want %s rewritten in place", result, file)
	}
	if !strings.Contains(guest.files[file], "DEVICE=eth0\n") || strings.Contains(guest.files[file], "System_eth0") {
		t.Fatalf("profile:\n%s", guest.files[file])
	}
	if !strings.Contains(guest.files[interfaceLinkProfile], "Name=eth0\n") {
		t.Fatalf("the NIC is renamed after the file, not the DEVICE:\n%s", guest.files[interfaceLinkProfile])
	}

	t.Run("without a DEVICE the file name names the interface", func(t *testing.T) {
		guest := newMemGuest(t, map[string]string{ifcfgDir + "/ifcfg-eth7": ifcfgProfileText("")}, networkManagerDir, ifcfgDir)
		result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
		if err != nil || result.Files[0] != ifcfgDir+"/ifcfg-eth7" || !strings.Contains(guest.files[interfaceLinkProfile], "Name=eth7\n") {
			t.Fatalf("result = %+v, %v; link:\n%s", result, err, guest.files[interfaceLinkProfile])
		}
	})
	t.Run("a DEVICE no kernel interface can have is not a profile for the NIC", func(t *testing.T) {
		guest := newMemGuest(t, map[string]string{ifcfgDir + "/ifcfg-eth0": ifcfgProfileText("a-name-longer-than-fifteen")}, networkManagerDir, ifcfgDir)
		result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
		if err != nil || result.Strategy != modeNetworkManager {
			t.Fatalf("result = %+v, %v; want the keyfile profile", result, err)
		}
	})
}

// A package upgrade (on Rocky 9, for example) leaves ifcfg-eth0.rpmsave (and,
// with rpm and augeas, .rpmorig and .augsave) beside the profile; each is a
// copy of it, bound to the same MAC, and none is read by NetworkManager's
// ifcfg-rh plugin or by initscripts. Recovery ignores them rather than refusing
// the guest ("several legacy profiles are bound to the recovered NIC's MAC")
// and asking for interface_name, which an ordinary guest should not need.
func TestAutoRecoveryIgnoresPackageUpgradeLeftoversBesideTheIfcfgProfile(t *testing.T) {
	active := ifcfgDir + "/ifcfg-eth0"
	for _, leftover := range []string{".rpmsave", ".rpmorig", ".rpmnew", ".augsave", ".augnew", ".augtmp", ".RPMSAVE"} {
		t.Run(leftover, func(t *testing.T) {
			files := map[string]string{
				active:                              ifcfgProfileText("eth0"),
				ifcfgDir + "/ifcfg-eth0" + leftover: ifcfgProfileText("eth0"),
			}
			guest := newMemGuest(t, files, networkManagerDir, ifcfgDir)
			result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
			if err != nil {
				t.Fatalf("Apply = %v, want the active profile recovered", err)
			}
			if result.Strategy != modeIfcfg || result.Files[0] != active {
				t.Fatalf("result = %+v, want %s rewritten in place", result, active)
			}
			if !strings.Contains(guest.files[active], "IPADDR=10.100.0.10\n") {
				t.Fatalf("the active profile was not rewritten:\n%s", guest.files[active])
			}
			if got := guest.files[ifcfgDir+"/ifcfg-eth0"+leftover]; got != ifcfgProfileText("eth0") {
				t.Fatalf("the leftover was changed:\n%s", got)
			}
		})
	}

	t.Run("all of them at once", func(t *testing.T) {
		files := map[string]string{active: ifcfgProfileText("eth0")}
		for _, leftover := range []string{".rpmsave", ".rpmorig", ".augsave", ".bak", "~"} {
			files[active+leftover] = ifcfgProfileText("eth0")
		}
		guest := newMemGuest(t, files, networkManagerDir, ifcfgDir)
		result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
		if err != nil || result.Strategy != modeIfcfg || result.Files[0] != active {
			t.Fatalf("result = %+v, %v; want %s rewritten in place", result, err, active)
		}
		for file, original := range files {
			if file != active && guest.files[file] != original {
				t.Fatalf("the leftover %s was changed", file)
			}
		}
	})

	// The leftover is not a profile to name the NIC after or to rewrite either:
	// with nothing else bound to the MAC the keyfile profile is written, as it is
	// for the other ignored names.
	t.Run("a leftover alone is not the profile", func(t *testing.T) {
		leftover := active + ".rpmsave"
		guest := newMemGuest(t, map[string]string{leftover: ifcfgProfileText("eth0")}, networkManagerDir, ifcfgDir)
		result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
		if err != nil || result.Strategy != modeNetworkManager || result.Files[0] != networkManagerProfile {
			t.Fatalf("result = %+v, %v; want the NetworkManager keyfile profile", result, err)
		}
		if guest.files[leftover] != ifcfgProfileText("eth0") {
			t.Fatalf("the leftover was rewritten:\n%s", guest.files[leftover])
		}
	})
}

// The other side: the list of ignored names must not swallow a real second
// profile. ifcfg-eth0-2 and a differently named real file are loaded by
// NetworkManager, so two of them bound to the MAC still ask for interface_name,
// and the leftover beside them is not named among the candidates.
func TestAutoRecoveryStillRefusesTwoRealProfilesBoundToTheNIC(t *testing.T) {
	for name, second := range map[string]string{
		"a numbered sibling":    ifcfgDir + "/ifcfg-eth0-2",
		"a differently named":   ifcfgDir + "/ifcfg-System_eth0",
		"a suffix that is real": ifcfgDir + "/ifcfg-eth0.rpmsaved",
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{
				ifcfgDir + "/ifcfg-eth0":         ifcfgProfileText("eth0"),
				ifcfgDir + "/ifcfg-eth0.rpmsave": ifcfgProfileText("eth0"),
				second:                           ifcfgProfileText("eth0"),
			}
			guest := newMemGuest(t, files, networkManagerDir, ifcfgDir)
			_, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
			if err == nil || !strings.Contains(err.Error(), "several legacy profiles") || !strings.Contains(err.Error(), "interface_name") {
				t.Fatalf("Apply = %v, want several profiles refused and interface_name asked for", err)
			}
			// The candidates are listed between the first pair of parentheses.
			list := err.Error()[strings.Index(err.Error(), "(")+1:]
			list = list[:strings.Index(list, ")")]
			want := []string{ifcfgDir + "/ifcfg-eth0", second}
			sort.Strings(want)
			got := strings.Split(list, ", ")
			sort.Strings(got)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("candidates named = %q, want exactly the two real profiles %q (the .rpmsave leftover is not one)", got, want)
			}
			if guest.mutated() {
				t.Fatal("something was written although the profile to rewrite is ambiguous")
			}
		})
	}
}

// Two profiles NetworkManager loads are bound to the NIC: directory order is
// not a reason to rewrite one of them.
func TestAutoRecoveryAsksForTheInterfaceWhenSeveralProfilesAreBoundToTheNIC(t *testing.T) {
	files := map[string]string{ifcfgDir + "/ifcfg-eth0": ifcfgProfileText("eth0"), ifcfgDir + "/ifcfg-Wired_1": ifcfgProfileText("eth0")}
	guest := newMemGuest(t, files, networkManagerDir, ifcfgDir)
	_, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
	if err == nil || !strings.Contains(err.Error(), "ifcfg-Wired_1") || !strings.Contains(err.Error(), "ifcfg-eth0") || !strings.Contains(err.Error(), "interface_name") {
		t.Fatalf("Apply = %v, want both profiles named and interface_name asked for", err)
	}
	if guest.mutated() {
		t.Fatal("something was written although the profile to rewrite is ambiguous")
	}
	cfg := multiDiskConfig(bootOverlayPath)
	cfg.InterfaceName = "eth0"
	if _, err := guest.adapter().Apply(context.Background(), cfg); err != nil {
		t.Fatalf("with interface_name: %v", err)
	}
}

// A profile that is a link is not followed and not skipped either:
// the profile NetworkManager would activate is the one that must be rewritten.
func TestAutoRecoveryRefusesASymbolicIfcfgProfile(t *testing.T) {
	files := map[string]string{
		ifcfgDir + "/ifcfg-eth0":  "-> /etc/victim",
		"/etc/victim":             ifcfgProfileText("eth0"),
		ifcfgDir + "/ifcfg-eth0~": ifcfgProfileText("eth0"),
	}
	guest := newMemGuest(t, files, networkManagerDir, ifcfgDir)
	_, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("Apply = %v, want the link refused", err)
	}
	if guest.files["/etc/victim"] != ifcfgProfileText("eth0") {
		t.Fatal("the file the link points at was written")
	}
}

// An explicit interface name can make the profile's own file name one
// NetworkManager ignores.
func TestExplicitInterfaceNameCannotMakeAnIgnoredIfcfgFileName(t *testing.T) {
	for _, name := range []string{"eth0.bak", "eth0.orig", "eth0.rej", "x.rpmnew", "x.rpmorig", "x.rpmsave", "x.augnew", "x.augsave", "x.augtmp", "eth0.BAK"} {
		guest := newMemGuest(t, nil, ifcfgDir)
		cfg := multiDiskConfig(bootOverlayPath)
		cfg.Mode, cfg.InterfaceName = modeIfcfg, name
		_, err := guest.adapter().Apply(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "ignores") || !strings.Contains(err.Error(), name) {
			t.Errorf("interface %q: Apply = %v, want it refused as a name NetworkManager ignores", name, err)
		}
		if guest.mutated() {
			t.Errorf("interface %q: the guest was written before the refusal", name)
		}
	}
	guest := newMemGuest(t, nil, ifcfgDir)
	cfg := multiDiskConfig(bootOverlayPath)
	cfg.Mode, cfg.InterfaceName = modeIfcfg, "eth0"
	if _, err := guest.adapter().Apply(context.Background(), cfg); err != nil {
		t.Fatalf("control: %v", err)
	}
}
