// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// batchDestinations are the guest paths a write batch creates or replaces: what
// it uploads, copies to, and links.
func batchDestinations(t *testing.T, batch []string) []string {
	t.Helper()
	var destinations []string
	for _, command := range batchCommands(batch) {
		switch {
		case command[0] == "upload" && len(command) == 3:
			destinations = append(destinations, command[2])
		case command[0] == "cp-a" && len(command) == 3:
			destinations = append(destinations, command[2])
		case command[0] == "ln-s" && len(command) == 3:
			destinations = append(destinations, command[2])
		}
	}
	return destinations
}

// reportedPaths are the paths the signed list names; a link is listed as
// "path -> target".
func reportedPaths(files []string) []string {
	paths := make([]string, len(files))
	for i, file := range files {
		paths[i], _, _ = strings.Cut(file, " -> ")
	}
	return paths
}

// exactlyOnce fails unless two path lists hold the same paths, each once. A
// path the batch both copies and uploads (a copy of the guest's profile that
// the upload then fills) is one destination.
func exactlyOnce(t *testing.T, what string, written, reported []string) {
	t.Helper()
	unique := map[string]bool{}
	for _, p := range written {
		unique[p] = true
	}
	var want []string
	for p := range unique {
		want = append(want, p)
	}
	sort.Strings(want)
	got := append([]string(nil), reported...)
	sort.Strings(got)
	if strings.Join(want, "\n") != strings.Join(got, "\n") {
		t.Fatalf("%s: the batch writes\n  %s\nbut the signed list names\n  %s", what, strings.Join(want, "\n  "), strings.Join(got, "\n  "))
	}
}

// The diagnostic batch writes six destinations (the script, the boot unit, the
// late unit, the dispatcher and two enablement links), and the result lists
// every one. The list is part of the signed VM record, so a reviewer can
// reconstruct what was written into the guest.
func TestSignedFilesNameEveryDestinationTheBatchWrites(t *testing.T) {
	cases := []struct {
		name  string
		mode  string
		files map[string]string
		dirs  []string
		edit  func(*Config)
	}{
		{"NetworkManager", modeNetworkManager, map[string]string{networkManagerDir + "/seed.nmconnection": "[connection]\n"}, []string{networkManagerDir}, func(*Config) {}},
		{"ifcfg with a named interface", modeIfcfg, map[string]string{ifcfgDir + "/ifcfg-eth0": ifcfgProfileText("eth0")}, []string{ifcfgDir}, func(c *Config) { c.InterfaceName = "eth0" }},
		{"Netplan", modeNetplan, map[string]string{netplanDir + "/50-cloud-init.yaml": "network:\n  version: 2\n"}, []string{netplanDir}, func(*Config) {}},
		{"systemd-networkd", modeSystemdNetworkd, nil, []string{systemdNetworkdDir}, func(*Config) {}},
		{"ifupdown with a named interface", modeIfupdown, map[string]string{ifupdownConfig: "auto eth0\niface eth0 inet dhcp\n"}, []string{ifupdownDir}, func(c *Config) { c.InterfaceName, c.OnlyNIC = "eth0", true }},
		{"NetworkManager with firewalld", modeNetworkManager, map[string]string{
			firewalldConfig: "DefaultZone=public\n", firewalldZoneDir + "/public.xml": "<zone>\n  <short>Public</short>\n</zone>\n",
		}, []string{networkManagerDir, firewalldDir, firewalldZoneDir}, func(c *Config) {
			c.ProbeIP, c.FirewallPorts = "10.100.0.1", []FirewallPort{{Protocol: "tcp", Port: 443}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest := newMemGuest(t, tc.files, tc.dirs...)
			cfg := multiDiskConfig(bootOverlayPath)
			cfg.Mode, cfg.CaptureDiagnostics = tc.mode, true
			tc.edit(&cfg)
			result, err := guest.adapter().Apply(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			exactlyOnce(t, tc.name, batchDestinations(t, lastBatch(guest.calls)), reportedPaths(result.Files))
			for _, want := range []string{
				diagnosticScript, diagnosticUnit, diagnosticLateUnit, diagnosticDispatcher,
				diagnosticLink + " -> ../certistack-network-recovery.service",
				diagnosticLateLink + " -> ../certistack-network-recovery-late.service",
			} {
				if !containsString(result.Files, want) {
					t.Errorf("the signed list lacks %q: %v", want, result.Files)
				}
			}
		})
	}
	t.Run("without diagnostics none are listed", func(t *testing.T) {
		guest := newMemGuest(t, nil, networkManagerDir)
		result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
		if err != nil {
			t.Fatal(err)
		}
		exactlyOnce(t, "no diagnostics", batchDestinations(t, lastBatch(guest.calls)), reportedPaths(result.Files))
		for _, file := range result.Files {
			if strings.Contains(file, "certistack-network-recovery") {
				t.Fatalf("a diagnostic file is listed although none was installed: %v", result.Files)
			}
		}
	})
}

// The install describes its own writes: its commands and its list come from the
// same calls, in the same order, one entry per write.
func TestDiagnosticInstallListsItsOwnWritesInOrder(t *testing.T) {
	install, err := diagnosticMutations(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var written []string
	for _, command := range install.commands {
		if (command[0] == "upload" || command[0] == "ln-s") && len(command) == 3 {
			written = append(written, command[2])
		}
	}
	if strings.Join(reportedPaths(install.files), "\n") != strings.Join(written, "\n") {
		t.Fatalf("files %v do not follow the writes %v", install.files, written)
	}
	if len(install.files) != 6 {
		t.Fatalf("files = %v, want the four regular files then the two links", install.files)
	}
}
