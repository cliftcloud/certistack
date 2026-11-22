// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	wizardPVE80     = "pve-manager/8.0.3/bbf3993334bfa916 (running kernel: 6.2.16-3-pve)"
	wizardPVE81     = "pve-manager/8.1.3/b46aac3b42da5d15 (running kernel: 6.5.11-4-pve)"
	wizardNoHandler = "No 'get' handler defined for '/cluster/sdn/zones'"
)

// A node that check would fail for its versions or its lack of the SDN API is
// refused when setup reads it, with check's reason and fix, before setup
// installs or creates anything on the node or the PBS: a
// proxmox-backup-client older than 3, a PVE release older than 8.1, a PVE
// without the SDN API, and the PVE 8.0 node as installed, which has all three
// (check's PVE layer names its release, not its SDN).
func TestTheWizardRefusesANodeARunCannotUseBeforeAnyChange(t *testing.T) {
	clientReason := "✗ proxmox-backup-client 2.99.0 is older than proxmox-backup-client 3, the oldest this release supports\n" +
		"  Fix: Update proxmox-backup-client on the node to version 3 or later. On the node as root: apt update; apt install proxmox-backup-client"
	pveReason := "✗ PVE 8.0.3 is older than PVE 8.1, the oldest this release supports (PVE 8.0 ships proxmox-backup-client 2.x and no SDN support): update the node\n" +
		"  Fix: Update the node to Proxmox VE 8.1 or later; the versions this release supports are listed at https://certistack.dev/docs/compatibility/#supported-versions"
	sdnReason := "✗ this node has no SDN API (pvesh get /cluster/sdn/zones on the node: No 'get' handler defined): the package libpve-network-perl is not installed\n" +
		"  Fix: A run builds its sandbox network with PVE's SDN, which this node lacks: install libpve-network-perl and ifupdown2 on the node, or update the node to PVE 8.1 or later. On the node as root: apt update; apt install libpve-network-perl ifupdown2"
	for name, tc := range map[string]struct {
		pve, client, sdnError string
		yes                   bool
		want, not             []string
	}{
		"client 2.99":     {pve: wizardPVE81, client: "client version: 2.99.0", want: []string{clientReason}, not: []string{"✗ PVE", "no SDN API"}},
		"PVE 8.0":         {pve: wizardPVE80, client: "client version: 3.0.1", want: []string{pveReason}, not: []string{"✗ proxmox-backup-client", "no SDN API"}},
		"no SDN":          {pve: wizardPVE81, client: "client version: 3.1.2", sdnError: wizardNoHandler, want: []string{sdnReason}, not: []string{"✗ proxmox-backup-client", "✗ PVE"}},
		"no SDN, --yes":   {pve: wizardPVE81, client: "client version: 3.1.2", sdnError: wizardNoHandler, yes: true, want: []string{sdnReason}},
		"PVE 8.0 as is":   {pve: wizardPVE80, client: "client version: 2.99.0", sdnError: wizardNoHandler, want: []string{clientReason, pveReason}, not: []string{"no SDN API"}},
		"client 2.x, PVE": {pve: "pve-manager/7.4-3/9002ab8a (running kernel: 5.15.102-1-pve)", client: "client version: 2.4.1", want: []string{"✗ PVE 7.4-3 is older than PVE 8, the oldest this release supports", "✗ proxmox-backup-client 2.4.1 is older"}},
	} {
		t.Run(name, func(t *testing.T) {
			f, dir := newWizardWorld(t)
			f.authorized = true
			f.tools = []string{"guestfish", "nft"}
			f.pveVersion, f.client, f.sdnError = tc.pve, tc.client, tc.sdnError
			opts := setupWizardOptions{NodeHost: "pve1.example.com"}
			answers := []string{"", "", "yes"} // the directory, the node's address, the host key
			if tc.yes {
				opts = setupWizardOptions{NodeHost: "pve1.example.com", Yes: true, Fingerprint: fixedHostKey(t, 7).Fingerprint,
					PBSHost: "pbs.example.com", PBSDatastore: "datastore1", PBSNamespace: "/", PBSSSH: "root@pbs.example.com"}
				answers = nil
			}
			out, err := runWizard(t, f, dir, opts, answers...)
			if err == nil || !strings.Contains(err.Error(), "setup stopped before it installed or created anything on the node or the PBS") ||
				!strings.Contains(err.Error(), "then run certistack setup again") {
				t.Fatalf("setup = %v, want the refusal\n%s", err, out)
			}
			// The controller's own key is all that was made; nothing on the node
			// or the PBS.
			if got := strings.Join(f.changes, "|"); got != "keygen id_ed25519" {
				t.Errorf("changes = %q, want only the controller's key", f.changes)
			}
			if len(f.pbsScripts) != 0 || f.checked != "" {
				t.Errorf("the PBS was given %d scripts, check ran on %q", len(f.pbsScripts), f.checked)
			}
			for _, name := range []string{"controller.env", partialEnvName} {
				if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
					t.Errorf("%s exists (%v)", name, err)
				}
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks\n%s\n---\n%s", want, out)
				}
			}
			for _, not := range append(tc.not, "every tool a run needs", "Packages on the node") {
				if strings.Contains(out, not) {
					t.Errorf("output has %q:\n%s", not, out)
				}
			}
			if n := strings.Count(out, "Without a Proxmox subscription apt update prints 401"); n > 1 {
				t.Errorf("the note on apt update is printed %d times:\n%s", n, out)
			}
		})
	}
}

// A supported node goes on, with a line on what setup checked, and the line on
// its tools names the client version setup read; a node whose client version
// or SDN read could not be told apart is not refused here, and the line says
// that the check at the end judges them.
func TestTheWizardGoesOnWithASupportedNode(t *testing.T) {
	for name, tc := range map[string]struct {
		pve, client, sdnError, usable, line string
	}{
		"PVE 8.1": {pve: wizardPVE81, client: "client version: 3.1.2",
			usable: "✓ This node can run CertiStack: Proxmox VE 8.1.3, proxmox-backup-client 3.1.2, SDN available.",
			line:   "The node has every tool a run needs (qemu-img, proxmox-backup-client 3.1.2, ip, guestfish, nft)."},
		"PVE 9.2": {
			usable: "✓ This node can run CertiStack: Proxmox VE 9.2.2, proxmox-backup-client 4.1.1, SDN available.",
			line:   "The node has every tool a run needs (qemu-img, proxmox-backup-client 4.1.1, ip, guestfish, nft)."},
		"nothing told apart": {pve: wizardPVE81, client: "Error: no version", sdnError: "ipcc_send_rec[1] failed: Connection refused",
			usable: "Nothing setup read refuses this node (Proxmox VE 8.1.3); it could not read the proxmox-backup-client version or the SDN zones, which the check at the end judges.",
			line:   "The node has every tool a run needs (qemu-img, proxmox-backup-client, ip, guestfish, nft)."},
	} {
		t.Run(name, func(t *testing.T) {
			f, dir := newWizardWorld(t)
			f.authorized = true
			f.tools = []string{"guestfish", "nft"}
			f.pveVersion, f.client, f.sdnError = tc.pve, tc.client, tc.sdnError
			out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"},
				"", "", "yes", // the directory, the node's address, the host key
				"", "", "", // the storage directory, add it, create the PVE access
				"pbs.example.com", "datastore1", "", "y", "", // the PBS, its datastore, the root namespace, yes, over ssh
				"", // the fingerprint read over ssh
			)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			want := "keygen id_ed25519|storage: pvesm add dir certistack-scratch --path /var/lib/vz/certistack-scratch --content images --shared 0|pve access|pbs access on root@pbs.example.com"
			if got := strings.Join(f.changes, "|"); got != want {
				t.Errorf("changes = %q\nwant      %q", got, want)
			}
			if !strings.Contains(out, tc.line+"\n") || strings.Contains(out, "✗") {
				t.Errorf("output lacks %q, or refuses:\n%s", tc.line, out)
			}
			// The node line is followed by the one on what the read found.
			if !strings.Contains(out, ", standalone.\n"+tc.usable+"\n") {
				t.Errorf("output lacks %q after the node line:\n%s", tc.usable, out)
			}
		})
	}
}
