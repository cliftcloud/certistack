// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/nodecheck"
)

// A node that cannot run fails check (and so setup's closing check) at the
// layer that would stop plan, with the fix in words: a client older than the
// release supports, a PVE release older than that, or a PVE without the SDN
// API a run builds its sandbox with.
func TestCheckFailsANodeThatCannotRun(t *testing.T) {
	passed := passingReport().Layers
	for name, tc := range map[string]struct {
		layers []nodecheck.Layer
		want   []string
	}{
		"client 2.99": {
			layers: []nodecheck.Layer{{Name: nodecheck.LayerTools, Status: nodecheck.StatusFailed, Code: nodecheck.CodeClientUnsupported,
				Detail: "found on the node: qemu-img, proxmox-backup-client, guestfish, ip, nft, but proxmox-backup-client 2.99.0 is older than proxmox-backup-client 3, the oldest this release supports"}},
			want: []string{"✗ 4. Node tools", "proxmox-backup-client 2.99.0 is older", "Fix: Update proxmox-backup-client on the node to version 3 or later", "apt update; apt install proxmox-backup-client", "401 Unauthorized"},
		},
		"PVE 7": {
			layers: []nodecheck.Layer{passed[0], {Name: nodecheck.LayerPVE, Status: nodecheck.StatusFailed, Code: nodecheck.CodePVEUnsupported,
				Detail: "the node reaches the PVE API and PVE accepts the token (Proxmox VE 7.4-3), but PVE 7.4-3 is older than PVE 8, the oldest this release supports"}},
			want: []string{"✗ 5. PVE API", "PVE 7.4-3 is older than PVE 8", "Fix: Update the node to Proxmox VE 8.1 or later", "https://certistack.dev/docs/compatibility/#supported-versions"},
		},
		"no SDN": {
			layers: []nodecheck.Layer{passed[0], {Name: nodecheck.LayerPVE, Status: nodecheck.StatusFailed, Code: nodecheck.CodePVESDNMissing,
				Detail: "the node reaches the PVE API and PVE accepts the token (Proxmox VE 8.0.3), but this node has no SDN API (PVE answers GET /cluster/sdn/zones with HTTP 501 Not Implemented): the package libpve-network-perl is not installed"}},
			want: []string{"✗ 5. PVE API", "no SDN API", "Fix: A run builds its sandbox network with PVE's SDN, which this node lacks: install libpve-network-perl and ifupdown2 on the node, or update the node to PVE 8.1 or later", "apt install libpve-network-perl ifupdown2", "- 6. PBS"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := readyController(t)
			withNode(t, &nodeStub{report: nodecheck.Report{Layers: tc.layers}})
			out, _ := failsAt(t, c)
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "Every layer passed") {
				t.Errorf("check passed a node that cannot run:\n%s", out)
			}
		})
	}
}
