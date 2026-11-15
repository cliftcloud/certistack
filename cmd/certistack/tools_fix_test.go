// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/nodecheck"
)

// Review R2-13. The fix text for missing tools is a root command meant to be
// pasted on the node, and its package names came from the node's own JSON. The
// controller has no need of the node's word for a package name: it knows the
// package of each tool it asks for, so it looks the package up by the tool's
// name and drops any name it does not know.
func TestToolsFixNamesOnlyPackagesTheControllerKnows(t *testing.T) {
	const envPath = "/secure/certistack/controller.env"
	fix := toolsFix([]nodecheck.Tool{
		{Name: "guestfish", Package: "libguestfs-tools; rm -rf /"},
		{Name: "qemu-img", Package: "$(reboot)"},
		{Name: "evil-tool", Package: "evil-package"},
		{Name: "nft", Package: ""},
	}, envPath)
	for _, want := range []string{"apt install --no-upgrade libguestfs-tools nftables qemu-utils", "certistack setup --dir /secure/certistack:"} {
		if !strings.Contains(fix, want) {
			t.Errorf("fix lacks %q:\n%s", want, fix)
		}
	}
	for _, unwanted := range []string{"rm -rf", "$(reboot)", "evil", ";rm", "install -y", " -y "} {
		if strings.Contains(fix, unwanted) {
			t.Errorf("the fix holds %q, which came from the node's report or skips apt's question:\n%s", unwanted, fix)
		}
	}
	// A file that is not setup's controller.env is not in the directory setup
	// would write to: the fix then names no directory.
	if fix := toolsFix([]nodecheck.Tool{{Name: "guestfish", Package: "libguestfs-tools"}}, "/etc/certistack/my.env"); strings.Contains(fix, "--dir") || !strings.Contains(fix, "Run certistack setup:") {
		t.Errorf("a file that is not controller.env:\n%s", fix)
	}
	// With nothing the controller knows, there is no install command to paste.
	if fix := toolsFix([]nodecheck.Tool{{Name: "evil-tool", Package: "evil-package"}}, envPath); strings.Contains(fix, "apt install") {
		t.Errorf("an unknown tool produced an install command:\n%s", fix)
	}
}
