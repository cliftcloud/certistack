// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/nodecheck"
)

// nodeToolPackages names the Debian package a node tool comes from, for the
// tools whose package has another name.
var nodeToolPackages = map[string]string{
	"qemu-img":              "qemu-utils",
	"proxmox-backup-client": "proxmox-backup-client",
	"guestfish":             "libguestfs-tools",
	"nft":                   "nftables",
}

// alwaysOnPVENode are tools the node preflight looks for that every Proxmox VE
// node has, because PVE depends on their package (iproute2); a guide does not
// have to tell a reader to install them.
var alwaysOnPVENode = map[string]bool{"ip": true}

// requiredNodeTools are the programs the node preflight looks for, read from
// its source: the tools of `check`'s layer 4, the list the preflight loops
// over, and every other exec.LookPath it makes.
func requiredNodeTools(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(docRoot, "internal", "preflight", "preflight_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var tools []string
	add := func(name string) {
		if !seen[name] && !alwaysOnPVENode[name] {
			seen[name] = true
			tools = append(tools, name)
		}
	}
	for _, tool := range nodecheck.Tools {
		add(tool.Name)
	}
	quoted := regexp.MustCompile(`"([a-z][a-z0-9-]+)"`)
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "exec.LookPath(") && !strings.Contains(line, "range []string{") {
			continue
		}
		for _, m := range quoted.FindAllStringSubmatch(line, -1) {
			add(m[1])
		}
	}
	for _, want := range []string{"qemu-img", "proxmox-backup-client", "guestfish", "nft"} {
		if !seen[want] {
			t.Fatalf("read the node tools %v from the preflight; %s is missing, so the pattern this test reads has changed", tools, want)
		}
	}
	return tools
}

// section is the text of a page from the heading that starts with this text to
// the next heading of the same level.
func section(t *testing.T, page, heading string) string {
	t.Helper()
	text := markdownText(t, filepath.Join(docRoot, "docs", page))
	_, rest, found := strings.Cut(text, "\n## "+heading)
	if !found {
		t.Fatalf("docs/%s has no \"## %s\" section", page, heading)
	}
	body, _, _ := strings.Cut(rest, "\n## ")
	return body
}

// A first-time reader installs what the guide lists and nothing else. Each
// program the node preflight looks for is named, with its package or by its own
// name, in the steps for setting up by hand (the quickstart has certistack setup
// install them): one that is left out stops the first plan on a stock node after
// the reader has done everything the page said.
func TestPrerequisitesNameEveryToolTheNodePreflightNeeds(t *testing.T) {
	for _, page := range []struct{ file, heading string }{
		{"manual-setup.md", "Set up by hand"},
	} {
		text := section(t, page.file, page.heading)
		for _, tool := range requiredNodeTools(t) {
			pkg := nodeToolPackages[tool]
			if !strings.Contains(text, tool) && (pkg == "" || !strings.Contains(text, pkg)) {
				t.Errorf("the %q section of docs/%s does not name the node tool %s (package %s), which the node preflight requires", page.heading, page.file, tool, pkg)
			}
		}
	}
}
