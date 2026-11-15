// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The guest network recovery part of docs/plan-reference.md tells an operator which guest files COW
// guest-network recovery reads, where it writes, what it refuses and how its
// diagnostics are bounded. The lists it quotes (the ifcfg names NetworkManager
// ignores, the NetworkManager and systemd directories, the diagnostic limits) are
// the adapter's own, read here from its source, so a change to either side fails
// until the other follows.
func TestGuestNetworkDocumentationQuotesWhatTheAdapterDoes(t *testing.T) {
	read := func(parts ...string) string {
		t.Helper()
		data, err := os.ReadFile(repoFile(parts...))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	doc := strings.Join(strings.Fields(read("docs", "plan-reference.md")), " ")
	adapter := read("internal", "guestnet", "adapter.go")
	ifcfg := read("internal", "guestnet", "ifcfg.go")
	nmconfig := read("internal", "guestnet", "nmconfig.go")
	precedence := read("internal", "guestnet", "precedence.go")
	diagnostic := read("internal", "guestnet", "diagnostic.go")

	quoted := func(what, text string) []string {
		t.Helper()
		found := regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(text, -1)
		if len(found) == 0 {
			t.Fatalf("found no %s in the source", what)
		}
		var items []string
		for _, match := range found {
			items = append(items, match[1])
		}
		return items
	}
	mustContain := func(what string, items []string) {
		t.Helper()
		for _, item := range items {
			if !strings.Contains(doc, "`"+item+"`") {
				t.Errorf("docs/plan-reference.md does not name %s `%s` (the adapter uses it)", what, item)
			}
		}
	}

	// The names NetworkManager's ifcfg plugin ignores.
	suffixes := regexp.MustCompile(`ifcfgIgnoredSuffixes = \[\]string\{([^}]*)\}`).FindStringSubmatch(ifcfg)
	if suffixes == nil {
		t.Fatal("ifcfgIgnoredSuffixes is gone from internal/guestnet/ifcfg.go")
	}
	mustContain("the ignored ifcfg ending", quoted("ignored ifcfg endings", suffixes[1]))

	// Where NetworkManager's configuration is read from.
	var nmPaths []string
	for _, name := range []string{"nmUsrLibConfDir", "nmRunConfDir", "nmEtcConfDir", "nmInternConf"} {
		match := regexp.MustCompile(name + `\s*=\s*"([^"]+)"`).FindStringSubmatch(nmconfig)
		if match == nil {
			t.Fatalf("%s is gone from internal/guestnet/nmconfig.go", name)
		}
		nmPaths = append(nmPaths, match[1])
	}
	for _, name := range []string{"networkManagerConf", "networkManagerDir"} {
		match := regexp.MustCompile(name + `\s*=\s*"([^"]+)"`).FindStringSubmatch(adapter)
		if match == nil {
			t.Fatalf("%s is gone from internal/guestnet/adapter.go", name)
		}
		nmPaths = append(nmPaths, match[1])
	}
	mustContain("the NetworkManager path", nmPaths)

	// The directories udev reads .link files from.
	block := regexp.MustCompile(`suffix == "\.link"[^\n]*\{\s*return \[\]string\{([^}]*)\}`).FindStringSubmatch(precedence)
	if block == nil {
		t.Fatal("systemdSearchDirs lost its .link list in internal/guestnet/precedence.go")
	}
	var linkDirs []string
	for _, item := range strings.Split(block[1], ",") {
		item = strings.TrimSpace(item)
		if strings.HasPrefix(item, `"`) {
			linkDirs = append(linkDirs, strings.Trim(item, `"`))
		} else if item == "systemdNetworkdDir" {
			match := regexp.MustCompile(`systemdNetworkdDir\s*=\s*"([^"]+)"`).FindStringSubmatch(adapter)
			if match == nil {
				t.Fatal("systemdNetworkdDir is gone from internal/guestnet/adapter.go")
			}
			linkDirs = append(linkDirs, match[1])
		}
	}
	if len(linkDirs) != 5 {
		t.Fatalf("the .link search list is %v; the guide names five directories", linkDirs)
	}
	mustContain("the .link directory", linkDirs)

	// The diagnostic's limits.
	kib := func(name string) string {
		match := regexp.MustCompile(name + `\s*=\s*(\d+) << 10`).FindStringSubmatch(diagnostic)
		if match == nil {
			t.Fatalf("%s is gone from internal/guestnet/diagnostic.go", name)
		}
		return match[1] + " KiB"
	}
	for _, limit := range []string{kib("diagnosticReadLimit"), kib("diagnosticFileLimit")} {
		if !strings.Contains(doc, limit) {
			t.Errorf("docs/plan-reference.md does not state the diagnostic limit %s", limit)
		}
	}
	keep := regexp.MustCompile(`diagnosticKeep\s*=\s*(\d+)`).FindStringSubmatch(diagnostic)
	words := map[int]string{4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten"}
	if keep == nil {
		t.Fatal("diagnosticKeep is gone from internal/guestnet/diagnostic.go")
	}
	count, _ := strconv.Atoi(keep[1])
	if word := words[count]; word == "" || !strings.Contains(doc, "the newest "+word+" stay in the overlay") {
		t.Errorf("docs/plan-reference.md does not say that the newest %d captures stay in the overlay", count)
	}

	// What an operator is told they get and are refused: the refusals they can
	// meet and the limits of what recovery can see. (The 2026-11-12 rewrite left
	// out the write mechanics and the hostile-image limits, which no user acts
	// on: how the diagnostic is published and cleaned, the enablement links,
	// NetworkManager's command-line overrides, newline names and linked
	// directories.)
	for _, want := range []string{
		"refuses a path that is a link, directory or special file, naming it",
		"rewrites that profile in place",
		"asks for `interface_name` instead of rewriting whichever the directory lists first",
		"A configuration it cannot evaluate offline is refused before anything is written, naming the file",
		"the replacement file keeps the guest's own stanzas for the other interfaces",
		"A stanza built on the recovered NIC (a bridge, bond or VLAN over it, `bridge_ports all`), a `mapping`, `rename` or `template` stanza, and an option line outside any stanza are refused before anything is written",
		"a file hides one of the same name in a later directory, and a link to `/dev/null` hides it altogether",
		"Rules inside the guest's initramfs are not visible offline and are not modeled",
		"a cut capture ends with `[truncated]`",
		"The overlay is read during teardown, after the sandbox VM is confirmed stopped and before PVE destroys it",
		"When the VM cannot be confirmed stopped the overlay is not read, and the diagnostic in the report says it was not read and why",
		"An overlay that is already gone, or that cannot be read, is said in the diagnostic and is not a cleanup failure",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/plan-reference.md no longer says %q", want)
		}
	}
}
