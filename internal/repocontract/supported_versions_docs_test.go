// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/support"
)

// The guides say which Proxmox versions are tested, untested and unsupported.
// The table is the code's (internal/support), so the guide that restates it
// must say the same: flipping a pair in the code fails here until the guide's
// table says so too, and the pages that make the statement point to it.
func TestSupportedVersionsGuideRestatesTheCodesTable(t *testing.T) {
	read := func(parts ...string) string {
		t.Helper()
		data, err := os.ReadFile(repoFile(parts...))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	guide := read("docs", "compatibility.md")
	start := strings.Index(guide, "\n## Supported versions\n")
	if start < 0 {
		t.Fatal("docs/compatibility.md has no Supported versions section")
	}
	section := guide[start+1:]
	if end := strings.Index(section[len("## Supported versions"):], "\n## "); end >= 0 {
		section = section[:len("## Supported versions")+end]
	}

	for _, pair := range support.Pairs {
		minor := "x"
		if pair.PVEMinor != support.AnyMinor {
			minor = fmt.Sprint(pair.PVEMinor)
		}
		row := fmt.Sprintf("| %d.%s | %d.x | %s |", pair.PVEMajor, minor, pair.PBSMajor, pair.Level)
		if !strings.Contains(section, row) {
			t.Errorf("the Supported versions table lacks the row %q for %s", row, pair.Describe())
		}
	}
	for _, row := range []string{
		fmt.Sprintf("| %d.x and older | any | %s |", support.MinPVEMajor-1, support.Unsupported),
		fmt.Sprintf("| any | %d.x and older (server or client) | %s |", support.MinPBSMajor-1, support.Unsupported),
	} {
		if !strings.Contains(section, row) {
			t.Errorf("the Supported versions table lacks the row %q", row)
		}
	}
	for _, level := range []support.Level{support.Tested, support.Untested, support.Unsupported} {
		if !strings.Contains(section, "| `"+level.String()+"` |") {
			t.Errorf("the Supported versions section does not define the status %q", level)
		}
	}
	for _, want := range []string{"internal/support", "`version_support`", "`unknown`"} {
		if !strings.Contains(section, want) {
			t.Errorf("the Supported versions section does not mention %s", want)
		}
	}

	// Every page that states which versions are supported sends the reader to
	// the table.
	for _, page := range [][]string{
		{"docs", "faq.md"}, {"docs", "manual-setup.md"},
		{"docs", "cli-reference.md"}, {"docs", "reports.md"},
		{"docs", "quickstart.md"},
	} {
		if text := read(page...); !strings.Contains(text, "compatibility.md#supported-versions") {
			t.Errorf("%s does not link to the Supported versions section", strings.Join(page, "/"))
		}
	}

	// The doctor reference lists the check and its JSON member, and the report
	// reference the four members.
	cli := read("docs", "cli-reference.md")
	for _, want := range []string{"| `version_support` |", `"versions": {"pve", "pbs", "pbs_client", "support", "reason"}`} {
		if !strings.Contains(cli, want) {
			t.Errorf("docs/cli-reference.md lacks %s", want)
		}
	}
	reports := read("docs", "reports.md")
	for _, member := range []string{"pve_version", "pbs_version", "pbs_client_version", "version_support"} {
		if !strings.Contains(reports, "`"+member+"`") {
			t.Errorf("docs/reports.md does not describe %s", member)
		}
	}
}

// Two guides restate the tested pairs in a sentence (the FAQ and the
// quickstart), each with a link to the table. They say "9.x and 8.4, each with PBS 3.x or 4.x". When the code's table
// stops matching that sentence, this fails and names the pages to edit, so a
// pair flipped to tested cannot leave a guide saying something older.
func TestProseRestatementsOfTheTestedPairsStillMatchTheTable(t *testing.T) {
	type pair struct {
		pve string
		pbs int
	}
	tested := map[pair]bool{}
	for _, p := range support.Pairs {
		if p.Level != support.Tested {
			continue
		}
		minor := "x"
		if p.PVEMinor != support.AnyMinor {
			minor = fmt.Sprint(p.PVEMinor)
		}
		tested[pair{fmt.Sprintf("%d.%s", p.PVEMajor, minor), p.PBSMajor}] = true
	}
	want := map[pair]bool{{"9.x", 3}: true, {"9.x", 4}: true, {"8.4", 3}: true, {"8.4", 4}: true}
	same := len(tested) == len(want)
	for p := range want {
		same = same && tested[p]
	}
	if !same {
		t.Fatalf("the code's tested pairs are now %v, not the four the guides' sentences say (PVE 9.x and 8.4, each with PBS 3.x or 4.x). Edit these pages, then update this test: docs/faq.md, docs/quickstart.md", tested)
	}
}
