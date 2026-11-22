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
	versions := section(t, read("docs", "compatibility.md"), "Supported versions")

	for _, pair := range support.Pairs {
		minor := "x"
		if pair.PVEMinor != support.AnyMinor {
			minor = fmt.Sprint(pair.PVEMinor)
		}
		row := fmt.Sprintf("| %d.%s | %d.x | %s |", pair.PVEMajor, minor, pair.PBSMajor, pair.Level)
		if !strings.Contains(versions, row) {
			t.Errorf("the Supported versions table lacks the row %q for %s", row, pair.Describe())
		}
	}
	for _, row := range []string{
		fmt.Sprintf("| %d.x and older | any | %s |", support.MinPVEMajor-1, support.Unsupported),
		fmt.Sprintf("| any | %d.x and older (server or client) | %s |", support.MinPBSMajor-1, support.Unsupported),
	} {
		if !strings.Contains(versions, row) {
			t.Errorf("the Supported versions table lacks the row %q", row)
		}
	}
	// The section says what each status other than tested does, and what the
	// report records.
	for _, want := range []string{"`" + support.Untested.String() + "`", "`" + support.Unsupported.String() + "`", "`unknown`", "`version_support`"} {
		if !strings.Contains(versions, want) {
			t.Errorf("the Supported versions section does not mention %s", want)
		}
	}

	// Every page that states which versions are supported sends the reader to
	// the table.
	for _, page := range [][]string{{"docs", "quickstart.md"}} {
		if text := read(page...); !strings.Contains(text, "compatibility.md#supported-versions") {
			t.Errorf("%s does not link to the Supported versions section", strings.Join(page, "/"))
		}
	}

	// The report reference names the four members a report records them in.
	reports := read("docs", "reports.md")
	for _, member := range []string{"pve_version", "pbs_version", "pbs_client_version", "version_support"} {
		if !strings.Contains(reports, "`"+member+"`") {
			t.Errorf("docs/reports.md does not describe %s", member)
		}
	}
}

// The quickstart restates the tested pairs in a sentence, with a link to the
// table: Proxmox VE 9.x or 8.4, with PBS 3.x or 4.x. When the code's table stops
// matching that sentence, this fails and names the page to edit, so a pair
// flipped to tested cannot leave the guide saying something else.
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
	want := map[pair]bool{{"9.x", 3}: true, {"9.x", 4}: true}
	for minor := 1; minor <= 4; minor++ {
		want[pair{fmt.Sprintf("8.%d", minor), 3}] = true
		want[pair{fmt.Sprintf("8.%d", minor), 4}] = true
	}
	same := len(tested) == len(want)
	for p := range want {
		same = same && tested[p]
	}
	if !same {
		t.Fatalf("the code's tested pairs are now %v, not the ones the quickstart's sentence says (PVE 9.x and 8.1 to 8.4, each with PBS 3.x or 4.x). Edit docs/quickstart.md, then update this test", tested)
	}
}
