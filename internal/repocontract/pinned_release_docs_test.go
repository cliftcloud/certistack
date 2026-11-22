// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"regexp"
	"testing"
)

// The pages that pin a release in a command a reader copies (a download URL, a
// clone of the tag, a version to install) pin the newest release in
// CHANGELOG.md, so a release cannot ship pages that install the one before.
func TestPinnedReleasesInThePagesAreTheNewestRelease(t *testing.T) {
	changelog := readRepoText(t, "CHANGELOG.md")
	newest := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`).FindStringSubmatch(changelog)
	if newest == nil {
		t.Fatal("CHANGELOG.md has no release section")
	}
	want := "v" + newest[1]
	pinned := regexp.MustCompile(`releases/download/(v\d+\.\d+\.\d+)/|--branch (v\d+\.\d+\.\d+)\b|CERTISTACK_VERSION=(v\d+\.\d+\.\d+)|(?m)^version=(v\d+\.\d+\.\d+)$`)
	found := 0
	for _, page := range [][]string{{"docs", "quickstart.md"}, {"docs", "manual-setup.md"}, {"SECURITY.md"}, {"README.md"}, {"deploy", "controller", "README.md"}, {"deploy", "appliance", "README.md"}} {
		for _, m := range pinned.FindAllStringSubmatch(readRepoText(t, page...), -1) {
			found++
			for _, got := range m[1:] {
				if got != "" && got != want {
					t.Errorf("%v pins %s in %q; the newest release in CHANGELOG.md is %s", page, got, m[0], want)
				}
			}
		}
	}
	if found < 4 {
		t.Fatalf("found only %d pinned releases in the pages; the patterns no longer match how the pages pin a release", found)
	}
}
