// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"strings"
	"testing"
)

// `verify-report --unsigned` is how a script gates on a report of the Community
// Edition, which writes its reports unsigned, so it is in the feature list that
// promises what Community keeps free (TestCommunityFeatureListMatchesTheCode
// holds the list to flags the code declares; this holds the list to naming this
// one).
func TestCommunityFeatureListNamesTheUnsignedGate(t *testing.T) {
	list := section(t, readRepoText(t, "docs", "editions.md"), "Community feature list")
	for _, line := range strings.Split(list, "\n") {
		if rest, ok := strings.CutPrefix(line, "- Flags: "); ok {
			if !strings.Contains(rest, "`--unsigned`") {
				t.Error("docs/editions.md's list of Community flags does not name `--unsigned`, the flag that judges a Community report")
			}
			return
		}
	}
	t.Fatal("docs/editions.md has no \"- Flags:\" bullet under \"Community feature list\"")
}
