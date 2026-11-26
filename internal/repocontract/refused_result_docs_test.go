// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// A report the controller refuses keeps its raw worker result as a file that is
// not evidence. Where the file is kept is documented where an operator meets the
// refusal and where the files are listed, in the code's own names; the
// behaviors are pinned by pkg/attest (refused_test.go), pkg/controller
// (refused_result_test.go) and cmd/certistack (verify_refused_test.go).
func TestKeptRefusedResultsAreDocumented(t *testing.T) {
	read := func(parts ...string) string {
		t.Helper()
		data, err := os.ReadFile(repoFile(parts...))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(data)), " ")
	}
	kept := "/" + attest.RefusedDirName + "/<run-id>" + attest.RefusedResultSuffix + "`"
	for _, page := range []string{"reports.md", "configuration.md"} {
		text := read("docs", page)
		at := strings.Index(text, kept)
		if at < 0 {
			t.Errorf("docs/%s does not say where a refused worker result is kept (…%s)", page, kept)
			continue
		}
		if !strings.Contains(text[at:min(len(text), at+200)], "not evidence") {
			t.Errorf("docs/%s does not say, where it names the kept file, that a refused worker result is not evidence", page)
		}
	}
	issue := headingSection(t, readRepoText(t, "docs", "troubleshooting.md"), "### ", "Issue 43: Worker's report refused")
	if !strings.Contains(issue, "`<output>/"+attest.RefusedDirName+"/`") {
		t.Errorf("Issue 43 of docs/troubleshooting.md does not name the directory the refused result is kept in:\n%s", issue)
	}
}
