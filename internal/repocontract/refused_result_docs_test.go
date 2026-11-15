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
// not evidence. What the file is, where it is, and what reads it (nothing that
// reads reports) is documented where an operator meets the refusal; the
// behaviours are pinned by pkg/attest (refused_test.go), pkg/controller
// (refused_result_test.go) and cmd/certistack (verify_refused_test.go). This
// keeps the documentation in place and the banner it quotes the one the code
// writes.
func TestKeptRefusedResultsAreDocumented(t *testing.T) {
	read := func(parts ...string) string {
		t.Helper()
		data, err := os.ReadFile(repoFile(parts...))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(data)), " ")
	}
	troubleshooting := read("docs", "troubleshooting.md")
	for _, want := range []string{
		"`REFUSED, NOT EVIDENCE: this worker result failed the controller's checks and was never signed`",
		"`<output>/refused/<run-id>.refused.txt`",
		"The kept result.",
		"never in the directory's root and never beside a plan's reports",
		"mode 0600",
		"Its name ends in `.refused.txt` and its content is not JSON",
		"CertiStack never deletes it",
		"is not kept, and neither is a report that was saved",
	} {
		if !strings.Contains(troubleshooting, want) {
			t.Errorf("docs/troubleshooting.md no longer says %q", want)
		}
	}
	if !strings.Contains(troubleshooting, attest.RefusedBanner) {
		t.Errorf("docs/troubleshooting.md does not quote the banner the code writes: %q", attest.RefusedBanner)
	}
	if !strings.Contains(read("docs", "architecture.md"), "`<output>/refused/<run-id>.refused.txt` (troubleshooting Issue 34)") {
		t.Error("docs/architecture.md does not say where a refused worker result is kept")
	}
}
