// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/controller"
)

// Review R1-11. The CLI reference showed, and described, a second "Next:" line
// after a pass (certistack verify-report --keyring <trusted-signers> ...) that
// `run` no longer prints: the Community Edition's report is unsigned, so that
// command exits 2 for it. The example output and the sentence that describes it
// are held to what runNextSteps produces.
func TestTheCLIReferenceShowsTheNextLinesARunPrints(t *testing.T) {
	text := markdownText(t, filepath.Join(docRoot, "docs", "cli-reference.md"))
	lines := strings.Split(text, "\n")
	saved := -1
	var path string
	for i, line := range lines {
		if rest, ok := strings.CutPrefix(line, "✓ Controller report saved to: "); ok {
			saved, path = i, strings.TrimSpace(rest)
			break
		}
	}
	if saved < 0 {
		t.Fatal("docs/cli-reference.md has no example of the line 'Controller report saved to:'")
	}
	var shown []string
	for _, line := range lines[saved+1:] {
		if !strings.HasPrefix(line, "Next: ") {
			break
		}
		// The example writes the report's file name as <report-id>; a real name
		// has no angle brackets, which the command would have to quote.
		shown = append(shown, strings.ReplaceAll(line, "<report-id>", "0123abcd"))
	}
	path = strings.ReplaceAll(path, "<report-id>", "0123abcd")
	want := runNextSteps(&controller.Result{Report: &attest.Report{AllPassed: true}, ReportPath: path}, nil)
	if strings.Join(shown, "\n") != strings.Join(want, "\n") {
		t.Errorf("the example after a pass shows\n%s\nand run prints\n%s", strings.Join(shown, "\n"), strings.Join(want, "\n"))
	}

	// The prose says how many there are, and none of them is a verify-report
	// command with a keyring.
	count := map[int]string{1: "one line", 2: "two lines"}[len(want)]
	if count == "" || !strings.Contains(text, "After a pass, "+count) {
		t.Errorf("the description of the next steps does not say that after a pass there is %q", count)
	}
	for _, line := range want {
		if strings.Contains(line, "verify-report") {
			t.Errorf("run prints a verify-report line after a pass: %q; the test and the docs must change together", line)
		}
	}
	if strings.Contains(text, "command with `--keyring <trusted-signers>`, where you put") {
		t.Error("the description still sends the reader of a pass to verify-report --keyring")
	}
}
