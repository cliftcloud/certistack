// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every plan in examples/ is listed in examples/README.md and shown, whole,
// in the examples of docs/plan-reference.md, so a plan added to the folder is not left for a
// reader to find by listing it, and a page never shows a file that is gone.
// (That each of them validates is TestShippedPlansValidateAndUseDocumentationAddresses
// and TestExamplesDirectoryPassesValidate, in cmd/certistack.)
func TestEveryExamplePlanIsListedAndShown(t *testing.T) {
	files, err := filepath.Glob(repoFile("examples", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 3 {
		t.Fatalf("found %d example plans, want at least the 3 the guides describe", len(files))
	}
	readme, err := os.ReadFile(repoFile("examples", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	guide, err := os.ReadFile(repoFile("docs", "plan-reference.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		name := filepath.Base(file)
		if !strings.Contains(string(readme), "]("+name+")") {
			t.Errorf("examples/README.md does not list examples/%s", name)
		}
		if !strings.Contains(string(guide), `--8<-- "examples/`+name+`"`) {
			t.Errorf("docs/plan-reference.md does not show examples/%s (include it with --8<-- \"examples/%s\")", name, name)
		}
	}
	for _, line := range strings.Split(string(guide), "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), `--8<-- "examples/`); ok {
			name = strings.TrimSuffix(name, `"`)
			if _, err := os.Stat(repoFile("examples", name)); err != nil {
				t.Errorf("docs/plan-reference.md includes examples/%s, which does not exist", name)
			}
		}
	}
}
