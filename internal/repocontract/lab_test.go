// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The public release carries no .lab directory: it holds the operator's own
// lab (host names, networks, run records), which stays in the internal
// repository. Whatever CI and the release workflow run therefore has to live
// outside it, or the public tree could not build itself.
func TestPublicBuildDoesNotNeedTheLabDirectory(t *testing.T) {
	readers := []string{repoFile("Makefile")}
	for _, pattern := range []string{
		repoFile(".github", "workflows", "*.yml"),
		repoFile("scripts", "*_test.sh"),
	} {
		files, err := filepath.Glob(pattern)
		if err != nil || len(files) == 0 {
			t.Fatalf("%s matched nothing: %v", pattern, err)
		}
		readers = append(readers, files...)
	}
	for _, file := range readers {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), ".lab/") {
			t.Errorf("%s names a path under .lab/, which the public release does not ship; keep what CI runs under scripts/", file)
		}
	}

	// The two campaign tools CI verifies are where the workflows say.
	for _, tool := range []string{"generate_current_coverage_cases.go", "audit_compatibility_matrix.go"} {
		if _, err := os.Stat(repoFile("scripts", "campaign", tool)); err != nil {
			t.Errorf("scripts/campaign/%s: %v", tool, err)
		}
	}
}

// .gitignore ignores .lab/ and re-includes nothing under it; an exception would
// version lab files into a tree that is published.
func TestGitignoreVersionsNothingUnderLab(t *testing.T) {
	raw, err := os.ReadFile(repoFile(".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == ".lab/" {
			seen = true
		}
		if strings.HasPrefix(line, "!.lab/") {
			t.Errorf(".gitignore re-includes %q; nothing under .lab/ may be versioned", line)
		}
	}
	if !seen {
		t.Error(".gitignore no longer ignores .lab/")
	}
}
