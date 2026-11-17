// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The .lab directory is local test material and is not versioned. Whatever CI
// and the release workflow run has to live outside it, or a fresh checkout
// could not build itself.
func TestPublicBuildDoesNotNeedTheLabDirectory(t *testing.T) {
	readers := []string{repoFile("Makefile")}
	for _, pattern := range []string{
		repoFile(".github", "workflows", "*.yml"),
		repoFile("scripts", "*"),
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
}

// .gitignore ignores .lab/ and re-includes nothing under it; an exception would
// version local test files into a published tree.
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
		t.Error(".gitignore does not ignore .lab/")
	}
}
