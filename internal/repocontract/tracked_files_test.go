// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CI and the release workflow read only tracked files. Whatever they run lives
// outside the directories a developer's checkout may hold untracked, or a
// fresh checkout could not build itself, and .gitignore re-includes nothing
// under those directories.
func TestCIAndReleaseReadOnlyTrackedFiles(t *testing.T) {
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
		for dir := range untrackedDirs {
			if strings.Contains(string(raw), dir+"/") {
				t.Errorf("%s names a path under %s/, which a fresh checkout does not have; keep what CI runs under scripts/", file, dir)
			}
		}
	}

	raw, err := os.ReadFile(repoFile(".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		for dir := range untrackedDirs {
			if strings.HasPrefix(line, "!"+dir+"/") {
				t.Errorf(".gitignore re-includes %q; nothing under %s/ may be tracked", line, dir)
			}
		}
	}
}
