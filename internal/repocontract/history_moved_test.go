// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// `history` moved from the Community Edition to the Enterprise Edition on
// 2026-10-08, before the first release. The pages that list what Community
// does must not offer it, and docs/community-commitments.md must say that it moved, when,
// and that nothing which shipped in a release has moved: the pledge is only as
// good as the account of its one exception.
func TestHistoryMovedToEnterpriseIsStatedAndNotOffered(t *testing.T) {
	doc := readRepoText(t, "docs", "community-commitments.md")

	var commands string
	for _, line := range strings.Split(section(t, doc, "Community feature list"), "\n") {
		if rest, ok := strings.CutPrefix(line, "- Commands: "); ok {
			commands = rest
		}
	}
	if commands == "" {
		t.Fatal("docs/community-commitments.md lists no commands under \"Community feature list\"")
	}
	if strings.Contains(commands, "`history`") {
		t.Error("docs/community-commitments.md still lists `history` as a Community command")
	}

	// The page wraps its lines: compare what it says, not where it breaks.
	flat := strings.Join(strings.Fields(doc), " ")
	moved := regexp.MustCompile(`2026-10-08.{0,300}` + "`history`" + `.{0,300}Enterprise Edition`).FindString(flat)
	if moved == "" {
		t.Error("docs/community-commitments.md does not say, with the date 2026-10-08, that `history` moved to the Enterprise Edition")
	}
	for _, want := range []string{"before the first release", "never in a release", "Nothing that shipped in a release has moved"} {
		if !strings.Contains(flat, want) {
			t.Errorf("docs/community-commitments.md does not say %q about the move of `history`", want)
		}
	}

	// Everywhere else: no page offers the command or lists it as Community's.
	offered := regexp.MustCompile("certistack history|`history`|\\[`history`\\]|#history\\b|\\bhistory \\[DIR\\]")
	var files []string
	for _, pattern := range []string{"README.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md", "LICENSING-FAQ.md", "CHANGELOG.md", "docs/*.md"} {
		matches, err := filepath.Glob(repoFile(filepath.FromSlash(pattern)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	for _, root := range []string{"deploy", "examples", "terraform"} {
		err := filepath.WalkDir(repoFile(root), func(path string, entry fs.DirEntry, err error) error {
			if err == nil && !entry.IsDir() && strings.HasSuffix(path, ".md") {
				files = append(files, path)
			}
			return err
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if len(files) < 10 {
		t.Fatalf("found only %d documents to check", len(files))
	}
	for _, file := range files {
		if filepath.Base(file) == "community-commitments.md" {
			continue // the account of the move is the one place that names it
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(data), "\n") {
			if offered.MatchString(line) {
				t.Errorf("%s:%d offers the Community command history, which moved to the Enterprise Edition: %s", filepath.ToSlash(file), number+1, strings.TrimSpace(line))
			}
		}
	}
}
