// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// docRoot is the repository root, from this package's directory.
const docRoot = "../.."

// documentationFiles lists the Markdown a reader is sent to: the README, the
// pages under docs/, the examples and deployment guides and the other
// top-level documents. CHANGELOG.md is left out: it records the commands and
// flags of earlier releases.
func documentationFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, pattern := range []string{
		"README.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md", "LICENSING-FAQ.md",
		"docs/*.md", "examples/README.md", "deploy/*/README.md",
	} {
		matches, err := filepath.Glob(filepath.Join(docRoot, filepath.FromSlash(pattern)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	if len(files) < 15 {
		t.Fatalf("found only %d documentation files (%v); the layout this test reads has changed", len(files), files)
	}
	return files
}

// markdownLine is one line of a Markdown file, with whether it sits inside a
// fenced block and that block's language.
type markdownLine struct {
	file   string
	number int
	text   string
	fenced bool
	lang   string
}

func (l markdownLine) where() string {
	rel, err := filepath.Rel(docRoot, l.file)
	if err != nil {
		rel = l.file
	}
	return filepath.ToSlash(rel) + ":" + strconv.Itoa(l.number)
}

// markdownLines reads a file's lines. The fence lines themselves are not
// returned.
func markdownLines(t *testing.T, path string) []markdownLine {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []markdownLine
	fence, lang := "", ""
	for i, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimRight(raw, "\r")
		trimmed := strings.TrimLeft(raw, " \t")
		switch {
		case fence == "" && (strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")):
			fence = trimmed[:3]
			lang = strings.TrimSpace(strings.TrimLeft(trimmed, "`~"))
			if cut := strings.IndexAny(lang, " {"); cut >= 0 {
				lang = lang[:cut]
			}
		case fence != "" && strings.HasPrefix(trimmed, fence):
			fence, lang = "", ""
		default:
			lines = append(lines, markdownLine{file: path, number: i + 1, text: raw, fenced: fence != "", lang: lang})
		}
	}
	return lines
}

var inlineCode = regexp.MustCompile("`([^`\n]+)`")

// markdownText reads a file whole.
func markdownText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
