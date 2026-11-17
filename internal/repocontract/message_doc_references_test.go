// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/recoverhint"
)

// messageLiteral is a string the binary can print, with where it is written.
type messageLiteral struct {
	where string
	text  string
}

// binaryStrings are the string literals of the non-test Go code of the
// binaries and their packages: every message an operator can read.
func binaryStrings(t *testing.T) []messageLiteral {
	t.Helper()
	var out []messageLiteral
	fset := token.NewFileSet()
	for _, root := range []string{"cmd", "internal", "pkg"} {
		err := filepath.WalkDir(repoFile(root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				text, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				rel, _ := filepath.Rel(repoFile(), path)
				out = append(out, messageLiteral{where: filepath.ToSlash(rel) + ":" + strconv.Itoa(fset.Position(lit.Pos()).Line), text: text})
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) < 5000 {
		t.Fatalf("found only %d string literals in cmd, internal and pkg; the scan this test makes has changed", len(out))
	}
	return out
}

// headingsOf are the texts of a Markdown file's headings, as the page renders
// them, at any level.
func headingsOf(t *testing.T, file string) map[string]bool {
	t.Helper()
	headings := map[string]bool{}
	for _, line := range proseLines(t, file) {
		if m := headingLine.FindStringSubmatch(line.text); m != nil {
			headings[headingText(m[2])] = true
		}
	}
	return headings
}

var (
	// "docs/page.md", "deploy/controller/README.md", with an optional #anchor.
	messagePageRef = regexp.MustCompile(`\b((?:docs|deploy)/[A-Za-z0-9._/-]+\.md)(#[A-Za-z0-9_-]+)?`)
	// A section named by its heading, right after its page: docs/page.md, "Heading".
	messageSectionRef = regexp.MustCompile(`\b((?:docs|deploy)/[A-Za-z0-9._/-]+\.md), "([^"]+)"`)
	// Issue 39, Issues 26 and 27: the troubleshooting page's numbered issues.
	messageIssueRef = regexp.MustCompile(`\bIssues? (\d+)(?: and (\d+))?`)
	// "(quickstart ...": the only way to name one of its sections is its step.
	messageQuickstartRef = regexp.MustCompile(`\(quickstart([^)]*)`)
	quickstartStepOnly   = regexp.MustCompile(`^,? step( \d+| %d)? ?$`)
	messageStepRef       = regexp.MustCompile(`\bquickstart\)?,? \(?step (\d+)`)
)

// A message that sends the reader to the documentation names something that
// is there: a page that exists, a heading or anchor of it, a numbered issue of
// the troubleshooting page, a numbered step of the quickstart. A section is
// named by its heading, in quotes, right after its page; a step by its number.
func TestMessagesNameDocumentationThatExists(t *testing.T) {
	anchorCache := map[string][2]map[string]bool{}
	headingCache := map[string]map[string]bool{}
	checked := 0

	for _, lit := range binaryStrings(t) {
		text := lit.text

		for _, m := range messagePageRef.FindAllStringSubmatch(text, -1) {
			page, fragment := m[1], strings.TrimPrefix(m[2], "#")
			file := repoFile(filepath.FromSlash(page))
			if !existsExactly(file) {
				t.Errorf("%s: the message names %s, which does not exist", lit.where, page)
				continue
			}
			checked++
			if fragment == "" {
				continue
			}
			anchors, ok := anchorCache[page]
			if !ok {
				mkdocs, github := anchorsOf(t, file)
				anchors = [2]map[string]bool{mkdocs, github}
				anchorCache[page] = anchors
			}
			offered := anchors[1]
			if strings.HasPrefix(page, "docs/") {
				offered = anchors[0]
			}
			if !offered[fragment] {
				t.Errorf("%s: the message names %s#%s, and %s has no such anchor", lit.where, page, fragment, page)
			}
		}

		for _, m := range messageSectionRef.FindAllStringSubmatch(text, -1) {
			page, heading := m[1], m[2]
			file := repoFile(filepath.FromSlash(page))
			if !existsExactly(file) {
				continue // reported above
			}
			headings, ok := headingCache[page]
			if !ok {
				headings = headingsOf(t, file)
				headingCache[page] = headings
			}
			checked++
			if !headings[heading] {
				t.Errorf("%s: the message sends the reader to %q in %s, and that page has no heading of that name", lit.where, heading, page)
			}
		}

		for _, m := range messageIssueRef.FindAllStringSubmatch(text, -1) {
			headings, ok := headingCache["docs/troubleshooting.md"]
			if !ok {
				headings = headingsOf(t, repoFile("docs", "troubleshooting.md"))
				headingCache["docs/troubleshooting.md"] = headings
			}
			for _, number := range m[1:] {
				if number == "" {
					continue
				}
				checked++
				found := false
				for heading := range headings {
					if strings.HasPrefix(heading, "Issue "+number+":") {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: the message names Issue %s, and docs/troubleshooting.md has no such issue", lit.where, number)
				}
			}
		}

		for _, m := range messageQuickstartRef.FindAllStringSubmatch(text, -1) {
			checked++
			if !quickstartStepOnly.MatchString(m[1]) {
				t.Errorf("%s: the message names the quickstart as %q; the quickstart's sections are numbered steps, so name one as (quickstart step N), or send the reader to another page by its heading", lit.where, "(quickstart"+m[1]+")")
			}
		}
		for _, m := range messageStepRef.FindAllStringSubmatch(text, -1) {
			headings, ok := headingCache["docs/quickstart.md"]
			if !ok {
				headings = headingsOf(t, repoFile("docs", "quickstart.md"))
				headingCache["docs/quickstart.md"] = headings
			}
			found := false
			for heading := range headings {
				if strings.HasPrefix(heading, m[1]+". ") {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: the message names quickstart step %s, and docs/quickstart.md has no such step", lit.where, m[1])
			}
		}
	}
	if checked < 10 {
		t.Fatalf("checked only %d documentation references in the binary's messages; the pattern this test reads has changed", checked)
	}
}

var certistackRecover = regexp.MustCompile(`\bcertistack recover\b`)

// A node set up by the documentation has no certistack on its PATH: a message
// that tells the operator to "run certistack recover" names a command the
// reader does not have. The messages name what exists, in one wording
// (recoverhint): the node's next run recovers first, or the kept worker's
// certistack-node recover runs the recovery by hand. `certistack recover` is
// the controller binary's subcommand, and only its own help text may name it.
func TestMessagesDoNotSendTheOperatorToCertistackRecover(t *testing.T) {
	for _, lit := range binaryStrings(t) {
		if strings.HasPrefix(lit.where, "cmd/certistack/cmd_recover.go:") {
			continue
		}
		if certistackRecover.MatchString(lit.text) {
			t.Errorf("%s: the message names `certistack recover`, which a node set up by the documentation does not have; use the wording of internal/recoverhint", lit.where)
		}
	}
}

// What recoverhint says is what Issue 35 of the troubleshooting guide gives: the
// kept worker's recover subcommand, run with the state directory and the kept
// workspace's environment file, and the node's next run recovering first.
func TestRecoverHintMatchesTheTroubleshootingGuide(t *testing.T) {
	data, err := os.ReadFile(repoFile("docs", "troubleshooting.md"))
	if err != nil {
		t.Fatal(err)
	}
	guide := string(data)
	start := strings.Index(guide, "### Issue 35:")
	end := strings.Index(guide, "### Issue 36:")
	if start < 0 || end < start {
		t.Fatal("docs/troubleshooting.md has no Issue 35 before Issue 36")
	}
	issue := strings.Join(strings.Fields(guide[start:end]), " ")
	for _, want := range []string{
		"/var/lib/certistack/workers/<run>/certistack-node recover \\ --state-dir /var/lib/certistack \\ --env-file /var/lib/certistack/workers/<run>/runtime.env",
		"next run recovers first",
	} {
		if !strings.Contains(issue, want) {
			t.Errorf("Issue 35 does not say %q, which the recovery messages rely on", want)
		}
	}
	for name, phrase := range map[string]string{
		"Recover": recoverhint.Recover, "Again": recoverhint.Again, "Recovery": recoverhint.Recovery,
	} {
		if !strings.Contains(phrase, recoverhint.Guide) || !strings.Contains(recoverhint.Guide, "Issue 35") {
			t.Errorf("recoverhint.%s does not send the reader to Issue 35: %q", name, phrase)
		}
		if strings.Contains(phrase, "%") {
			t.Errorf("recoverhint.%s holds a %%, and it is concatenated into format strings: %q", name, phrase)
		}
	}
	if !strings.Contains(recoverhint.Recover, "certistack-node recover") {
		t.Errorf("recoverhint.Recover does not name the kept worker's command: %q", recoverhint.Recover)
	}
}
