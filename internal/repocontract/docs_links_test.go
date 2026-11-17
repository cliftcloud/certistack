// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"gopkg.in/yaml.v3"
)

// linkedDocuments are the Markdown files whose links and named paths must
// resolve: the README and the other top-level documents, everything under
// docs/, the example and deployment guides and the changelog.
func linkedDocuments(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, pattern := range []string{
		"*.md", "docs/*.md", "examples/README.md", "deploy/*/README.md", "deploy/*/*/README.md",
	} {
		matches, err := filepath.Glob(repoFile(filepath.FromSlash(pattern)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	if len(files) < 20 {
		t.Fatalf("found only %d Markdown documents (%v); the layout this test reads has changed", len(files), files)
	}
	return files
}

// docLine is a line of prose: not inside a fenced block.
type docLine struct {
	number int
	text   string
}

// proseLines are the lines of a Markdown file outside fenced blocks, and the
// fenced blocks' languages are not needed.
func proseLines(t *testing.T, file string) []docLine {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var lines []docLine
	fence := ""
	for i, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimRight(raw, "\r")
		trimmed := strings.TrimLeft(raw, " \t")
		switch {
		case fence == "" && (strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")):
			fence = trimmed[:3]
		case fence != "" && strings.HasPrefix(trimmed, fence):
			fence = ""
		case fence == "":
			lines = append(lines, docLine{i + 1, raw})
		}
	}
	return lines
}

var (
	inlineCodeSpan  = regexp.MustCompile("`[^`\n]*`")
	inlineLink      = regexp.MustCompile(`\]\(\s*(<[^>]*>|[^)\s]*)(?:\s+(?:"[^"]*"|'[^']*'))?\s*\)`)
	referenceLink   = regexp.MustCompile(`^\s{0,3}\[[^\]]+\]:\s+(\S+)`)
	htmlLink        = regexp.MustCompile(`(?:href|src)="([^"]*)"`)
	headingLine     = regexp.MustCompile(`^(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$`)
	attrID          = regexp.MustCompile(`\{\s*#([A-Za-z0-9_:.-]+)[^}]*\}`)
	htmlID          = regexp.MustCompile(`(?:id|name)="([^"]+)"`)
	snippetInclude  = regexp.MustCompile(`^--8<--\s+"([^"]+)"`)
	markdownLinkTxt = regexp.MustCompile(`!?\[([^\]]*)\]\([^)]*\)`)
	htmlTag         = regexp.MustCompile(`<[^>]+>`)
)

// headingText is a heading's text as the page renders it: code quotes, links,
// emphasis and HTML tags removed.
func headingText(raw string) string {
	text := attrID.ReplaceAllString(raw, "")
	text = markdownLinkTxt.ReplaceAllString(text, "$1")
	text = strings.NewReplacer("`", "", "**", "", "__", "", "&amp;", "&", "&lt;", "<", "&gt;", ">").Replace(text)
	text = htmlTag.ReplaceAllString(text, "")
	// *emphasis* with single asterisks.
	text = regexp.MustCompile(`\*([^*]+)\*`).ReplaceAllString(text, "$1")
	return strings.TrimSpace(text)
}

// mkdocsSlug is the anchor mkdocs (Python-Markdown's toc extension) gives a
// heading: ASCII letters, digits, underscore and hyphen, lower case, runs of
// spaces and hyphens made one hyphen.
func mkdocsSlug(text string) string {
	var b strings.Builder
	for _, r := range text {
		switch {
		case r < unicode.MaxASCII && (r == '_' || r == '-' || r == ' ' || r == '\t' || unicode.IsLetter(r) || unicode.IsDigit(r)):
			b.WriteRune(r)
		}
	}
	slug := strings.ToLower(strings.TrimSpace(b.String()))
	return regexp.MustCompile(`[-\s]+`).ReplaceAllString(slug, "-")
}

// githubSlug is the anchor GitHub gives a heading: lower case, punctuation
// other than hyphen and underscore removed, every space a hyphen.
func githubSlug(text string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(text) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.M, r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// anchorsOf lists the anchors a Markdown file offers under each of the two
// renderers, with the duplicate suffixes each uses, and the ids written by
// hand ({#id}, id="..." and name="...").
func anchorsOf(t *testing.T, file string) (mkdocs, github map[string]bool) {
	t.Helper()
	mkdocs, github = map[string]bool{}, map[string]bool{}
	seenMkdocs, seenGithub := map[string]int{}, map[string]int{}
	var read func(file string, depth int)
	read = func(file string, depth int) {
		for _, line := range proseLines(t, file) {
			if m := snippetInclude.FindStringSubmatch(line.text); m != nil && depth < 3 {
				// An include (docs/changelog.md holds the whole CHANGELOG.md).
				included := repoFile(filepath.FromSlash(m[1]))
				if _, err := os.Stat(included); err == nil && strings.HasSuffix(included, ".md") {
					read(included, depth+1)
				}
				continue
			}
			for _, m := range attrID.FindAllStringSubmatch(line.text, -1) {
				mkdocs[m[1]], github[m[1]] = true, true
			}
			for _, m := range htmlID.FindAllStringSubmatch(line.text, -1) {
				mkdocs[m[1]], github[m[1]] = true, true
			}
			m := headingLine.FindStringSubmatch(line.text)
			if m == nil {
				continue
			}
			text := headingText(m[2])
			if id := attrID.FindStringSubmatch(m[2]); id != nil {
				continue // the heading carries its own id, recorded above
			}
			slug := mkdocsSlug(text)
			if n := seenMkdocs[slug]; n > 0 {
				mkdocs[slug+"_"+strconv.Itoa(n)] = true
			} else {
				mkdocs[slug] = true
			}
			seenMkdocs[slug]++
			slug = githubSlug(text)
			if n := seenGithub[slug]; n > 0 {
				github[slug+"-"+strconv.Itoa(n)] = true
			} else {
				github[slug] = true
			}
			seenGithub[slug]++
		}
	}
	read(file, 0)
	return mkdocs, github
}

// existsExactly reports whether the path exists with this exact spelling: a
// case-insensitive file system (Windows, macOS) finds README.MD for README.md,
// and GitHub and the Linux builds do not.
func existsExactly(p string) bool {
	p = filepath.Clean(p)
	dir, base := filepath.Split(p)
	if base == "" || base == "." || base == ".." {
		_, err := os.Stat(p)
		return err == nil
	}
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() == base {
			return dir == "." || existsExactly(dir)
		}
	}
	return false
}

// linksOf lists the link targets of a file's prose, with their line.
func linksOf(t *testing.T, file string) []struct {
	line   int
	target string
} {
	t.Helper()
	var out []struct {
		line   int
		target string
	}
	add := func(line int, target string) {
		target = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(target), "<"), ">")
		if target != "" {
			out = append(out, struct {
				line   int
				target string
			}{line, target})
		}
	}
	for _, line := range proseLines(t, file) {
		text := inlineCodeSpan.ReplaceAllString(line.text, "")
		for _, m := range inlineLink.FindAllStringSubmatch(text, -1) {
			add(line.number, m[1])
		}
		for _, m := range htmlLink.FindAllStringSubmatch(text, -1) {
			add(line.number, m[1])
		}
		if m := referenceLink.FindStringSubmatch(text); m != nil {
			add(line.number, m[1])
		}
	}
	return out
}

// isExternalLink is a link that leaves the repository.
func isExternalLink(target string) bool {
	if i := strings.Index(target, ":"); i > 0 && !strings.ContainsAny(target[:i], "/#") {
		return true // https:, mailto:, tel:, and so on
	}
	return strings.HasPrefix(target, "//")
}

// Every relative link in the README, the top-level documents, docs/, the
// example and deployment guides resolves to a file or directory that exists
// with that exact spelling, and a #fragment names a heading (or an id written
// by hand) of the page it points at, under the slug rule of the renderer that
// shows the link: mkdocs for a page under docs/ (which the site publishes),
// GitHub for the others.
func TestDocumentationLinksAndAnchorsResolve(t *testing.T) {
	cache := map[string][2]map[string]bool{}
	anchors := func(file string) (map[string]bool, map[string]bool) {
		if c, ok := cache[file]; ok {
			return c[0], c[1]
		}
		a, b := anchorsOf(t, file)
		cache[file] = [2]map[string]bool{a, b}
		return a, b
	}
	docsDir := repoFile("docs")
	checked := 0
	for _, file := range linkedDocuments(t) {
		rel, _ := filepath.Rel(repoFile(), file)
		inDocs := filepath.Dir(file) == docsDir
		for _, link := range linksOf(t, file) {
			target := link.target
			where := filepath.ToSlash(rel) + ":" + strconv.Itoa(link.line)
			if isExternalLink(target) {
				continue
			}
			pathPart, fragment, _ := strings.Cut(target, "#")
			if i := strings.IndexAny(pathPart, "?"); i >= 0 {
				pathPart = pathPart[:i]
			}
			if decoded, err := url.PathUnescape(pathPart); err == nil {
				pathPart = decoded
			}
			if decoded, err := url.PathUnescape(fragment); err == nil {
				fragment = decoded
			}
			checked++
			resolved := file
			if pathPart != "" {
				if strings.HasPrefix(pathPart, "/") {
					t.Errorf("%s: the link %q is absolute; a page cannot count on where the site or the repository is served from", where, target)
					continue
				}
				resolved = filepath.Join(filepath.Dir(file), filepath.FromSlash(pathPart))
				if !existsExactly(resolved) {
					t.Errorf("%s: the link %q points at %s, which does not exist", where, target, filepath.ToSlash(strings.TrimPrefix(resolved, repoFile()+string(filepath.Separator))))
					continue
				}
				if inDocs {
					inside, err := filepath.Rel(docsDir, resolved)
					if err != nil || strings.HasPrefix(inside, "..") {
						t.Errorf("%s: the link %q leaves docs/, which is all the site publishes; link the file on GitHub (https://github.com/cliftcloud/certistack/blob/main/...) instead", where, target)
						continue
					}
				}
			}
			if fragment == "" || !strings.HasSuffix(resolved, ".md") {
				continue
			}
			mkdocs, github := anchors(resolved)
			offered := github
			if inDocs {
				offered = mkdocs
			}
			if !offered[fragment] {
				var names []string
				for a := range offered {
					names = append(names, a)
				}
				sort.Strings(names)
				t.Errorf("%s: the link %q names the anchor #%s, which %s has no heading for (it has %s)", where, target, fragment, filepath.ToSlash(path.Base(filepath.ToSlash(resolved))), nearestAnchors(fragment, names))
			}
		}
	}
	if checked < 100 {
		t.Fatalf("checked only %d relative links; the pattern this test reads has changed", checked)
	}
}

// nearestAnchors names up to three anchors that share the longest prefix with
// the wrong one, so that the failure says what it probably should have been.
func nearestAnchors(wrong string, names []string) string {
	type scored struct {
		name  string
		score int
	}
	var all []scored
	for _, n := range names {
		score := 0
		for score < len(n) && score < len(wrong) && n[score] == wrong[score] {
			score++
		}
		all = append(all, scored{n, score})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].score > all[j].score })
	var out []string
	for i := 0; i < len(all) && i < 3; i++ {
		out = append(out, "#"+all[i].name)
	}
	return strings.Join(out, ", ")
}

// repositoryRoots are the names a path starts with when it is a path in this
// repository, as the documentation writes them.
var repositoryRoots = []string{
	"cmd/", "pkg/", "internal/", "docs/", "examples/", "deploy/", "scripts/", "terraform/", "release/",
	"testdata/", ".github/",
}

// generatedPaths are named in the documentation and not in the repository: a
// build writes them.
var generatedPaths = []string{"bin/", "dist/", "site/"}

// topLevelFile is a file name at the root of the repository that a guide may
// name on its own.
var topLevelFile = regexp.MustCompile(`^(?:[A-Z][A-Z-]*\.md|LICENSE|NOTICE|Makefile|go\.mod|go\.sum|mkdocs\.yml|requirements-docs\.txt)$`)

// siblingDirectories lists the directories inside dir, except the repository
// root, whose directories are the repositoryRoots already.
func siblingDirectories(t *testing.T, dir string) []string {
	t.Helper()
	if filepath.Clean(dir) == filepath.Clean(repoFile()) {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

// Every file or directory a guide names in code quotes as a path of this
// repository exists (a wildcard matches something), so no guide sends the
// reader to a file that is not there.
func TestDocumentedRepositoryPathsExist(t *testing.T) {
	checked := 0
	for _, file := range linkedDocuments(t) {
		rel, _ := filepath.Rel(repoFile(), file)
		if filepath.Base(file) == "CHANGELOG.md" || filepath.Base(file) == "changelog.md" {
			continue // release notes may name files as they were at that release
		}
		for _, line := range proseLines(t, file) {
			for _, span := range regexp.MustCompile("`([^`\n]+)`").FindAllStringSubmatch(line.text, -1) {
				name := strings.TrimSpace(span[1])
				if strings.ContainsAny(name, " <>{}$()=|") {
					continue
				}
				name = strings.TrimPrefix(name, "./")
				// path:line and path#anchor name the file.
				if cut := strings.IndexAny(name, ":#"); cut >= 0 {
					name = name[:cut]
				}
				isPath := topLevelFile.MatchString(name)
				base := repoFile()
				for _, root := range repositoryRoots {
					if strings.HasPrefix(name, root) {
						isPath = true
					}
				}
				// A guide in a directory of its own (deploy/appliance) also names
				// the directories beside it (files/, packer/) from where it sits.
				if !isPath {
					for _, sibling := range siblingDirectories(t, filepath.Dir(file)) {
						if strings.HasPrefix(name, sibling+"/") {
							isPath, base = true, filepath.Dir(file)
						}
					}
				}
				for _, root := range generatedPaths {
					if strings.HasPrefix(name, root) {
						isPath = false
					}
				}
				if !isPath {
					continue
				}
				checked++
				where := filepath.ToSlash(rel) + ":" + strconv.Itoa(line.number)
				full := filepath.Join(base, filepath.FromSlash(name))
				if strings.ContainsAny(name, "*?[") {
					matches, err := filepath.Glob(full)
					if err != nil || len(matches) == 0 {
						t.Errorf("%s: `%s` matches nothing in the repository", where, span[1])
					}
					continue
				}
				if !existsExactly(full) {
					t.Errorf("%s: `%s` names a path that is not in the repository", where, span[1])
				}
			}
		}
	}
	if checked < 50 {
		t.Fatalf("checked only %d repository paths; the pattern this test reads has changed", checked)
	}
}

// The site's navigation names pages that exist, and every page under docs/ is
// in it: a page left out is built and linked to by nothing.
func TestSiteNavigationListsEveryDocsPage(t *testing.T) {
	data, err := os.ReadFile(repoFile("mkdocs.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Nav []any `yaml:"nav"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	var walk func(node any)
	walk = func(node any) {
		switch v := node.(type) {
		case string:
			listed[v] = true
		case []any:
			for _, item := range v {
				walk(item)
			}
		case map[string]any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(config.Nav)
	if len(listed) < 10 {
		t.Fatalf("read only %d pages from the navigation (%v)", len(listed), listed)
	}
	for page := range listed {
		if !existsExactly(repoFile("docs", filepath.FromSlash(page))) {
			t.Errorf("mkdocs.yml lists %s in the navigation, and docs/%s does not exist", page, page)
		}
	}
	pages, err := filepath.Glob(repoFile("docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, page := range pages {
		name := filepath.Base(page)
		// docs/README.md is the folder's landing page on GitHub, which
		// mkdocs.yml excludes from the site.
		if name == "README.md" {
			continue
		}
		if !listed[name] {
			t.Errorf("docs/%s is not in the navigation of mkdocs.yml", name)
		}
	}
}

// The slug rules and the link reader are checked against headings whose
// anchors are known, so that a failure of the test above means a broken link
// and not a misread heading.
func TestAnchorSlugsFollowTheRenderers(t *testing.T) {
	for _, c := range []struct{ heading, mkdocs, github string }{
		{"Quickstart", "quickstart", "quickstart"},
		{"1. Install the CLI", "1-install-the-cli", "1-install-the-cli"},
		{"Issue 24: QGA is connected, but the report says guest-exec is unavailable", "issue-24-qga-is-connected-but-the-report-says-guest-exec-is-unavailable", "issue-24-qga-is-connected-but-the-report-says-guest-exec-is-unavailable"},
		{"`init --inspect`", "init-inspect", "init---inspect"},
		{"Write a first plan (`certistack init`)", "write-a-first-plan-certistack-init", "write-a-first-plan-certistack-init"},
		{"Terraform & PVE", "terraform-pve", "terraform--pve"},
		{"plan_id and name", "plan_id-and-name", "plan_id-and-name"},
	} {
		text := headingText(c.heading)
		if got := mkdocsSlug(text); got != c.mkdocs {
			t.Errorf("mkdocs slug of %q = %q, want %q", c.heading, got, c.mkdocs)
		}
		if got := githubSlug(text); got != c.github {
			t.Errorf("GitHub slug of %q = %q, want %q", c.heading, got, c.github)
		}
	}
	for _, c := range []struct {
		target   string
		external bool
	}{
		{"https://example.com/a", true}, {"tel:+15550100", true}, {"//cdn.example/x", true},
		{"docs/quickstart.md#step-1", false}, {"#top", false}, {"../README.md", false}, {"a:b/c.md", true},
	} {
		if got := isExternalLink(c.target); got != c.external {
			t.Errorf("isExternalLink(%q) = %v, want %v", c.target, got, c.external)
		}
	}
}
