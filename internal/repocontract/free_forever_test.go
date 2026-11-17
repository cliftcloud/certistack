// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The README shows the same comparison of the editions as docs/editions.md,
// row for row, so the two cannot say different things about what Community
// includes.
func TestReadmeEditionTableIsTheEditionsPageTable(t *testing.T) {
	rows := func(doc, heading string) []string {
		var out []string
		for _, line := range strings.Split(section(t, doc, heading), "\n") {
			if strings.HasPrefix(line, "|") {
				out = append(out, line)
			}
		}
		return out
	}
	readme := rows(readRepoText(t, "README.md"), "Community and Enterprise")
	editions := rows(readRepoText(t, "docs", "editions.md"), "Comparison")
	if len(readme) < 10 {
		t.Fatalf("the README edition table has %d lines, want a header and its rows", len(readme))
	}
	if strings.Join(readme, "\n") != strings.Join(editions, "\n") {
		t.Error("the table in README.md (Community and Enterprise) differs from the one in docs/editions.md (Comparison); change both")
	}
}

// The Community feature list of docs/editions.md names the commands, probe
// types and flags the Community Edition has and promises they stay. Removing,
// renaming or moving one of them out of cmd/certistack or pkg/config fails here
// until the page is changed on purpose, in a reviewed change, in public.
func TestCommunityFeatureListMatchesTheCode(t *testing.T) {
	doc := readRepoText(t, "docs", "editions.md")
	list := section(t, doc, "Community feature list")

	listed := map[string][]string{}
	quoted := regexp.MustCompile("`([^`]+)`")
	for _, line := range strings.Split(list, "\n") {
		for _, label := range []string{"Commands", "Probe types", "Flags"} {
			rest, ok := strings.CutPrefix(line, "- "+label+": ")
			if !ok {
				continue
			}
			for _, m := range quoted.FindAllStringSubmatch(rest, -1) {
				listed[label] = append(listed[label], m[1])
			}
		}
	}
	for label, minimum := range map[string]int{"Commands": 8, "Probe types": 8, "Flags": 20} {
		if len(listed[label]) < minimum {
			t.Fatalf("docs/editions.md lists %d %s under \"Community feature list\", want at least %d; the list is a bullet \"- %s: `a`, `b`\"", len(listed[label]), strings.ToLower(label), minimum, label)
		}
	}

	// Commands: a cobra command named in a Use field of cmd/certistack.
	// Flags: a flag declared on a command or the root.
	commands := map[string]bool{}
	flags := map[string]bool{}
	use := regexp.MustCompile(`Use:\s+"([a-z][a-z-]*)`)
	flag := regexp.MustCompile(`Flags\(\)\.(?:Bool|String|Int|Int64|Uint|Float64|Duration|Count)(?:Slice|Array)?(?:Var)?P?\([^"\n]*"([a-z][a-z0-9-]*)"`)
	files, err := filepath.Glob(repoFile("cmd", "certistack", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources found in cmd/certistack: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range use.FindAllStringSubmatch(string(data), -1) {
			commands[m[1]] = true
		}
		for _, m := range flag.FindAllStringSubmatch(string(data), -1) {
			flags[m[1]] = true
		}
	}
	for _, name := range listed["Commands"] {
		if !commands[name] {
			t.Errorf("docs/editions.md lists the command %q, which cmd/certistack does not define", name)
		}
	}
	for _, name := range listed["Flags"] {
		if !strings.HasPrefix(name, "--") || !flags[strings.TrimPrefix(name, "--")] {
			t.Errorf("docs/editions.md lists the flag %q, which cmd/certistack does not declare", name)
		}
	}

	// Probe types: the canonical list the plan validator accepts.
	source := readRepoText(t, "pkg", "config", "probe_fields.go")
	declared := regexp.MustCompile(`(?s)var probeTypes = \[\]string\{([^}]*)\}`).FindStringSubmatch(source)
	if declared == nil {
		t.Fatal("pkg/config/probe_fields.go does not declare probeTypes; update this test with it")
	}
	probes := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([a-z0-9_]+)"`).FindAllStringSubmatch(declared[1], -1) {
		probes[m[1]] = true
	}
	for _, name := range listed["Probe types"] {
		if !probes[name] {
			t.Errorf("docs/editions.md lists the probe type %q, which pkg/config does not accept", name)
		}
	}

	// The check reads the page, so keep the page honest about what it lists:
	// every probe type the code accepts today is on it.
	var missing []string
	for name := range probes {
		found := false
		for _, listedName := range listed["Probe types"] {
			found = found || listedName == name
		}
		if !found {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("docs/editions.md does not list the probe types %v that pkg/config accepts; add them, or the pledge does not cover them", missing)
	}
}
