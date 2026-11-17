// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// environmentVariableName is how the documentation spells a variable of this
// product: the three prefixes every one of them has.
var environmentVariableName = regexp.MustCompile(`\b(?:PVE|PBS|CERTISTACK)_[A-Z0-9]+(?:_[A-Z0-9]+)*\b`)

// processEnvironmentOnly are the variables the documentation describes as
// read from the process environment and never from an environment file, so the
// file's allowlist must not accept them (a name in the file is an error, and
// the page says so).
var processEnvironmentOnly = map[string]bool{
	"DO_NOT_TRACK":                  true,
	"CERTISTACK_TELEMETRY":          true,
	"CERTISTACK_TELEMETRY_BUSINESS": true,
	"CERTISTACK_TELEMETRY_URL":      true,
}

// acceptedEnvironmentNames is every name an environment file may hold, for the
// controller and for a node worker.
func acceptedEnvironmentNames() map[string]bool {
	names := map[string]bool{}
	for name := range controllerEnvironmentNames {
		names[name] = true
	}
	for name := range workerEnvironmentNames {
		names[name] = true
	}
	return names
}

// variablesTable lists the variables the "## Variables" section of the
// configuration reference puts in the first cell of its table rows, keyed by
// the heading they are under.
func variablesTable(t *testing.T) map[string][]string {
	t.Helper()
	sections := map[string][]string{}
	var heading string
	row := regexp.MustCompile("^\\| `([A-Z][A-Z0-9_]*)` \\|")
	inVariables := false
	for _, line := range markdownLines(t, docRoot+"/docs/configuration.md") {
		if line.fenced {
			continue
		}
		if title, ok := strings.CutPrefix(line.text, "## "); ok {
			heading = strings.TrimSpace(attrAnchor.ReplaceAllString(title, ""))
			inVariables = heading == "Variables"
			continue
		}
		if title, ok := strings.CutPrefix(line.text, "### "); ok && inVariables {
			heading = strings.TrimSpace(attrAnchor.ReplaceAllString(title, ""))
			continue
		}
		if m := row.FindStringSubmatch(line.text); m != nil && inVariables {
			sections[heading] = append(sections[heading], m[1])
		}
	}
	return sections
}

// Every name an environment file accepts is in the table of the "Variables"
// section of the configuration reference (anchor #variables, which messages
// name), so a variable added to the allowlist cannot ship undocumented, and
// every variable the table lists is one the file accepts, apart from the ones
// the page says are read from the process environment only.
func TestEnvironmentFileVariablesAndConfigurationReferenceAgree(t *testing.T) {
	accepted := acceptedEnvironmentNames()
	tables := variablesTable(t)
	documented := map[string]string{}
	for heading, names := range tables {
		for _, name := range names {
			documented[name] = heading
		}
	}
	if len(documented) < 25 {
		t.Fatalf("read only %d variables from the configuration reference (%v); the layout this test reads has changed", len(documented), tables)
	}
	for name := range accepted {
		if _, ok := documented[name]; !ok {
			t.Errorf("an environment file accepts %s, which docs/configuration.md does not list in a variables table", name)
		}
	}
	for name, heading := range documented {
		switch {
		case processEnvironmentOnly[name]:
			if accepted[name] {
				t.Errorf("docs/configuration.md says %s is read from the process environment only (\"%s\"), and an environment file accepts it", name, heading)
			}
		case !accepted[name]:
			t.Errorf("docs/configuration.md lists %s under \"%s\", and an environment file does not accept it", name, heading)
		}
	}
	for name := range processEnvironmentOnly {
		if _, ok := documented[name]; !ok {
			t.Errorf("%s is read from the process environment and docs/configuration.md does not list it", name)
		}
	}
}

// sourceNamesOf lists the variable names that shipped files other than
// Markdown mention: Go source (tests included, since the contributor
// documentation names test variables), scripts, workflows, Compose and
// Terraform files and the Makefile. A name that only the documentation
// carries is a name the product does not know.
func sourceNamesOf(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	skipDir := map[string]bool{".git": true, ".lab": true, "node_modules": true, "site": true, "bin": true, "dist": true}
	err := filepath.WalkDir(docRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		base := d.Name()
		// This file and its siblings hold the names as test data.
		if strings.HasPrefix(base, "docs_") && strings.HasSuffix(base, "_test.go") {
			return nil
		}
		switch ext := strings.ToLower(filepath.Ext(base)); ext {
		case ".md", ".png", ".pdf", ".deb", ".gz", ".zip", ".sig", ".asc", ".pub", ".gpg", ".ico", ".svg", ".jpg", ".woff", ".woff2", ".sum":
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 4<<20 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, name := range environmentVariableName.FindAllString(string(data), -1) {
			names[name] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// Every variable the documentation names is one the product reads or a shipped
// file sets: an environment file accepts it, or code or a shipped script or
// workflow mentions it. A renamed or invented variable in a guide is a
// setting that does nothing.
func TestEveryDocumentedEnvironmentVariableExists(t *testing.T) {
	known := sourceNamesOf(t)
	for name := range acceptedEnvironmentNames() {
		known[name] = true
	}
	if len(known) < 40 {
		t.Fatalf("found only %d variable names in the source; the walk this test makes has changed", len(known))
	}
	// A prefix the pages write with a wildcard or a placeholder (CERTISTACK_*),
	// and the family of names the Terraform and packer variables share, are not
	// variable names.
	seen := map[string][]string{}
	for _, file := range documentationFiles(t) {
		for _, line := range markdownLines(t, file) {
			for _, name := range environmentVariableName.FindAllString(line.text, -1) {
				if !known[name] {
					seen[name] = append(seen[name], line.where())
				}
			}
		}
	}
	var unknown []string
	for name := range seen {
		unknown = append(unknown, name)
	}
	sort.Strings(unknown)
	for _, name := range unknown {
		t.Errorf("the documentation names %s (%s), which no code, script or workflow in the repository mentions", name, strings.Join(seen[name], ", "))
	}
}
