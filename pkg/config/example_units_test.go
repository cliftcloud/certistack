// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bareGroupingUnit matches a service check that names Debian's `postgresql`
// grouping unit: a oneshot unit that reports active with no database cluster
// running, and so passes on a guest whose database is down or was never
// restored. The cluster's own unit (`postgresql@16-main`) follows the name
// with an at sign and is what an example must name.
var bareGroupingUnit = regexp.MustCompile(`systemctl is-active postgresql(\.service)?(["'\s]|$)`)

// The plan an operator copies must not teach a check that passes
// without the service it names. Every plan file CertiStack ships, and every
// YAML block in the docs, is scanned for the grouping unit.
func TestShippedExamplesDoNotAssertTheDebianPostgreSQLGroupingUnit(t *testing.T) {
	var files []string
	for _, pattern := range []string{
		filepath.Join("..", "..", "examples", "*.yaml"),
		filepath.Join("..", "..", "testdata", "plans", "*.yaml"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	docs, err := filepath.Glob(filepath.Join("..", "..", "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	docs = append(docs, filepath.Join("..", "..", "README.md"), filepath.Join("..", "..", "examples", "README.md"))
	if len(files) < 3 || len(docs) < 5 {
		t.Fatalf("found %d plan files and %d documents; the scan is looking in the wrong place", len(files), len(docs))
	}

	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			if bareGroupingUnit.MatchString(line) {
				t.Errorf("%s:%d names the bare postgresql unit, which is active on Debian and Ubuntu with no database running; name the cluster's unit (postgresql@16-main)", path, number+1)
			}
		}
	}
	for _, path := range docs {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		inFence := false
		for number, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				inFence = !inFence
				continue
			}
			// Prose may explain the trap; only a block someone copies counts.
			if inFence && !strings.HasPrefix(strings.TrimSpace(line), "#") && bareGroupingUnit.MatchString(line) {
				t.Errorf("%s:%d: a code block names the bare postgresql unit, which is active on Debian and Ubuntu with no database running; name the cluster's unit (postgresql@16-main)", path, number+1)
			}
		}
	}
}

// The scan itself: it finds the trap and passes the cluster's unit.
func TestBareGroupingUnitPatternFindsTheTrapOnly(t *testing.T) {
	for line, want := range map[string]bool{
		`command: "systemctl is-active postgresql"`:         true,
		`command: 'systemctl is-active postgresql'`:         true,
		`command: systemctl is-active postgresql`:           true,
		`command: "systemctl is-active postgresql "`:        true,
		`command: "systemctl is-active postgresql@16-main"`: false,
		`command: "systemctl is-active postgresql-16"`:      false,
		`command: "systemctl is-active postgresql.service"`: true,
		`command: "systemctl is-active nginx"`:              false,
	} {
		if got := bareGroupingUnit.MatchString(line); got != want {
			t.Errorf("bareGroupingUnit.MatchString(%q) = %v, want %v", line, got, want)
		}
	}
}
