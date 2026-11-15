// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// schemaKeys are the names of every key the plan loader accepts, read from the
// JSON Schema that `certistack schema` prints, which is generated from the
// loader's own types.
func schemaKeys(node any, keys map[string]bool) {
	switch v := node.(type) {
	case map[string]any:
		if properties, ok := v["properties"].(map[string]any); ok {
			for key := range properties {
				keys[key] = true
			}
		}
		for _, child := range v {
			schemaKeys(child, keys)
		}
	case []any:
		for _, child := range v {
			schemaKeys(child, keys)
		}
	}
}

// The plan reference's keys section ("The keys" to the end of the page, with
// its probes) and the keys the plan loader accepts are the same set: a key the loader reads and the
// reference does not name is undocumented, and a name the reference gives a
// row that the loader does not know is a key a plan written from the page
// would be refused for. (The probe types have rows of their own.)
func TestPlanReferenceFieldsAreTheKeysThePlanLoaderAccepts(t *testing.T) {
	keys := map[string]bool{}
	schemaKeys(config.PlanSchema(), keys)
	if len(keys) < 60 {
		t.Fatalf("read only %d plan keys from the schema; the schema's layout has changed", len(keys))
	}
	reference := markdownText(t, docRoot+"/docs/plan-reference.md")
	_, section, found := strings.Cut(reference, "\n## The keys\n")
	if !found {
		t.Fatal("docs/plan-reference.md has no \"## The keys\" section")
	}

	row := regexp.MustCompile(`(?m)^\| \x60([A-Za-z0-9_]+)\x60 \|`)
	documented := map[string]bool{}
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		documented[m[1]] = true
	}
	probeTypes := map[string]bool{}
	for _, name := range []string{"tcp", "http", "dns", "ldap", "mssql", "smb", "qga", "qmp", "screendump"} {
		probeTypes[name] = true
	}

	var undocumented, unknown []string
	for key := range keys {
		if !strings.Contains(section, "`"+key+"`") {
			undocumented = append(undocumented, key)
		}
	}
	for name := range documented {
		if !keys[name] && !probeTypes[name] {
			unknown = append(unknown, name)
		}
	}
	sort.Strings(undocumented)
	sort.Strings(unknown)
	for _, key := range undocumented {
		t.Errorf("the plan loader accepts the key %q, and the keys section of docs/plan-reference.md never names it", key)
	}
	for _, name := range unknown {
		t.Errorf("the keys section of docs/plan-reference.md has a row for %q, which is not a key the plan loader accepts", name)
	}
}
