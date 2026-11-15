// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var yamlFence = regexp.MustCompile("(?s)```ya?ml\n(.*?)```")

// A plan must list compliance frameworks and a retention, and a docs fragment
// that shows a plan's `compliance:` block with only `sign_key_path` teaches a
// plan that does not validate (one fragment did, and put `vms:` at the top
// level, where a plan has none). Every YAML fragment in the documentation that
// is a plan, by naming its plan_id, compliance or tiers, gives
// compliance.frameworks and retention_days when it has a compliance block, and
// only the top-level keys the reference lists. Fragments that are not YAML (the
// reference's annotated skeleton) are not read.
func TestDocumentedPlanFragmentsAreWhatAPlanNeeds(t *testing.T) {
	reference, err := os.ReadFile(repoFile("docs", "plan-reference.md"))
	if err != nil {
		t.Fatal(err)
	}
	allowed := topLevelKeys(t, string(reference))
	for _, want := range []string{"plan_id", "compliance", "tiers"} {
		if !allowed[want] {
			t.Fatalf("the reference's top-level table does not list %q (read %v)", want, allowed)
		}
	}
	if allowed["vms"] {
		t.Fatal("the reference's top-level table lists vms, which belongs to a tier")
	}

	files, err := filepath.Glob(repoFile("docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, repoFile("README.md"))
	planLike := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, fence := range yamlFence.FindAllStringSubmatchIndex(string(data), -1) {
			body := string(data)[fence[2]:fence[3]]
			line := strings.Count(string(data)[:fence[0]], "\n") + 1
			var document map[string]any
			if yaml.Unmarshal([]byte(body), &document) != nil || document == nil {
				continue
			}
			_, hasCompliance := document["compliance"]
			_, hasPlanID := document["plan_id"]
			_, hasTiers := document["tiers"]
			if !hasCompliance && !hasPlanID && !hasTiers {
				continue
			}
			planLike++
			where := filepath.Base(file) + ":" + strconv.Itoa(line)
			for key := range document {
				if !allowed[key] {
					t.Errorf("%s: the plan fragment has a top-level %q, which a plan does not have (the reference lists %v)", where, key, allowed)
				}
			}
			if !hasCompliance {
				continue
			}
			compliance, _ := document["compliance"].(map[string]any)
			if frameworks, _ := compliance["frameworks"].([]any); len(frameworks) == 0 {
				t.Errorf("%s: the plan fragment's compliance block lists no frameworks, which a plan needs", where)
			}
			if days, _ := compliance["retention_days"].(int); days < 1 {
				t.Errorf("%s: the plan fragment's compliance block gives no retention_days, which a plan needs", where)
			}
		}
	}
	if planLike == 0 {
		t.Error("no plan fragment was found in the documentation; the pattern this test reads has changed")
	}
}

// topLevelKeys reads the keys of the reference's "Top level" table.
func topLevelKeys(t *testing.T, reference string) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	_, section, found := strings.Cut(reference, "### Top level\n")
	if !found {
		t.Fatal("docs/plan-reference.md has no \"### Top level\" section")
	}
	if end := strings.Index(section, "\n###"); end >= 0 {
		section = section[:end]
	}
	row := regexp.MustCompile("^\\| `([a-z_]+)` \\|")
	for _, line := range strings.Split(section, "\n") {
		if m := row.FindStringSubmatch(line); m != nil {
			keys[m[1]] = true
		}
	}
	// "admission is an accepted alias", said in the row for admission_control.
	keys["admission"] = true
	return keys
}
