// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// docYAMLBlock is a fenced yaml block of a documentation page.
type docYAMLBlock struct {
	where string
	body  string
}

// documentedYAMLBlocks lists the fenced yaml blocks of the documentation.
func documentedYAMLBlocks(t *testing.T) []docYAMLBlock {
	t.Helper()
	var blocks []docYAMLBlock
	for _, file := range documentationFiles(t) {
		var current *docYAMLBlock
		for _, line := range markdownLines(t, file) {
			switch {
			case line.fenced && (line.lang == "yaml" || line.lang == "yml"):
				if current == nil {
					current = &docYAMLBlock{where: line.where()}
				}
				current.body += line.text + "\n"
			case current != nil:
				blocks = append(blocks, *current)
				current = nil
			}
		}
		if current != nil {
			blocks = append(blocks, *current)
		}
	}
	return blocks
}

// validatePlanText runs the command `certistack validate` on a plan held in a
// file of its own, and returns its error.
func validatePlanText(t *testing.T, text string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := validateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		return fmt.Errorf("%w\n%s", err, stderr.String())
	}
	return nil
}

var includedSnippet = regexp.MustCompile(`^--8<--\s+"([^"]+)"\s*$`)

// placeholderChange is the word a plan written by init (and an example) uses
// for a value the reader must choose.
const placeholderChange = "CHANGE"

// planWithValues replaces the documented CHANGE placeholders the way the
// examples show: the compliance frameworks are given a value.
func planWithValues(text string) string {
	return regexp.MustCompile(`frameworks:\s*\[\s*CHANGE\s*\]`).ReplaceAllString(text, `frameworks: ["DORA"]`)
}

// Every plan the documentation shows whole (a yaml block that starts with
// version:), and every plan included from examples/, passes `certistack
// validate`, so a page cannot teach a plan the loader refuses.
func TestDocumentedWholePlansValidate(t *testing.T) {
	plans := 0
	for _, block := range documentedYAMLBlocks(t) {
		var document map[string]any
		if err := yaml.Unmarshal([]byte(block.body), &document); err != nil || document == nil {
			continue
		}
		if _, starts := document["version"]; !starts {
			continue
		}
		if _, whole := document["tiers"]; !whole {
			// The first line of a plan (the editor-schema header) is not a plan; a
			// block that starts one and goes on without tiers is.
			if len(document) > 1 {
				t.Errorf("%s: the block starts a plan with version: and has no tiers, so it is neither a whole plan nor a fragment; show the whole plan or start the block at the part it is about", block.where)
			}
			continue
		}
		plans++
		text := planWithValues(block.body)
		for _, line := range strings.Split(text, "\n") {
			if code, _, _ := strings.Cut(line, "#"); strings.Contains(code, placeholderChange) {
				t.Errorf("%s: the plan keeps a %s placeholder that nothing replaces: %q", block.where, placeholderChange, strings.TrimSpace(line))
			}
		}
		if err := validatePlanText(t, text); err != nil {
			t.Errorf("%s: the plan shown there does not validate: %v", block.where, err)
		}
	}
	// A page that includes a plan from examples/ shows that file, whole.
	for _, file := range documentationFiles(t) {
		for _, line := range markdownLines(t, file) {
			m := includedSnippet.FindStringSubmatch(line.text)
			if m == nil || !strings.HasSuffix(m[1], ".yaml") {
				continue
			}
			plans++
			data, err := os.ReadFile(filepath.Join(docRoot, filepath.FromSlash(m[1])))
			if err != nil {
				t.Errorf("%s: includes %s, which cannot be read: %v", line.where(), m[1], err)
				continue
			}
			if err := validatePlanText(t, string(data)); err != nil {
				t.Errorf("%s: the included plan %s does not validate: %v", line.where(), m[1], err)
			}
		}
	}
	if plans == 0 {
		t.Fatal("no whole plan was found in the documentation; the pattern this test reads has changed")
	}
}

// The yaml fragments the plan reference and the guides show for one part of a
// plan are valid in a plan: a list of probes goes under a VM, a
// network_recovery block under a VM, an admission_control block at the top.
// Each is put into examples/minimal-single-vm.yaml (a probe list replacing its
// probes, one fragment at a time) and the result must validate. The pages show
// at least one such fragment.
func TestDocumentedPlanFragmentsValidateInAPlan(t *testing.T) {
	baseText, err := os.ReadFile(filepath.Join(docRoot, "examples", "minimal-single-vm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	wrapped := map[string]int{}
	for _, block := range documentedYAMLBlocks(t) {
		var parsed any
		if err := yaml.Unmarshal([]byte(block.body), &parsed); err != nil || parsed == nil {
			continue
		}
		var base map[string]any
		if err := yaml.Unmarshal(baseText, &base); err != nil {
			t.Fatal(err)
		}
		vm := base["tiers"].([]any)[0].(map[string]any)["vms"].([]any)[0].(map[string]any)
		kind := ""
		switch v := parsed.(type) {
		case []any:
			if len(v) == 0 {
				continue
			}
			probes := true
			for _, item := range v {
				if m, ok := item.(map[string]any); !ok || m["type"] == nil {
					probes = false
				}
			}
			if !probes {
				continue
			}
			vm["probes"], kind = v, "probe list"
		case map[string]any:
			switch {
			case len(v) == 1 && v["network_recovery"] != nil:
				vm["network_recovery"], kind = v["network_recovery"], "network_recovery block"
			case len(v) == 1 && v["admission_control"] != nil:
				// A block that changes a limit is shown as the keys it changes.
				merged, _ := base["admission_control"].(map[string]any)
				for key, value := range v["admission_control"].(map[string]any) {
					merged[key] = value
				}
				kind = "admission_control block"
			default:
				continue
			}
		default:
			continue
		}
		out, err := yaml.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		wrapped[kind]++
		if err := validatePlanText(t, string(out)); err != nil {
			t.Errorf("%s: the %s shown there does not validate in a plan: %v", block.where, kind, err)
		}
	}
	total := 0
	for _, n := range wrapped {
		total += n
	}
	if total == 0 {
		t.Error("no plan fragment (a probe list, a network_recovery or an admission_control block) was found in the documentation; the pattern this test reads has changed")
	}
}

// Every plan in examples/ passes the validate command when it is given the
// directory, as a reader who copies the folder would run it (the plan loader
// itself is checked file by file, with the address rules, by
// TestShippedPlansValidateAndUseDocumentationAddresses).
func TestExamplesDirectoryPassesValidate(t *testing.T) {
	cmd := validateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{filepath.Join(docRoot, "examples")})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("validate examples: %v\n%s", err, stderr.String())
	}
	files, err := filepath.Glob(filepath.Join(docRoot, "examples", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%d/%d plans are valid", len(files), len(files))
	if len(files) < 3 || !strings.Contains(stdout.String(), want) {
		t.Fatalf("validate examples printed %q for %d plan files, want it to say %q", stdout.String(), len(files), want)
	}
}
