// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeValidationFixture(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatalf("read valid fixture: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestCollectPlanPathsReadsOnlyImmediateYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	first := writeValidationFixture(t, dir, "b-plan.yaml")
	second := writeValidationFixture(t, dir, "a-plan.YML")
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore"), 0600); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	_ = writeValidationFixture(t, nested, "nested.yaml")

	paths, _, err := collectPlanPaths(dir)
	if err != nil {
		t.Fatalf("collect directory plans: %v", err)
	}
	want := []string{second, first}
	if len(paths) != len(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("paths = %v, want %v", paths, want)
		}
	}
}

func TestValidateCmdDirectoryReportsEveryPlan(t *testing.T) {
	dir := t.TempDir()
	validPath := writeValidationFixture(t, dir, "valid.yaml")
	invalidPath := filepath.Join(dir, "invalid.yml")
	if err := os.WriteFile(invalidPath, []byte("version: v1\nunknown_field: true\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := validateCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{dir})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "1 of 2 plans are invalid") {
		t.Fatalf("directory validation error = %v", err)
	}
	if !strings.Contains(stdout.String(), "Validating 2 plan files") || !strings.Contains(stdout.String(), validPath) {
		t.Fatalf("directory validation stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), invalidPath) || !strings.Contains(stderr.String(), "unknown_field") {
		t.Fatalf("directory validation stderr = %q", stderr.String())
	}
}

func TestValidateCmdRejectsAmbiguousPlanPath(t *testing.T) {
	dir := t.TempDir()
	plan := writeValidationFixture(t, dir, "valid.yaml")
	cmd := validateCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--plan", plan, plan})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("ambiguous validation path error = %v", err)
	}
}

func TestCollectPlanPathsFollowsATopLevelSymlinkAsRunDoes(t *testing.T) {
	dir := t.TempDir()
	plan := writeValidationFixture(t, dir, "valid.yaml")
	link := filepath.Join(dir, "linked.yaml")
	if err := os.Symlink(plan, link); err != nil {
		t.Skipf("symbolic links unavailable in this test environment: %v", err)
	}
	if paths, _, err := collectPlanPaths(link); err != nil || len(paths) != 1 || paths[0] != link {
		t.Fatalf("a linked plan path: %v, %v", paths, err)
	}
}
