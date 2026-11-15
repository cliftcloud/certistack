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

// validate of one invalid plan printed its problems twice: on a "✗ file: ..."
// line, and again in "Error: plan validation failed: ..." (CR2-11). Everything
// the command says on a terminal is what it writes to standard error plus the
// "Error: " line main prints for the returned error; the problem must be there
// once, the plan named, and the exit status the same.
func TestValidateOfOneInvalidPlanSaysItsProblemsOnce(t *testing.T) {
	dir := t.TempDir()
	invalid := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("version: v1\nunknown_field: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"the plan file":                    {invalid},
		"--plan":                           {"--plan", invalid},
		"a directory holding only the one": {dir},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := validateCmd()
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs(args)
			err := cmd.Execute()
			if err == nil || exitCodeForError(err) != exitCodeValidationFailed {
				t.Fatalf("err = %v (exit %d), want a validation failure (exit %d)", err, exitCodeForError(err), exitCodeValidationFailed)
			}
			terminal := stderr.String() + "Error: " + err.Error() + "\n"
			if got := strings.Count(terminal, `unknown key "unknown_field"`); got != 1 {
				t.Errorf("the problem is said %d times, want once:\n%s", got, terminal)
			}
			if !strings.Contains(terminal, invalid) || !strings.Contains(terminal, "plan validation failed") {
				t.Errorf("the output must name the plan and say that validation failed:\n%s", terminal)
			}
			if stdout.Len() != 0 {
				t.Errorf("standard output = %q, want none", stdout.String())
			}
		})
	}
}

// Several plans: each invalid one is listed once, and the closing error counts
// them, as before.
func TestValidateOfSeveralPlansListsEachProblemOnce(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.yaml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("version: v1\nunknown_field: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := validateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var stderr bytes.Buffer
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{dir})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "2 of 2 plans are invalid") || exitCodeForError(err) != exitCodeValidationFailed {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Count(stderr.String(), `unknown key "unknown_field"`); got != 2 {
		t.Errorf("the problem is listed %d times, want once per plan:\n%s", got, stderr.String())
	}
}
