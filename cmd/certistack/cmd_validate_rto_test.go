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

// The CLI called a plan with an explicit rto_target_seconds of 0 valid,
// and the run then enforced no objective. validate refuses it now, and names
// the field; a positive or fractional objective, or none, is valid.
func TestValidateCmdHoldsTheRTOObjectiveToTheRulesOfTheLoaders(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, line string
		valid      bool
	}{
		{"omitted", "", true},
		{"positive", "  rto_target_seconds: 30\n", true},
		{"fractional", "  rto_target_seconds: 0.5\n", true},
		{"zero", "  rto_target_seconds: 0\n", false},
		{"negative", "  rto_target_seconds: -1\n", false},
		{"fractional negative", "  rto_target_seconds: -0.5\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := strings.Replace(string(fixture), "compliance:\n", "compliance:\n"+tc.line, 1)
			if !strings.Contains(plan, tc.line) {
				t.Fatal("test bug: the fixture has no compliance block")
			}
			path := filepath.Join(t.TempDir(), "plan.yaml")
			if err := os.WriteFile(path, []byte(plan), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := validateCmd()
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs([]string{path})
			err := cmd.Execute()
			switch {
			case tc.valid && err != nil:
				t.Errorf("validate refused rto_target_seconds %q: %v (%s)", strings.TrimSpace(tc.line), err, stderr.String())
			case !tc.valid && err == nil:
				t.Errorf("validate accepted rto_target_seconds %q, which no run would enforce", strings.TrimSpace(tc.line))
			case !tc.valid && !strings.Contains(stderr.String()+err.Error(), "compliance.rto_target_seconds"):
				t.Errorf("validate refused the plan without naming the field: %v %s", err, stderr.String())
			}
		})
	}
}
