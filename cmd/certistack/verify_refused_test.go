// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
)

// Verify-report takes one file and does no discovery, and the file the
// controller keeps for a refused worker result is refused by name. The worst
// case is a kept result whose bytes are a complete report with a valid
// signature from a trusted signer: the banner in front of them keeps it from
// being read as one, under every flag.
func TestVerifyReportRefusesAKeptRefusedResult(t *testing.T) {
	plan := mustLoadFixturePlan()
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	trusted := hex.EncodeToString(public)
	out := t.TempDir()
	planDir := filepath.Join(out, plan.PlanID)
	if err := os.MkdirAll(planDir, 0o700); err != nil {
		t.Fatal(err)
	}
	reportPath := writeSignedFixture(t, planDir, fixtureReport(plan, reportFixture{mode: accept.OutcomePass}), private)
	signed, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	// The control: the signed report in the report directory is accepted.
	if output, err := runVerifyReport("--format", "json", "--trusted-key", trusted, "--expect-outcome", "pass", reportPath); err != nil || !strings.Contains(output, `"verdict":"accepted"`) {
		t.Fatalf("the control report was not accepted: err=%v output=%q", err, output)
	}

	keptPath, err := attest.SaveRefusedResult(out, "run-6f1a0c52-3a0e-4d6b-9d58-7a2b6c1f9e10", "the report names node \"x\"", signed)
	if err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no flag":             {},
		"json":                {"--format", "json"},
		"an expected outcome": {"--expect-outcome", "pass"},
		"test mode allowed":   {"--allow-test-mode"},
		"the plan":            {"--expect-plan", fixturePlanPath},
	} {
		t.Run(name, func(t *testing.T) {
			output, err := runVerifyReport(append(append([]string{"--trusted-key", trusted}, args...), keptPath)...)
			if err == nil {
				t.Fatalf("verify-report accepted the kept result: %q", output)
			}
			if code := exitCodeForError(err); code == 0 {
				t.Errorf("exit status %d for a kept refused result", code)
			}
			for _, bad := range []string{`"verdict":"accepted"`, "Acceptance:  ACCEPTED", `"signature_valid":true`, "Signature:   VALID"} {
				if strings.Contains(output, bad) {
					t.Errorf("verify-report printed %q for a kept refused result:\n%s", bad, output)
				}
			}
			if !strings.Contains(err.Error(), "report") {
				t.Errorf("the refusal does not say it is about the report: %v", err)
			}
		})
	}

	// verify-report does no discovery: handed the report directory, or the
	// directory of the kept results, it refuses them as it refuses any
	// directory, and reads nothing in them.
	for _, dir := range []string{out, filepath.Dir(keptPath), planDir} {
		if output, err := runVerifyReport("--trusted-key", trusted, dir); err == nil {
			t.Errorf("verify-report accepted the directory %s: %q", dir, output)
		}
	}
}
