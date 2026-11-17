// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
)

// A plan that carries `frameworks: []` does not load. verify-report loads
// --expect-plan the way a node worker does, so it refuses such a plan before it
// judges any report, with the validation error and exit status 2. A copy of
// that plan with a framework filled in binds the VMs and probes of a report of
// schema 1.5, which carries no plan_sha256 (the verdict says the digest is NOT
// BOUND); a report of schema 1.6 needs the exact file that ran. docs/reports.md
// describes the plan loading and the NOT BOUND digest.
func TestExpectPlanRefusesAPlanWithEmptyFrameworks(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	trusted := hex.EncodeToString(public)
	dir := t.TempDir()
	plan := mustLoadFixturePlan()

	original, err := os.ReadFile(fixturePlanPath)
	if err != nil {
		t.Fatal(err)
	}
	const frameworks = "  frameworks:\n    - \"DORA-Article-12\"\n    - \"SOC2-Type2-CC7.4\"\n"
	if !strings.Contains(string(original), frameworks) {
		t.Fatal("the fixture plan's frameworks are not laid out as this test expects")
	}
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	earlierPlan := write("empty-frameworks.yaml", strings.Replace(string(original), frameworks, "  frameworks: []\n", 1))
	filledIn := write("filled-in.yaml", strings.Replace(string(original), frameworks, "  frameworks: [\"DORA-Article-12\"]\n", 1))

	// A report of schema 1.5: no plan_sha256.
	earlierReport := passReport(plan)
	earlierReport.ReportSchemaVersion, earlierReport.PlanSHA256, earlierReport.WorkerSHA256, earlierReport.RunID = "1.5", "", "", ""
	earlierPath := writeSignedFixture(t, dir, earlierReport, private)

	// A plan with no framework is refused before the report is judged.
	output, err := runVerifyReport("--format", "json", "--trusted-key", trusted, "--expect-plan", earlierPlan, earlierPath)
	if err == nil || !strings.Contains(err.Error(), "load --expect-plan") || !strings.Contains(err.Error(), "compliance.frameworks") {
		t.Fatalf("a plan with frameworks: []: err = %v, output %q; want it refused for compliance.frameworks", err, output)
	}
	if code := exitCodeForError(err); code != exitCodeInfrastructure {
		t.Errorf("exit status %d, want %d", code, exitCodeInfrastructure)
	}
	if output != "" {
		t.Errorf("a verdict was printed for a plan that did not load: %q", output)
	}

	// The same plan with a framework filled in binds the schema 1.5 report's VMs
	// and probes, and the verdict says the digest was not bound.
	output, err = runVerifyReport("--format", "json", "--trusted-key", trusted, "--expect-plan", filledIn, earlierPath)
	var summary reportVerificationSummary
	if decodeErr := json.Unmarshal([]byte(output), &summary); decodeErr != nil || err != nil || summary.Acceptance.Verdict != accept.Accepted {
		t.Fatalf("the filled-in copy against a schema 1.5 report: err=%v decode=%v acceptance=%+v", err, decodeErr, summary.Acceptance)
	}
	if bindings := strings.Join(summary.Acceptance.Bindings, "\n"); !strings.Contains(bindings, "NOT BOUND: plan digest") {
		t.Errorf("the verdict does not say the plan digest was not bound: %q", bindings)
	}

	// A report that carries plan_sha256 is bound to the file that ran, so the
	// edited copy is not enough for it.
	current := writeSignedFixture(t, dir, passReport(plan), private)
	output, err = runVerifyReport("--format", "json", "--trusted-key", trusted, "--expect-plan", filledIn, current)
	if decodeErr := json.Unmarshal([]byte(output), &summary); decodeErr != nil || err == nil || summary.Acceptance.Verdict != accept.Rejected ||
		!strings.Contains(strings.Join(summary.Acceptance.Reasons, "\n"), "the report is for a plan file with SHA-256") {
		t.Fatalf("the filled-in copy against a schema 1.6 report: err=%v decode=%v acceptance=%+v", err, decodeErr, summary.Acceptance)
	}
}
