// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"os"
	"strings"
	"testing"
)

// withCompliance is the small handwritten plan with its compliance block
// replaced by block, as the author's own YAML.
func withCompliance(block string) string {
	text := handwritten("level: 1", "vmid: 9001", "timeout_sec: 5")
	start := strings.Index(text, "compliance:")
	end := strings.Index(text, "admission_control:")
	return text[:start] + "compliance:\n" + block + "\n" + text[end:]
}

const signKeyLine = "  sign_key_path: /etc/certistack/keys/signing.ed25519\n"

// A plan that names no framework, by omitting the key, an empty list
// or a null, was valid and was signed into a report that mapped to nothing.
// Both loaders refuse it now, and a valid framework list still loads.
func TestAPlanMustNameAFramework(t *testing.T) {
	for name, block := range map[string]string{
		"key omitted":     "  retention_days: 90\n" + signKeyLine,
		"empty list":      "  frameworks: []\n  retention_days: 90\n" + signKeyLine,
		"null":            "  frameworks:\n  retention_days: 90\n" + signKeyLine,
		"only the stub":   "  frameworks: [CHANGE]\n  retention_days: 90\n" + signKeyLine,
		"unknown entry":   "  frameworks: [PCI]\n  retention_days: 90\n" + signKeyLine,
		"a good and stub": "  frameworks: [DORA, CHANGE]\n  retention_days: 90\n" + signKeyLine,
	} {
		_, err := loadText(t, withCompliance(block))
		if err == nil || !strings.Contains(validationText(err), "compliance.frameworks") {
			t.Errorf("%s: err %v, want compliance.frameworks refused", name, err)
		}
	}
	plan, err := loadText(t, withCompliance("  frameworks: [DORA, ISO27001-A8.13]\n  retention_days: 90\n"+signKeyLine))
	if err != nil || len(plan.Compliance.Frameworks) != 2 {
		t.Fatalf("a plan naming two frameworks: %v", err)
	}

	// A plan built in code is held to the same rule, by Validate and by the
	// check a run applies to a plan it is handed.
	for name, frameworks := range map[string][]string{"nil": nil, "empty": {}} {
		p := validPlan()
		p.Compliance.Frameworks = frameworks
		if !hasFieldError(Validate(p), "compliance.frameworks") || !hasFieldError(ValidateForWorker(p), "compliance.frameworks") || !hasFieldError(ComplianceErrors(p), "compliance.frameworks") {
			t.Errorf("%s frameworks: Validate %v, ComplianceErrors %v, want a refusal", name, Validate(p), ComplianceErrors(p))
		}
	}
}

// NONE is the label for an operator with no standard to name. It is valid on
// its own, in both loaders and for a plan built in code, and it is refused next
// to a standard, because the two say opposite things about the same report.
func TestTheNoStandardLabelStandsAlone(t *testing.T) {
	plan, err := loadText(t, withCompliance("  frameworks: [NONE]\n  retention_days: 90\n"+signKeyLine))
	if err != nil || len(plan.Compliance.Frameworks) != 1 || plan.Compliance.Frameworks[0] != FrameworkNone {
		t.Fatalf("a plan whose only framework is NONE: plan %v, err %v", plan, err)
	}
	for name, block := range map[string]string{
		"NONE then a standard": "  frameworks: [NONE, DORA]\n  retention_days: 90\n" + signKeyLine,
		"a standard then NONE": "  frameworks: [SOC2, NONE]\n  retention_days: 90\n" + signKeyLine,
	} {
		_, err := loadText(t, withCompliance(block))
		if err == nil || !strings.Contains(validationText(err), "cannot be listed together") {
			t.Errorf("%s: err %v, want NONE refused next to a standard, with the reason", name, err)
		}
	}
	p := validPlan()
	p.Compliance.Frameworks = []string{FrameworkNone}
	if errs := ComplianceErrors(p); len(errs) != 0 {
		t.Errorf("a plan built in code with [NONE]: %v, want none", errs)
	}
	p.Compliance.Frameworks = []string{FrameworkNone, "DORA"}
	if !hasFieldError(Validate(p), "compliance.frameworks[0]") {
		t.Errorf("a plan built in code with [NONE, DORA]: %v, want a refusal", Validate(p))
	}
}

// The placeholder an earlier certistack init wrote is refused with a message
// that says where it came from and what to put instead, not with the generic list.
func TestTheFrameworkPlaceholderExplainsItself(t *testing.T) {
	p := validPlan()
	p.Compliance.Frameworks = []string{FrameworkPlaceholder}
	errs := Validate(p)
	if len(errs) != 1 || errs[0].Field != "compliance.frameworks[0]" || !strings.Contains(errs[0].Message, "placeholder an earlier certistack init wrote") {
		t.Fatalf("errors %v, want the placeholder explained", errs)
	}
}

// A plan that omits retention_days or sets it to zero was valid and
// was signed with a retention of zero, indistinguishable from a choice. The
// reported cases, omission and an explicit zero, are refused by both loaders,
// as are a negative count and more than a century.
func TestAPlanMustSetAPositiveRetention(t *testing.T) {
	const frameworks = "  frameworks: [DORA]\n"
	for name, block := range map[string]string{
		"omitted":        frameworks + signKeyLine,
		"explicit zero":  frameworks + "  retention_days: 0\n" + signKeyLine,
		"null":           frameworks + "  retention_days:\n" + signKeyLine,
		"negative":       frameworks + "  retention_days: -1\n" + signKeyLine,
		"over a century": frameworks + "  retention_days: 36501\n" + signKeyLine,
	} {
		_, err := loadText(t, withCompliance(block))
		if err == nil || !strings.Contains(validationText(err), "compliance.retention_days") {
			t.Errorf("%s: err %v, want compliance.retention_days refused", name, err)
		}
	}
	for _, days := range []string{"1", "90", "2555", "36500"} {
		if _, err := loadText(t, withCompliance(frameworks+"  retention_days: "+days+"\n"+signKeyLine)); err != nil {
			t.Errorf("retention_days %s: %v", days, err)
		}
	}
	// The message for an omitted or zero value says what to set, and why.
	p := validPlan()
	p.Compliance.RetentionDays = 0
	errs := ComplianceErrors(p)
	if len(errs) != 1 || !strings.Contains(errs[0].Message, "from 1 to 36500") || !strings.Contains(errs[0].Message, "no retention") {
		t.Errorf("errors %v, want the zero explained", errs)
	}
}

// The reference calls both fields required, and this test fails if that stops
// being what validation does, or the reverse: each row that describes either
// field must say "required" exactly when a plan without it is refused.
func TestTheReferenceAgreesWithTheComplianceValidation(t *testing.T) {
	data, err := os.ReadFile("../../docs/plan-reference.md")
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string]bool{}
	noFrameworks := validPlan()
	noFrameworks.Compliance.Frameworks = nil
	refused["frameworks"] = hasFieldError(Validate(noFrameworks), "compliance.frameworks")
	noRetention := validPlan()
	noRetention.Compliance.RetentionDays = 0
	refused["retention_days"] = hasFieldError(Validate(noRetention), "compliance.retention_days")

	rows := 0
	for _, line := range strings.Split(string(data), "\n") {
		for field, refusesMissing := range refused {
			if !strings.HasPrefix(line, "| `"+field+"` |") {
				continue
			}
			rows++
			cells := strings.Split(line, "|")
			var statuses []string
			for _, cell := range cells {
				cell = strings.ToLower(strings.TrimSpace(cell))
				if cell == "yes" || cell == "no" || strings.HasPrefix(cell, "required") || strings.HasPrefix(cell, "optional") {
					statuses = append(statuses, cell)
				}
			}
			if len(statuses) != 1 {
				t.Errorf("cannot read the status of %s in: %s", field, line)
				continue
			}
			says := statuses[0] == "yes" || strings.HasPrefix(statuses[0], "required")
			if says != refusesMissing {
				t.Errorf("the reference says %s is %q but a plan without it is refused = %v: %s", field, statuses[0], refusesMissing, line)
			}
		}
	}
	if rows != 2 {
		t.Errorf("found %d rows for frameworks and retention_days in the reference, want 2 (one per-key table, two fields)", rows)
	}
}

// The Community Edition signs nothing, so the reason for a missing retention is
// that the report would record none, not that a signed report would (hardening
// F9, CR1-09).
func TestRetentionMessageDoesNotCallTheReportSigned(t *testing.T) {
	p := validPlan()
	p.Compliance.RetentionDays = 0
	errs := ComplianceErrors(p)
	if len(errs) != 1 {
		t.Fatalf("errors %v, want one", errs)
	}
	if strings.Contains(errs[0].Message, "signed") || !strings.Contains(errs[0].Message, "because the report would record no retention") {
		t.Errorf("message = %q", errs[0].Message)
	}
}
