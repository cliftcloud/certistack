// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/json"
	"strings"
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
)

// An unsigned report is a file anyone can write, so its acceptance verdict says
// what it rests on: "accepted on its contents only" in the text, and
// "authenticated": false in the JSON verdict a script decides on. A verified
// signature says true. The exit codes are the same either way.

func TestAnUnsignedReportsAcceptanceSaysItRestsOnItsContentsOnly(t *testing.T) {
	m := newUnsignedMatrix(t)
	args := append(append([]string{"--unsigned", "--expect-outcome", "pass"}, expectArgsForFixture...), m.unsigned)
	stdout, _, err := runVerifyStreams(args...)
	if err != nil {
		t.Fatalf("an unsigned passing report was not accepted: %v\n%s", err, stdout)
	}
	const line = "Acceptance:  ACCEPTED on its contents only (UNSIGNED: the run's own claim, not authenticated evidence)"
	if !strings.Contains(stdout, line) {
		t.Errorf("the output lacks %q:\n%s", line, stdout)
	}
	if strings.Contains(stdout, "ACCEPTED as pass evidence") {
		t.Errorf("an unsigned report reads as accepted pass evidence:\n%s", stdout)
	}
	// What it was checked against is on the line below.
	if !strings.Contains(stdout, "judged as pass evidence") {
		t.Errorf("the output does not say what the contents were judged against:\n%s", stdout)
	}

	// A rejection says the same about what it rests on.
	rejected := fixtureReport(mustLoadFixturePlan(), reportFixture{mode: accept.OutcomePass})
	rejected.VMRecords = nil
	path := writeReportFile(t, m.dir, rejected)
	stdout, _, _ = runVerifyStreams("--unsigned", path)
	if !strings.Contains(stdout, "REJECTED on its contents only (UNSIGNED: the run's own claim, not authenticated evidence)") {
		t.Errorf("the rejection of an unsigned report:\n%s", stdout)
	}
}

func TestASignedReportsAcceptanceIsAuthenticated(t *testing.T) {
	m := newUnsignedMatrix(t)
	args := append(append([]string{"--keyring", m.keyring, "--expect-outcome", "pass"}, expectArgsForFixture...), m.signed)
	stdout, _, err := runVerifyStreams(args...)
	if err != nil {
		t.Fatalf("a signed passing report was not accepted: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Acceptance:  ACCEPTED as pass evidence") || strings.Contains(stdout, "UNSIGNED") {
		t.Errorf("a signed report's acceptance changed:\n%s", stdout)
	}
}

func TestTheAcceptanceObjectSaysWhetherTheReportWasAuthenticated(t *testing.T) {
	m := newUnsignedMatrix(t)
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"unsigned", append(append([]string{"--unsigned", "--format", "json", "--expect-outcome", "pass"}, expectArgsForFixture...), m.unsigned), false},
		{"signed and trusted", append(append([]string{"--keyring", m.keyring, "--format", "json", "--expect-outcome", "pass"}, expectArgsForFixture...), m.signed), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, err := runVerifyStreams(tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			var summary struct {
				Acceptance map[string]json.RawMessage `json:"acceptance"`
			}
			if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
				t.Fatal(err)
			}
			raw, present := summary.Acceptance["authenticated"]
			if !present {
				t.Fatalf("the acceptance object has no authenticated member:\n%s", stdout)
			}
			if string(raw) != map[bool]string{true: "true", false: "false"}[tc.want] {
				t.Errorf("authenticated = %s, want %v", raw, tc.want)
			}
			// Scripts match the start of the object; the authenticated member is
			// the last, so it does not change what they match.
			if !strings.Contains(stdout, `"acceptance":{"verdict":"accepted"`) {
				t.Errorf("the start of the acceptance object changed:\n%s", stdout)
			}
		})
	}
}

// report show with a keyring judges a verified signature: its acceptance is
// authenticated too.
func TestReportShowWithAKeyringCallsItsAcceptanceAuthenticated(t *testing.T) {
	m := newUnsignedMatrix(t)
	stdout, _, err := runReportCommand(t, "report", "show", "--json", "--keyring", m.keyring, m.signed)
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		Acceptance struct {
			Authenticated *bool `json:"authenticated"`
		}
	}
	if err := json.Unmarshal([]byte(stdout), &view); err != nil {
		t.Fatal(err)
	}
	if view.Acceptance.Authenticated == nil || !*view.Acceptance.Authenticated {
		t.Errorf("the acceptance of a verified report in report show: authenticated = %v", view.Acceptance.Authenticated)
	}
}
