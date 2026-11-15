// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
)

// signedModeReport writes a passing report, signed by key, whose
// validation_mode is mode, or which has no such member when omit is set. The
// mutation is made before the signature, so each report is genuinely signed
// by a trusted key: the verifier must judge the mode, not the signature.
func signedModeReport(t *testing.T, dir, name string, key ed25519.PrivateKey, mode string, omit bool) string {
	t.Helper()
	report := campaignFixtureReport(mustLoadFixturePlan(), campaignFixture{mode: accept.OutcomePass})
	report.ValidationMode = mode
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	for _, unsigned := range []string{"signature", "public_key", "signer_fingerprint"} {
		delete(members, unsigned)
	}
	if omit {
		delete(members, "validation_mode")
	}
	payload, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := attest.CanonicalizeReportJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	public := key.Public().(ed25519.PublicKey)
	for member, value := range map[string]string{
		"signature":          attesttest.SignCanonical(canonical, key),
		"public_key":         hex.EncodeToString(public),
		"signer_fingerprint": attest.Fingerprint(public),
	} {
		encoded, _ := json.Marshal(value)
		members[member] = encoded
	}
	signed, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The validation mode is an allowlist. The verifier refused the one
// literal test_skip_integrity and read an empty, a missing, another-case or
// a future-spelled mode as a pass, exiting 0 with all_passed=true when no
// --expect-* flag was given. Every mode but full_integrity (and
// test_skip_integrity under --allow-test-mode) is now refused at exit status
// 2, in text and in JSON, with and without an expectation and with and
// without the test-mode override, and all_passed is false in what is written.
func TestVerifyReportRefusesUnsupportedValidationModes(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	trusted := hex.EncodeToString(public)

	type variant struct {
		name string
		mode string
		omit bool
	}
	unsupported := []variant{
		{name: "omitted", omit: true},
		{name: "empty", mode: ""},
		{name: "blank", mode: " "},
		{name: "trailing space", mode: "full_integrity "},
		{name: "leading space", mode: " full_integrity"},
		{name: "upper case full", mode: "FULL_INTEGRITY"},
		{name: "mixed case full", mode: "Full_Integrity"},
		{name: "hyphenated", mode: "full-integrity"},
		{name: "upper case test", mode: "TEST_SKIP_INTEGRITY"},
		{name: "test with a version", mode: "test_skip_integrity_v2"},
		{name: "test with a line break", mode: "test_skip_integrity\n"},
		{name: "full with a hidden bidi control", mode: "full\u202e_integrity"},
		{name: "future spelling", mode: "full_integrity_v2"},
		{name: "legacy word", mode: "legacy_unspecified"},
	}
	flagSets := map[string][]string{
		"no flags":                  nil,
		"test mode allowed":         {"--allow-test-mode"},
		"an expectation":            {"--expect-outcome", "pass"},
		"expectation and override":  {"--allow-test-mode", "--expect-outcome", "pass"},
		"expect the full mode":      {"--expect-validation-mode", attest.ValidationModeFullIntegrity},
		"expect full, test allowed": {"--allow-test-mode", "--expect-validation-mode", attest.ValidationModeFullIntegrity},
	}
	for _, v := range unsupported {
		path := signedModeReport(t, dir, strings.ReplaceAll(v.name, " ", "-"), private, v.mode, v.omit)
		for flagName, flags := range flagSets {
			for _, format := range []string{"json", "text"} {
				label := fmt.Sprintf("%s / %s / %s", v.name, flagName, format)
				args := append(append([]string{"--format", format, "--trusted-key", trusted}, flags...), path)
				output, err := runVerifyReport(args...)
				if err == nil || exitCodeForError(err) != exitCodeInfrastructure {
					t.Errorf("%s: err=%v (exit %d); want a refusal at status 2\n%s", label, err, exitCodeForError(err), output)
					continue
				}
				if !strings.Contains(err.Error(), "unsupported validation mode") {
					t.Errorf("%s: the refusal does not name the mode: %v", label, err)
				}
				switch format {
				case "json":
					var summary reportVerificationSummary
					if decodeErr := json.Unmarshal([]byte(output), &summary); decodeErr != nil {
						t.Errorf("%s: no JSON summary to read: %v; output=%q", label, decodeErr, output)
						continue
					}
					if summary.AllPassed {
						t.Errorf("%s: the summary of a report with an unsupported mode says all_passed=true", label)
					}
					if summary.Acceptance.Verdict != accept.Rejected {
						t.Errorf("%s: acceptance = %+v, want rejected", label, summary.Acceptance)
					}
				case "text":
					if !strings.Contains(output, "All Passed:  false") || !strings.Contains(output, "not a supported mode") {
						t.Errorf("%s: the text does not say the mode is unsupported and all_passed is false:\n%s", label, output)
					}
				}
			}
		}
	}

	// The two supported modes keep working, and the test mode still needs its
	// override.
	full := signedModeReport(t, dir, "full", private, attest.ValidationModeFullIntegrity, false)
	for _, format := range []string{"json", "text"} {
		if output, err := runVerifyReport("--format", format, "--trusted-key", trusted, full); err != nil {
			t.Errorf("full_integrity as %s: %v\n%s", format, err, output)
		}
		if output, err := runVerifyReport("--format", format, "--trusted-key", trusted, "--expect-outcome", "pass", "--expect-validation-mode", attest.ValidationModeFullIntegrity, full); err != nil {
			t.Errorf("full_integrity as %s with expectations: %v\n%s", format, err, output)
		}
	}
	testMode := signedModeReport(t, dir, "test", private, attest.ValidationModeTestSkipIntegrity, false)
	if _, err := runVerifyReport("--format", "json", "--trusted-key", trusted, testMode); err == nil || exitCodeForError(err) != exitCodeInfrastructure || !strings.Contains(err.Error(), "--allow-test-mode") {
		t.Errorf("test_skip_integrity without the override: %v", err)
	}
	if _, err := runVerifyReport("--format", "json", "--trusted-key", trusted, "--allow-test-mode", testMode); err != nil {
		t.Errorf("test_skip_integrity with the override: %v", err)
	}
}

// sanitizeVerifyText drops every bidi control. The verifier printed
// the twelve code points of the Unicode Bidi_Control property from a signed
// report's text fields, where a paired RLO and PDF reverse what sits between
// them on a terminal that honours them. Text in a right-to-left script is
// not a control character and stays.
func TestSanitizeVerifyTextDropsEveryBidiControl(t *testing.T) {
	var controls []rune
	for _, r16 := range unicode.Bidi_Control.R16 {
		for r := rune(r16.Lo); r <= rune(r16.Hi); r += rune(r16.Stride) {
			controls = append(controls, r)
		}
	}
	for _, r32 := range unicode.Bidi_Control.R32 {
		for r := rune(r32.Lo); r <= rune(r32.Hi); r += rune(r32.Stride) {
			controls = append(controls, r)
		}
	}
	if len(controls) != 12 {
		t.Fatalf("the Bidi_Control property has %d code points here, want the 12 the reporter names: %U", len(controls), controls)
	}
	for _, r := range controls {
		if got := sanitizeVerifyText("a" + string(r) + "b"); got != "ab" {
			t.Errorf("sanitizeVerifyText kept U+%04X: %q", r, got)
		}
	}
	if got := sanitizeVerifyText("PASSED \u202edesspaf\u202c done"); got != "PASSED desspaf done" {
		t.Errorf("paired RLO/PDF survived: %q", got)
	}
	// Invisible characters that hide text, and the line breaks that forge a line.
	for in, want := range map[string]string{
		"zero\u200bwidth\u200d\u2060joined\ufeff": "zerowidthjoined",
		"one\nTwo":                     "one; Two",
		"esc\x1b[31mred":               "esc[31mred",
		"no\u00a0break":                "no break",
		"שלום עולם":                    "שלום עולם",
		"مرحبا بالعالم":                "مرحبا بالعالم",
		"plain ASCII, 123 and ünïcödé": "plain ASCII, 123 and ünïcödé",
	} {
		if got := sanitizeVerifyText(in); got != want {
			t.Errorf("sanitizeVerifyText(%q) = %q, want %q", in, got, want)
		}
	}
}

// The same, through the command: a signed report that carries every
// bidi control in the fields verify-report prints does not reach the terminal
// with one, in a signer name and node from the keyring too.
func TestVerifyReportTextDropsBidiControlsFromEveryField(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	all := "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
	plan := mustLoadFixturePlan()
	report := campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomePass})
	report.PlanName = "name" + all + "end"
	report.NodeFQDN = "node" + all + ".example"
	report.Frameworks = []string{"SOC2" + all}
	report.EngineVersion = "v0" + all + ".1.0"
	report.GitCommit = "abc" + all + "def"
	report.TeardownEvidence.VerifiedAt = "2026" + all + "-09-29"
	dir := t.TempDir()
	path := writeSignedFixture(t, dir, report, private)
	keyring := filepath.Join(dir, "keyring.json")
	ring := fmt.Sprintf(`{"trusted_signers":[{"name":%q,"node":%q,"public_key":%q}]}`, "lab"+all+"signer", "pve"+all+"1", hex.EncodeToString(public))
	if err := os.WriteFile(keyring, []byte(ring), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, trust := range [][]string{{"--keyring", keyring}, {"--trusted-key", hex.EncodeToString(public)}} {
		output, err := runVerifyReport(append(trust, path)...)
		if err != nil {
			t.Fatalf("verify-report: %v", err)
		}
		for _, r := range output {
			if unicode.Is(unicode.Bidi_Control, r) || unicode.Is(unicode.Cf, r) {
				t.Fatalf("the text output carries U+%04X:\n%s", r, output)
			}
		}
		if !strings.Contains(output, "Plan Name:   nameend") || !strings.Contains(output, "Node:        node.example") {
			t.Fatalf("the text output lost the readable part of a field:\n%s", output)
		}
		if strings.Contains(trust[0], "keyring") && (!strings.Contains(output, `"labsigner"`) || !strings.Contains(output, "Signer Node: pve1")) {
			t.Fatalf("the keyring signer name and node are not shown clean:\n%s", output)
		}
	}
}

// Without an --expect-* flag a rejected report still exits 0, which
// is documented, but the command says so on standard error, so a script or a
// person that looks only at the exit status is told what it does not show.
// An expectation makes the exit status follow the verdict and the note goes.
func TestVerifyReportSaysWhenTheExitStatusIsNotTheVerdict(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	trusted := hex.EncodeToString(public)
	plan := mustLoadFixturePlan()
	rejected := writeSignedFixture(t, dir, campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.VMRecords = nil }}), private)
	accepted := writeSignedFixture(t, dir, campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomePass}), private)

	run := func(args ...string) (stdout, stderr string, err error) {
		cmd := verifyReportCmd()
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(args)
		err = cmd.Execute()
		return out.String(), errOut.String(), err
	}
	for _, format := range []string{"json", "text"} {
		_, stderr, err := run("--format", format, "--trusted-key", trusted, rejected)
		if err != nil {
			t.Fatalf("%s: a rejected report without an expectation changed its documented exit status: %v", format, err)
		}
		for _, want := range []string{"REJECTED as pass evidence", "exit status 0", "--expect-outcome pass"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("%s: the note lacks %q:\n%s", format, want, stderr)
			}
		}
		if _, stderr, err = run("--format", format, "--trusted-key", trusted, "--expect-outcome", "pass", rejected); err == nil || exitCodeForError(err) != exitCodeValidationFailed || strings.Contains(stderr, "note:") {
			t.Errorf("%s: with --expect-outcome the exit status must follow the verdict (err=%v) and the note must go (stderr %q)", format, err, stderr)
		}
		if _, stderr, err = run("--format", format, "--trusted-key", trusted, accepted); err != nil || stderr != "" {
			t.Errorf("%s: an accepted report must be silent on stderr: err=%v stderr=%q", format, err, stderr)
		}
	}
}
