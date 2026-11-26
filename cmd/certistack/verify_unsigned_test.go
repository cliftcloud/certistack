// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
)

// The Community Edition writes its reports unsigned and the Enterprise Edition
// signs them; verify-report judges both. These tests are the matrix of what it
// does with a report that carries no signature, and with one that does.

const unsignedTrustLine = "UNSIGNED: the contents are the run's own claim, not authenticated"

// writeReportFile writes a report as the Community Edition does, or as a signer
// leaves it, and returns its path.
func writeReportFile(t *testing.T, dir string, report *attest.Report) string {
	t.Helper()
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, report.ReportID+".json")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runVerifyStreams runs verify-report and returns both output streams.
func runVerifyStreams(args ...string) (stdout, stderr string, err error) {
	cmd := verifyReportCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errOut.String(), err
}

func exitOf(err error) int { return exitCodeForError(err) }

type unsignedMatrix struct {
	dir      string
	public   string // the trusted key, hex
	keyring  string
	unsigned string // a passing report as the Community Edition writes it
	signed   string // the same kind of report, signed
	stripped string // the signed report with its signature members removed
}

func newUnsignedMatrix(t *testing.T) unsignedMatrix {
	t.Helper()
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	plan := mustLoadFixturePlan()
	m := unsignedMatrix{dir: dir, public: hex.EncodeToString(public)}
	m.keyring = filepath.Join(dir, "trusted-signers.pub")
	if err := os.WriteFile(m.keyring, []byte(m.public+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.unsigned = writeReportFile(t, dir, fixtureReport(plan, reportFixture{mode: accept.OutcomePass}))
	signedReport := fixtureReport(plan, reportFixture{mode: accept.OutcomePass})
	if err := attesttest.SignReport(signedReport, private); err != nil {
		t.Fatal(err)
	}
	m.signed = writeReportFile(t, dir, signedReport)
	// The same report with every signature member taken away, as someone who
	// wanted a signed report to read as an unsigned one would leave it.
	strippedReport := *signedReport
	strippedReport.Signature, strippedReport.PublicKey, strippedReport.SignerFingerprint, strippedReport.SignatureTimestamp = "", "", "", nil
	strippedReport.ReportID = "00000000-0000-4000-8000-0000000000aa"
	m.stripped = writeReportFile(t, dir, &strippedReport)
	return m
}

var expectArgsForFixture = []string{"--expect-plan", fixturePlanPath, "--expect-node", fixtureNode, "--expect-version", fixtureVersion, "--expect-commit", fixtureCommit, "--expect-build-date", fixtureBuildDate}

// An unsigned report is refused by default, and the refusal says what to do if
// the report is expected to be unsigned. This is the fail-closed default: a
// signature that was taken off a report must never read as an accepted report.
func TestVerifyReportRefusesAnUnsignedReportByDefault(t *testing.T) {
	m := newUnsignedMatrix(t)
	for name, path := range map[string]string{"a report as the Community Edition writes it": m.unsigned, "a signed report with its signature stripped": m.stripped} {
		for _, trust := range [][]string{{"--keyring", m.keyring}, {"--public-key", m.keyring}, {"--trusted-key", m.public}} {
			stdout, _, err := runVerifyStreams(append(append([]string{"--format", "json", "--expect-outcome", "pass"}, trust...), path)...)
			if err == nil || exitOf(err) != exitCodeInfrastructure {
				t.Errorf("%s with %s: exit %d (%v), want the report refused with %d", name, trust[0], exitOf(err), err, exitCodeInfrastructure)
				continue
			}
			for _, want := range []string{"report is unsigned (no signature present)", "--unsigned"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s with %s: the refusal %q does not say %q", name, trust[0], err, want)
				}
			}
			if stdout != "" {
				t.Errorf("%s with %s: a refused report printed %q", name, trust[0], stdout)
			}
		}
	}
}

// --unsigned says the caller expects the report to be unsigned: the signature is
// not checked, the output says that the contents are the run's own claim, and the
// acceptance rules decide the exit status exactly as they do for a signed report.
func TestVerifyReportUnsignedJudgesTheReportByTheAcceptanceRules(t *testing.T) {
	m := newUnsignedMatrix(t)
	plan := mustLoadFixturePlan()

	// Accepted: exit 0, the trust line says UNSIGNED, and the verdict is printed.
	stdout, _, err := runVerifyStreams(append(append([]string{"--unsigned", "--expect-outcome", "pass"}, expectArgsForFixture...), m.unsigned)...)
	if err != nil {
		t.Fatalf("an unsigned passing report was not accepted: %v\n%s", err, stdout)
	}
	for _, want := range []string{"! Report NOT SIGNED (--unsigned)", "Trust Source: " + unsignedTrustLine, "Acceptance:  ACCEPTED on its contents only (UNSIGNED: the run's own claim, not authenticated evidence)", "judged as pass evidence", "All Passed:  true"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the output lacks %q:\n%s", want, stdout)
		}
	}
	for _, forbidden := range []string{"signature VALID", "Signer Identity", "TRUSTED", "Signer Key"} {
		if strings.Contains(stdout, forbidden) {
			t.Errorf("an unsigned report's output says %q:\n%s", forbidden, stdout)
		}
	}

	// The same through the JSON summary: the signature is not valid, and nothing
	// pretends otherwise.
	stdout, _, err = runVerifyStreams("--unsigned", "--format", "json", "--expect-outcome", "pass", m.unsigned)
	if err != nil {
		t.Fatal(err)
	}
	var summary reportVerificationSummary
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if summary.SignatureValid || !summary.Unsigned || summary.TrustSource != unsignedTrustLine || summary.Acceptance.Verdict != accept.Accepted {
		t.Errorf("the summary of an unsigned report = %+v", summary)
	}
	if summary.SignatureTimestamp.Status != "none" {
		t.Errorf("an unsigned report has a timestamp status %q", summary.SignatureTimestamp.Status)
	}

	// Rejected by an acceptance rule: exit 1, as for a signed report.
	for name, mutate := range map[string]func(*attest.Report){
		"no VM": func(r *attest.Report) { r.VMRecords = nil },
		"a failed probe": func(r *attest.Report) {
			r.VMRecords[0].ProbeResults[0].Passed = false
			r.VMRecords[0].AllPassed = false
		},
		"cleanup unproven": func(r *attest.Report) { r.TeardownEvidence.AllCleaned = false },
		"another node":     func(r *attest.Report) { r.NodeFQDN = "someone-elses-node" },
	} {
		report := fixtureReport(plan, reportFixture{mode: accept.OutcomePass})
		mutate(report)
		path := writeReportFile(t, m.dir, report)
		_, _, err := runVerifyStreams(append(append([]string{"--unsigned", "--format", "json", "--expect-outcome", "pass"}, expectArgsForFixture...), path)...)
		if err == nil || exitOf(err) != exitCodeValidationFailed {
			t.Errorf("%s: exit %d (%v), want the rejected report to exit %d", name, exitOf(err), err, exitCodeValidationFailed)
		}
	}

	// A fault drill is judged against its plan, as for a signed report.
	fault := writeReportFile(t, m.dir, fixtureReport(plan, reportFixture{mode: accept.OutcomeFault}))
	if _, _, err := runVerifyStreams(append(append([]string{"--unsigned", "--format", "json", "--expect-outcome", "fault"}, expectArgsForFixture...), fault)...); err != nil {
		t.Errorf("an unsigned fault drill report: %v", err)
	}

	// Test mode keeps its own gate: refused unless it is allowed, exit 2.
	testMode := writeReportFile(t, m.dir, fixtureReport(plan, reportFixture{mode: accept.OutcomePass, testMode: true}))
	if _, _, err := runVerifyStreams("--unsigned", "--format", "json", testMode); err == nil || exitOf(err) != exitCodeInfrastructure {
		t.Errorf("an unsigned test-mode report: exit %d (%v), want %d", exitOf(err), err, exitCodeInfrastructure)
	}
	if _, _, err := runVerifyStreams("--unsigned", "--format", "json", "--allow-test-mode", "--expect-outcome", "pass", testMode); err != nil {
		t.Errorf("an unsigned test-mode report with --allow-test-mode: %v", err)
	}
}

// Without an --expect-* flag the exit status says nothing about acceptance, for an
// unsigned report as for a signed one; a rejected verdict is told on standard error,
// and the note does not claim that a signature was valid.
func TestVerifyReportUnsignedWithoutExpectationsKeepsItsStatusAndSaysSo(t *testing.T) {
	m := newUnsignedMatrix(t)
	report := fixtureReport(mustLoadFixturePlan(), reportFixture{mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.VMRecords = nil }})
	path := writeReportFile(t, m.dir, report)
	stdout, stderr, err := runVerifyStreams("--unsigned", path)
	if err != nil {
		t.Fatalf("exit %d (%v), want 0: without an --expect-* flag the status says only that the report was read", exitOf(err), err)
	}
	if !strings.Contains(stdout, "Acceptance:  REJECTED on its contents only (UNSIGNED: the run's own claim, not authenticated evidence)") {
		t.Errorf("the verdict is not printed:\n%s", stdout)
	}
	if !strings.Contains(stderr, "REJECTED") || !strings.Contains(stderr, "--expect-outcome pass") || strings.Contains(stderr, "signature is valid") {
		t.Errorf("the note on standard error = %q", stderr)
	}
}

// --unsigned says there is nothing to trust, so naming something to trust is a
// contradiction and a usage error, before any file is read.
func TestVerifyReportUnsignedWithATrustSourceIsAUsageError(t *testing.T) {
	m := newUnsignedMatrix(t)
	missing := filepath.Join(m.dir, "not-there.json")
	for _, trust := range [][]string{{"--keyring", m.keyring}, {"--public-key", m.keyring}, {"--trusted-key", m.public}} {
		for _, path := range []string{m.unsigned, missing} {
			stdout, _, err := runVerifyStreams(append(append([]string{"--unsigned"}, trust...), path)...)
			if err == nil || exitOf(err) != exitCodeInfrastructure {
				t.Errorf("%s with --unsigned on %s: exit %d (%v), want a usage error with %d", trust[0], filepath.Base(path), exitOf(err), err, exitCodeInfrastructure)
				continue
			}
			if !strings.Contains(err.Error(), "--unsigned") || !strings.Contains(err.Error(), trust[0]) || !strings.Contains(err.Error(), "cannot be used together") {
				t.Errorf("%s with --unsigned: the message %q does not name both flags", trust[0], err)
			}
			if strings.Contains(err.Error(), "cannot read") || strings.Contains(err.Error(), "not-there") || stdout != "" {
				t.Errorf("%s with --unsigned: a file was read before the contradiction was told: %v", trust[0], err)
			}
		}
	}
}

// A report that carries a signature, valid or not, is not an unsigned report:
// --unsigned refuses it and says to verify it with a trust source.
func TestVerifyReportUnsignedRefusesAReportThatCarriesASignature(t *testing.T) {
	m := newUnsignedMatrix(t)
	signed, err := os.ReadFile(m.signed)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{"a signed report": signed}
	// Each signature member alone is enough to refuse the report.
	for _, member := range attest.UnsignedReportMembers() {
		var members map[string]json.RawMessage
		if err := json.Unmarshal(signed, &members); err != nil {
			t.Fatal(err)
		}
		for _, other := range attest.UnsignedReportMembers() {
			if other != member {
				delete(members, other)
			}
		}
		if member == attest.TimestampMember {
			members[member] = json.RawMessage(`{"authority":"x","time":"2026-10-08T00:00:00Z","token":"AAAA","hash_algorithm":"sha256"}`)
		}
		data, err := json.Marshal(members)
		if err != nil {
			t.Fatal(err)
		}
		cases["only the "+member+" member"] = data
	}
	for name, data := range cases {
		path := filepath.Join(m.dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		stdout, _, err := runVerifyStreams("--unsigned", "--format", "json", "--expect-outcome", "pass", path)
		if err == nil || exitOf(err) != exitCodeInfrastructure {
			t.Errorf("%s: exit %d (%v), want it refused with %d", name, exitOf(err), err, exitCodeInfrastructure)
			continue
		}
		if !strings.Contains(err.Error(), "carries a signature") || !strings.Contains(err.Error(), "--keyring") {
			t.Errorf("%s: the refusal %q does not say that the report is signed and how to verify it", name, err)
		}
		if stdout != "" {
			t.Errorf("%s: a refused report printed %q", name, stdout)
		}
	}
}

// The verifier of a signed report is untouched: it still verifies under the
// keyring, still refuses another signer, and a tampered report is still caught.
func TestVerifyReportStillVerifiesASignedReport(t *testing.T) {
	m := newUnsignedMatrix(t)
	stdout, _, err := runVerifyStreams(append(append([]string{"--keyring", m.keyring, "--format", "json", "--expect-outcome", "pass"}, expectArgsForFixture...), m.signed)...)
	if err != nil {
		t.Fatalf("a signed report did not verify: %v\n%s", err, stdout)
	}
	var summary reportVerificationSummary
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatal(err)
	}
	if !summary.SignatureValid || summary.Unsigned || !strings.HasPrefix(summary.TrustSource, "keyring:") || summary.Acceptance.Verdict != accept.Accepted {
		t.Errorf("the summary of a signed report = %+v", summary)
	}

	otherPublic, _, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := runVerifyStreams("--trusted-key", hex.EncodeToString(otherPublic), "--format", "json", m.signed); err == nil || exitOf(err) != exitCodeInfrastructure {
		t.Errorf("another signer: exit %d (%v), want %d", exitOf(err), err, exitCodeInfrastructure)
	}

	data, err := os.ReadFile(m.signed)
	if err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(m.dir, "tampered.json")
	if err := os.WriteFile(tampered, bytes.Replace(data, []byte(`"all_passed": true`), []byte(`"all_passed": false`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runVerifyStreams("--keyring", m.keyring, "--format", "json", tampered); err == nil || !strings.Contains(err.Error(), "signature mismatch") {
		t.Errorf("a tampered report: %v, want the signature mismatch", err)
	}
}

// A missing trust source is a usage error that names both ways to call the
// command: a trust source, or --unsigned.
func TestVerifyReportNeedsATrustSourceOrUnsigned(t *testing.T) {
	m := newUnsignedMatrix(t)
	_, _, err := runVerifyStreams(m.signed)
	if err == nil || exitOf(err) != exitCodeInfrastructure || !strings.Contains(err.Error(), "--keyring, --public-key, or --trusted-key is required") || !strings.Contains(err.Error(), "--unsigned") {
		t.Errorf("no trust source: exit %d (%v), want a usage error naming the three sources and --unsigned", exitOf(err), err)
	}
}

// report show reads both kinds of report. An unsigned one is shown for what it
// is, in the text and in the JSON view, and says how to judge it.
func TestReportShowSaysThatAnUnsignedReportIsUnsigned(t *testing.T) {
	m := newUnsignedMatrix(t)
	stdout, _, err := runReportCommand(t, "report", "show", m.unsigned)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Signature:     none: this report is unsigned (the Community Edition writes its reports unsigned): its contents are the run's own claim, not authenticated evidence.",
		"Judge it: certistack verify-report --unsigned --expect-outcome pass <report.json>",
		"Outcome:       PASS (as the file states)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("report show lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "signature NOT checked") || strings.Contains(stdout, "--keyring") {
		t.Errorf("report show treats an unsigned report as a signed one that was not checked:\n%s", stdout)
	}

	stdout, _, err = runReportCommand(t, "report", "show", "--json", m.unsigned)
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		Signature struct{ Status, Note string }
	}
	if err := json.Unmarshal([]byte(stdout), &view); err != nil {
		t.Fatal(err)
	}
	if view.Signature.Status != "unsigned" || !strings.Contains(view.Signature.Note, "unsigned") {
		t.Errorf("the JSON view's signature = %+v", view.Signature)
	}

	// A signed report shown without a keyring is still "not checked".
	stdout, _, err = runReportCommand(t, "report", "show", "--json", m.signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(stdout), &view); err != nil || view.Signature.Status != "not_checked" {
		t.Errorf("a signed report shown without a keyring: %+v (%v)", view.Signature, err)
	}

	// With a keyring an unsigned report is refused, as verify-report refuses it.
	if _, _, err := runReportCommand(t, "report", "show", "--keyring", m.keyring, m.unsigned); err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Errorf("report show --keyring of an unsigned report: %v", err)
	}
}
