// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
)

// The signature_timestamp of a report is carried beside the signature and is
// not signed. verify-report says what it amounts to on a "Sig timestamp" line
// and in the JSON summary: none, a stub (a test token anyone can forge, NOT
// evidence), a token this build cannot verify, or one a configured verifier
// accepted. A timestamp never rescues a bad signature and never counts when it
// does not cover the signature.

var stampClock = func() time.Time { return time.Date(2026, 10, 2, 12, 30, 0, 0, time.UTC) }

type stampedVerifyFixture struct {
	path    string
	trusted string
	key     ed25519.PrivateKey
}

// writeStampedReport signs the reporter fixture report, asks ts for a timestamp
// (nil attaches none) and saves it.
func writeStampedReport(t *testing.T, ts attest.Timestamper) stampedVerifyFixture {
	t.Helper()
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := auditFailedReport()
	if err := attesttest.SignReport(report, private); err != nil {
		t.Fatal(err)
	}
	if ts != nil {
		if err := report.AttachTimestamp(context.Background(), ts); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return stampedVerifyFixture{path: path, trusted: hex.EncodeToString(public), key: private}
}

func (f stampedVerifyFixture) run(t *testing.T, format string) (string, error) {
	t.Helper()
	return runVerifyReport("--format", format, "--trusted-key", f.trusted, f.path)
}

// edit rewrites a member of the saved report document.
func (f stampedVerifyFixture) edit(t *testing.T, member string, value interface{}) {
	t.Helper()
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatal(err)
	}
	if value == nil {
		delete(members, member)
	} else if members[member], err = json.Marshal(value); err != nil {
		t.Fatal(err)
	}
	if data, err = json.Marshal(members); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func timestampSummary(t *testing.T, output string) map[string]any {
	t.Helper()
	var summary map[string]any
	if err := json.Unmarshal([]byte(output), &summary); err != nil {
		t.Fatalf("verify-report JSON: %v\n%s", err, output)
	}
	member, ok := summary["signature_timestamp"].(map[string]any)
	if !ok {
		t.Fatalf("the summary has no signature_timestamp object:\n%s", output)
	}
	return member
}

func TestVerifyReportTimestamp_NoneIsStatedAndChangesNothingElse(t *testing.T) {
	fixture := writeStampedReport(t, nil)

	text, err := fixture.run(t, "text")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "  Sig timestamp: none\n") {
		t.Errorf("the text lacks the none line:\n%s", text)
	}

	output, err := fixture.run(t, "json")
	if err != nil {
		t.Fatal(err)
	}
	member := timestampSummary(t, output)
	if member["status"] != "none" || member["evidence"] != false {
		t.Errorf("signature_timestamp = %v, want status none and evidence false", member)
	}
	for _, name := range []string{"authority", "claimed_time", "verified_time", "note"} {
		if _, present := member[name]; present {
			t.Errorf("a report with no timestamp has signature_timestamp.%s", name)
		}
	}
}

func TestVerifyReportTimestamp_StubIsReportedAsNotEvidence(t *testing.T) {
	fixture := writeStampedReport(t, attest.StubTimestamper{Now: stampClock})

	text, err := fixture.run(t, "text")
	if err != nil {
		t.Fatalf("a stub-timestamped report must verify: %v", err)
	}
	if !strings.Contains(text, "Sig timestamp: stub timestamp, NOT evidence") {
		t.Errorf("the text lacks the stub line:\n%s", text)
	}
	if strings.Contains(text, "verified at") {
		t.Errorf("the text calls a stub verified:\n%s", text)
	}
	if !strings.Contains(text, "✓ Audit Certificate Signature VALID") {
		t.Errorf("the signature is not reported valid:\n%s", text)
	}

	output, err := fixture.run(t, "json")
	if err != nil {
		t.Fatal(err)
	}
	member := timestampSummary(t, output)
	if member["status"] != "stub" || member["evidence"] != false || member["authority"] != attest.StubTimestampAuthority {
		t.Errorf("signature_timestamp = %v, want status stub, evidence false, the stub authority", member)
	}
	if _, present := member["verified_time"]; present {
		t.Errorf("a stub has a verified_time: %v", member)
	}
	if note, _ := member["note"].(string); !strings.Contains(note, "NOT evidence") {
		t.Errorf("the note %q does not say NOT evidence", note)
	}

	// Even a build whose configured verifier would take the stub's token never
	// reports it as evidence.
	t.Cleanup(func(old func() []attest.TimestampVerifier) func() {
		return func() { configuredTimestampVerifiers = old }
	}(configuredTimestampVerifiers))
	configuredTimestampVerifiers = func() []attest.TimestampVerifier { return []attest.TimestampVerifier{attest.StubVerifier{}} }
	output, err = fixture.run(t, "json")
	if err != nil {
		t.Fatal(err)
	}
	if member := timestampSummary(t, output); member["status"] != "stub" || member["evidence"] != false {
		t.Errorf("with the stub verifier configured, signature_timestamp = %v", member)
	}
}

type acceptingVerifier struct{ authority string }

func (v acceptingVerifier) VerifyTimestamp(token attest.TimestampToken, digest [32]byte) (time.Time, error) {
	if token.Authority != v.authority {
		return time.Time{}, attest.ErrTimestampAuthorityUnknown
	}
	return time.Date(2026, 10, 2, 9, 0, 1, 0, time.UTC), nil
}

type refusingVerifier struct{}

func (refusingVerifier) VerifyTimestamp(attest.TimestampToken, [32]byte) (time.Time, error) {
	return time.Time{}, errors.New("the token's certificate chain is not trusted")
}

// foreignTimestamp is a well-formed token of an authority Community does not
// know, which is what a hosted service's token will look like to it.
type foreignTimestamper struct{}

func (foreignTimestamper) Timestamp(_ context.Context, digest [32]byte) (attest.TimestampToken, error) {
	return attest.TimestampToken{Authority: "tsa.example.invalid", Time: "2026-10-02T09:00:00Z", Token: "AQID", HashAlgorithm: "sha256"}, nil
}

func TestVerifyReportTimestamp_ForeignTokenIsPresentButNotVerifiedWithoutAVerifier(t *testing.T) {
	fixture := writeStampedReport(t, foreignTimestamper{})

	text, err := fixture.run(t, "text")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Sig timestamp: present, not verified") || !strings.Contains(text, "tsa.example.invalid") {
		t.Errorf("the text lacks the not-verified line:\n%s", text)
	}
	member := timestampSummary(t, mustRun(t, fixture, "json"))
	if member["status"] != "unverified" || member["evidence"] != false {
		t.Errorf("signature_timestamp = %v, want status unverified and no evidence", member)
	}
}

func mustRun(t *testing.T, f stampedVerifyFixture, format string) string {
	t.Helper()
	output, err := f.run(t, format)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func TestVerifyReportTimestamp_VerifiedOnlyWhenAConfiguredVerifierAccepts(t *testing.T) {
	fixture := writeStampedReport(t, foreignTimestamper{})
	t.Cleanup(func(old func() []attest.TimestampVerifier) func() {
		return func() { configuredTimestampVerifiers = old }
	}(configuredTimestampVerifiers))

	configuredTimestampVerifiers = func() []attest.TimestampVerifier {
		return []attest.TimestampVerifier{acceptingVerifier{authority: "tsa.example.invalid"}}
	}
	text := mustRun(t, fixture, "text")
	if !strings.Contains(text, "Sig timestamp: verified at 2026-10-02T09:00:01Z by tsa.example.invalid\n") {
		t.Errorf("the text lacks the verified line:\n%s", text)
	}
	member := timestampSummary(t, mustRun(t, fixture, "json"))
	if member["status"] != "verified" || member["evidence"] != true || member["verified_time"] != "2026-10-02T09:00:01Z" {
		t.Errorf("signature_timestamp = %v, want verified with its time", member)
	}

	// A verifier that refuses the token makes the report a refusal.
	configuredTimestampVerifiers = func() []attest.TimestampVerifier { return []attest.TimestampVerifier{refusingVerifier{}} }
	_, err := fixture.run(t, "text")
	if err == nil || !strings.Contains(err.Error(), "timestamp beside it is refused") || !strings.Contains(err.Error(), "certificate chain is not trusted") {
		t.Errorf("a refusing verifier: err = %v", err)
	}
}

func TestVerifyReportTimestamp_TokenOverAnotherSignatureIsRefused(t *testing.T) {
	a := writeStampedReport(t, attest.StubTimestamper{Now: stampClock})
	b := writeStampedReport(t, nil)

	// Take a's timestamp member into b's document.
	dataA, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	var membersA map[string]json.RawMessage
	if err := json.Unmarshal(dataA, &membersA); err != nil {
		t.Fatal(err)
	}
	var token any
	if err := json.Unmarshal(membersA[attest.TimestampMember], &token); err != nil {
		t.Fatal(err)
	}
	b.edit(t, attest.TimestampMember, token)

	_, err = b.run(t, "text")
	if err == nil || !strings.Contains(err.Error(), "does not cover this signature") {
		t.Fatalf("verify-report accepted another signature's stub token: err = %v", err)
	}
}

func TestVerifyReportTimestamp_ABadSignatureIsNotRescuedByATimestamp(t *testing.T) {
	fixture := writeStampedReport(t, attest.StubTimestamper{Now: stampClock})
	fixture.edit(t, "plan_id", "someone-elses-plan")

	_, err := fixture.run(t, "text")
	if err == nil || !strings.Contains(err.Error(), "cryptographic signature mismatch") {
		t.Fatalf("a tampered report with a stub timestamp: err = %v, want the signature mismatch", err)
	}
}

func TestVerifyReportTimestamp_MalformedMemberAndUnknownHashAreRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		value any
		want  string
	}{
		"not an object":  {"yesterday", "must be an object"},
		"unknown hash":   {map[string]string{"authority": "x", "time": "2026-10-02T09:00:00Z", "token": "AQID", "hash_algorithm": "sha1"}, "hash_algorithm"},
		"bad time":       {map[string]string{"authority": "x", "time": "soon", "token": "AQID", "hash_algorithm": "sha256"}, "RFC 3339"},
		"missing member": {map[string]string{"authority": "x", "time": "2026-10-02T09:00:00Z", "hash_algorithm": "sha256"}, "missing token"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := writeStampedReport(t, nil)
			fixture.edit(t, attest.TimestampMember, tc.value)
			_, err := fixture.run(t, "text")
			if err == nil || !strings.Contains(err.Error(), attest.TimestampMember) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want a refusal naming %s and %q", err, attest.TimestampMember, tc.want)
			}
		})
	}
}
