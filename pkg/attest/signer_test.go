// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest_test

import (
	"bytes"
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
	"github.com/cliftcloud/certistack/pkg/config"
)

func unsignedTestReport() *attest.Report {
	return attest.BuildReport(&config.Plan{PlanID: "signer-hook"}, "node1", 3*time.Second, true, nil, "")
}

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

// signCanonicalForm is what an Enterprise signer does: sign the bytes
// CanonicalForm returns.
func signCanonicalForm(t *testing.T, report *attest.Report, private ed25519.PrivateKey) string {
	t.Helper()
	canonical, err := report.CanonicalForm()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(ed25519.Sign(private, canonical))
}

// A report the Community Edition writes is the same document without the
// signature members: nothing in the file says "signature", "public_key" or
// "signer_fingerprint", and report_schema_version is unchanged.
func TestAnUnsignedReportCarriesNoSignatureMembers(t *testing.T) {
	report := unsignedTestReport()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := report.Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatal(err)
	}
	for _, name := range attest.UnsignedReportMembers() {
		if _, present := members[name]; present {
			t.Errorf("the unsigned report has a %q member", name)
		}
	}
	if got := string(members["report_schema_version"]); got != `"`+attest.CurrentReportSchemaVersion+`"` {
		t.Errorf("report_schema_version = %s, want %q: leaving the signature out must not change the schema", got, attest.CurrentReportSchemaVersion)
	}
	// The verifier keeps refusing it unless the caller says it is expected to be unsigned.
	public, _ := testKeys(t)
	if _, _, err := attest.VerifyReport(data, []ed25519.PublicKey{public}); err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Errorf("VerifyReport of an unsigned report = %v, want it refused as unsigned", err)
	}
}

func TestCanonicalFormIsWhatTheVerifierChecksAndIgnoresTheSignatureMembers(t *testing.T) {
	report := unsignedTestReport()
	before, err := report.CanonicalForm()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := attest.CanonicalizeReportJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, fromJSON) {
		t.Fatalf("CanonicalForm differs from CanonicalizeReportJSON of the report:\n%s\n%s", before, fromJSON)
	}
	_, private := testKeys(t)
	if err := attesttest.SignReport(report, private); err != nil {
		t.Fatal(err)
	}
	after, err := report.CanonicalForm()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("signing the report changed its canonical form")
	}
	for _, member := range attest.UnsignedReportMembers() {
		if bytes.Contains(after, []byte(`"`+member+`"`)) {
			t.Errorf("the canonical form holds the unsigned member %q", member)
		}
	}
}

func TestAttachSignatureSetsTheSignatureMembersConsistentlyAndTheReportVerifies(t *testing.T) {
	public, private := testKeys(t)
	report := unsignedTestReport()
	report.SignatureTimestamp = &attest.TimestampToken{Authority: "stale", Token: "AAAA"}
	signature := signCanonicalForm(t, report, private)
	if err := report.AttachSignature(strings.ToUpper(signature), public); err != nil {
		t.Fatal(err)
	}
	if report.Signature != signature {
		t.Errorf("Signature = %q, want the lower-case spelling %q", report.Signature, signature)
	}
	if report.PublicKey != hex.EncodeToString(public) {
		t.Errorf("PublicKey = %q, want the key given", report.PublicKey)
	}
	if report.SignerFingerprint != attest.Fingerprint(public) {
		t.Errorf("SignerFingerprint = %q, want %q", report.SignerFingerprint, attest.Fingerprint(public))
	}
	if report.SignatureTimestamp != nil {
		t.Error("a timestamp that covered an earlier signature was kept")
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	verified, valid, err := attest.VerifyReport(data, []ed25519.PublicKey{public})
	if err != nil || !valid || verified.ReportID != report.ReportID {
		t.Fatalf("verify-report's verifier does not accept the signed report: valid=%v err=%v", valid, err)
	}
}

// What a faulty signer hands over is refused, and the report is left as it
// was: a signature that verify-report would refuse is never attached.
func TestAttachSignatureRefusesWhatDoesNotVerifyAndChangesNothing(t *testing.T) {
	public, private := testKeys(t)
	otherPublic, otherPrivate := testKeys(t)
	report := unsignedTestReport()
	good := signCanonicalForm(t, report, private)
	elsewhere := unsignedTestReport()
	elsewhere.PlanID = "another-report"
	overOtherBytes := signCanonicalForm(t, elsewhere, private)

	for name, test := range map[string]struct {
		signature string
		key       ed25519.PublicKey
		want      string
	}{
		"a signature over other bytes":      {overOtherBytes, public, "does not verify"},
		"a signature by another key":        {signCanonicalForm(t, report, otherPrivate), public, "does not verify"},
		"the right signature, another key":  {good, otherPublic, "does not verify"},
		"a signature that is not hex":       {"not hexadecimal", public, "not hexadecimal"},
		"a signature of the wrong length":   {good[:len(good)-2], public, "invalid signature length"},
		"an empty signature":                {"", public, "invalid signature length"},
		"a public key of the wrong size":    {good, public[:31], "public key size"},
		"no public key":                     {good, nil, "public key size"},
		"a small-order public key (zeroes)": {good, make(ed25519.PublicKey, ed25519.PublicKeySize), "small-order"},
	} {
		attempt := *report
		if err := attempt.AttachSignature(test.signature, test.key); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: AttachSignature = %v, want an error mentioning %q", name, err, test.want)
		}
		if attempt.Signature != "" || attempt.PublicKey != "" || attempt.SignerFingerprint != "" {
			t.Errorf("%s: the report was changed by a refused signature: %+v", name, attempt)
		}
	}

	// The report is signed over everything but the unsigned members: a change
	// after the signature was made means the signature no longer covers it.
	changed := *report
	changed.AllPassed = !changed.AllPassed
	if err := changed.AttachSignature(good, public); err == nil {
		t.Error("a signature made before the report changed was attached")
	}
}

type recordingSigner struct {
	calls  int
	sign   func(*attest.Report) error
	sawSig []string
}

func (s *recordingSigner) SignReport(report *attest.Report) error {
	s.calls++
	s.sawSig = append(s.sawSig, report.Signature+report.PublicKey+report.SignerFingerprint)
	if s.sign == nil {
		return nil
	}
	return s.sign(report)
}

func TestApplySignerWithoutASignerLeavesTheReportUnsigned(t *testing.T) {
	report := unsignedTestReport()
	if err := attest.ApplySigner(report, nil); err != nil {
		t.Fatal(err)
	}
	if report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" || report.SignatureTimestamp != nil {
		t.Fatalf("a report with no signer was signed: %+v", report)
	}
}

func TestApplySignerCallsTheSignerOnceAndTheResultVerifies(t *testing.T) {
	public, private := testKeys(t)
	signer := attesttest.NewSigner(private)
	report := unsignedTestReport()
	// An earlier signature on the report is not carried into the new signing.
	report.Signature, report.PublicKey, report.SignerFingerprint = "00", "11", "22"
	if err := attest.ApplySigner(report, signer); err != nil {
		t.Fatal(err)
	}
	if signer.Calls() != 1 {
		t.Fatalf("the signer was called %d times, want once", signer.Calls())
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid, err := attest.VerifyReport(data, []ed25519.PublicKey{public}); err != nil || !valid {
		t.Fatalf("the report does not verify: valid=%v err=%v", valid, err)
	}
	if !bytes.Equal(signer.Public(), public) {
		t.Error("the test signer's public key is not the key's own")
	}
}

func TestApplySignerFailsClosed(t *testing.T) {
	sentinel := errors.New("the signing service is down")
	for name, test := range map[string]struct {
		sign func(*attest.Report) error
		want string
	}{
		"the signer fails": {func(r *attest.Report) error {
			r.Signature = strings.Repeat("ab", 64) // half done before it failed
			return sentinel
		}, sentinel.Error()},
		"the signer returns without signing": {nil, "returned without signing"},
		"the signer sets a signature that does not verify": {func(r *attest.Report) error {
			public, _ := testKeys(t)
			r.Signature, r.PublicKey, r.SignerFingerprint = strings.Repeat("ab", 64), hex.EncodeToString(public), attest.Fingerprint(public)
			return nil
		}, "does not verify"},
		"the signer signs and then changes the report": {func(r *attest.Report) error {
			_, private := testKeys(t)
			if err := attesttest.SignReport(r, private); err != nil {
				return err
			}
			r.AllPassed = !r.AllPassed
			return nil
		}, "changed the report"}, // found before the signature is checked (review R1-05)
	} {
		report := unsignedTestReport()
		signer := &recordingSigner{sign: test.sign}
		err := attest.ApplySigner(report, signer)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: ApplySigner = %v, want an error mentioning %q", name, err, test.want)
		}
		if signer.calls != 1 {
			t.Errorf("%s: the signer was called %d times, want once", name, signer.calls)
		}
		if report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" || report.SignatureTimestamp != nil {
			t.Errorf("%s: the report was left with signature members: %+v", name, report)
		}
	}
	if err := attest.ApplySigner(nil, attesttest.NewFailingSigner(sentinel)); err == nil {
		t.Error("ApplySigner of no report succeeded")
	}
}

// The test signer fails the way a real one may: with its own error, once per call.
func TestTestSignerCountsFailingCalls(t *testing.T) {
	sentinel := errors.New("no key")
	signer := attesttest.NewFailingSigner(sentinel)
	report := unsignedTestReport()
	for i := 1; i <= 2; i++ {
		if err := signer.SignReport(report); !errors.Is(err, sentinel) {
			t.Fatalf("call %d: %v", i, err)
		}
		if signer.Calls() != i {
			t.Fatalf("after %d calls, Calls() = %d", i, signer.Calls())
		}
	}
	if err := attesttest.SignReport(report, make(ed25519.PrivateKey, 10)); err == nil || !strings.Contains(err.Error(), "private key is 64 bytes") {
		t.Errorf("SignReport with a key of the wrong size = %v", err)
	}
}
