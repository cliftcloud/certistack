// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest_test

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
)

// Review R1-03 and R1-08. The decoder reads a report's members without regard to
// case ("Signature" fills the same field as "signature"), so the checks that say
// whether a report is signed or unsigned must read them the same way: a
// signature that is there under another spelling is not an unsigned report, and
// a signature member that holds no usable signature is not a missing one.

// insertMember puts member (a `"name":value` text) into a report document.
func insertMember(t *testing.T, document []byte, member string) []byte {
	t.Helper()
	text := string(document)
	open := strings.Index(text, "{")
	if open < 0 {
		t.Fatalf("no object in %s", document)
	}
	return []byte(text[:open+1] + member + "," + text[open+1:])
}

func unsignedDocument(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(unsignedTestReport())
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCarriedSignatureMembersFindsEveryCaseVariant(t *testing.T) {
	document := unsignedDocument(t)
	if got, err := attest.CarriedSignatureMembers(document); err != nil || len(got) != 0 {
		t.Fatalf("CarriedSignatureMembers of an unsigned report = %v, %v", got, err)
	}
	withMembers := insertMember(t, insertMember(t, document, `"Signature":"ab"`), `"SIGNER_fingerprint":null`)
	got, err := attest.CarriedSignatureMembers(withMembers)
	if err != nil {
		t.Fatal(err)
	}
	// Both are found, as they are spelled, whatever the order of the document.
	if len(got) != 2 || !(got[0] == "Signature" && got[1] == "SIGNER_fingerprint" || got[1] == "Signature" && got[0] == "SIGNER_fingerprint") {
		t.Errorf("CarriedSignatureMembers = %v, want both members as spelled", got)
	}
	// A nested member of that name is content, not a signature.
	nested := insertMember(t, document, `"x_note":{"signature":"ab","public_key":"cd"}`)
	if got, err := attest.CarriedSignatureMembers(nested); err != nil || len(got) != 0 {
		t.Errorf("a nested member was counted: %v, %v", got, err)
	}
}

func TestDecodeUnsignedReportRefusesAnyCaseVariantOfASignatureMember(t *testing.T) {
	document := unsignedDocument(t)
	stub := `{"authority":"stub","time":"2026-10-08T00:00:00Z","token":"AAAA","hash_algorithm":"sha256"}`
	for _, member := range []string{
		`"Signature":"` + strings.Repeat("ab", 64) + `"`,
		`"SIGNATURE":"` + strings.Repeat("ab", 64) + `"`,
		`"Public_Key":"` + strings.Repeat("cd", 32) + `"`,
		`"public_KEY":"` + strings.Repeat("cd", 32) + `"`,
		`"Signer_Fingerprint":"SHA256:x"`,
		`"Signature_Timestamp":` + stub,
		`"SIGNATURE_TIMESTAMP":null`,
	} {
		_, err := attest.DecodeUnsignedReport(insertMember(t, document, member))
		if !errors.Is(err, attest.ErrReportSigned) {
			t.Errorf("DecodeUnsignedReport with %.40s = %v, want ErrReportSigned", member, err)
			continue
		}
		name := strings.Trim(strings.SplitN(member, ":", 2)[0], `"`)
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal %q does not name the member as it is spelled, %q", err, name)
		}
	}
	// A member that merely starts like a signature member is content.
	if _, err := attest.DecodeUnsignedReport(insertMember(t, document, `"signature_note":"hello"`)); err != nil {
		t.Errorf("a member called signature_note was refused: %v", err)
	}
}

// A signature member that holds no usable signature is not a missing signature:
// the report is neither signed nor unsigned, and the verifier says so instead of
// sending the reader to --unsigned, which would refuse it too.
func TestVerifiersDoNotCallAMalformedSignatureUnsigned(t *testing.T) {
	public, _ := testKeys(t)
	document := unsignedDocument(t)
	for _, tc := range []struct {
		name   string
		member string
	}{
		{"a signature that is a number", `"signature":5`},
		{"a signature that is an object", `"signature":{}`},
		{"a signature that is null", `"signature":null`},
		{"an empty signature", `"signature":""`},
		{"a public key alone", `"public_key":"` + strings.Repeat("cd", 32) + `"`},
		{"a fingerprint alone", `"signer_fingerprint":"SHA256:forged"`},
		{"a timestamp alone", `"signature_timestamp":{"authority":"x","time":"2026-10-08T00:00:00Z","token":"AAAA","hash_algorithm":"sha256"}`},
		{"a signature in another case", `"Signature":"` + strings.Repeat("ab", 64) + `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := insertMember(t, document, tc.member)
			_, _, err := attest.VerifyReport(data, []ed25519.PublicKey{public})
			if err == nil {
				t.Fatal("VerifyReport accepted it")
			}
			if errors.Is(err, attest.ErrReportUnsigned) {
				t.Errorf("VerifyReport = %v: a report that carries a signature member is not unsigned", err)
			}
			if !strings.Contains(err.Error(), "signature member") {
				t.Errorf("VerifyReport = %v, want it to say the report carries a signature member that is not usable", err)
			}
			if _, _, err := attest.VerifyReportSignatureOnly(data); errors.Is(err, attest.ErrReportUnsigned) {
				t.Errorf("VerifyReportSignatureOnly = %v: not unsigned", err)
			}
		})
	}
	// A report with none of the four members is the unsigned report it always was.
	if _, _, err := attest.VerifyReport(document, []ed25519.PublicKey{public}); !errors.Is(err, attest.ErrReportUnsigned) {
		t.Errorf("an unsigned report = %v, want ErrReportUnsigned", err)
	}
}

// A signed report that also holds a member spelled like one of the signature
// members in another case is refused, not verified with the stray member signed
// as content.
func TestVerifyRefusesASignedReportWithAStraySignatureMemberInAnotherCase(t *testing.T) {
	public, private := testKeys(t)
	report := unsignedTestReport()
	if err := attesttest.SignReport(report, private); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid, err := attest.VerifyReport(data, []ed25519.PublicKey{public}); err != nil || !valid {
		t.Fatalf("the signed report does not verify as written: valid=%v err=%v", valid, err)
	}
	stray := insertMember(t, data, `"Signer_Fingerprint":"SHA256:forged"`)
	if _, valid, err := attest.VerifyReport(stray, []ed25519.PublicKey{public}); err == nil || valid || !strings.Contains(strings.ToLower(err.Error()), "signer_fingerprint") {
		t.Errorf("VerifyReport with a stray Signer_Fingerprint = valid %v, %v; want a refusal that names it", valid, err)
	}
}
