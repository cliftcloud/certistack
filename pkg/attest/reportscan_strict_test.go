// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Review R1-09 and R1-10. The canonical form of a report is meant to be
// injective over the documents the verifier accepts, except for the slack the
// documentation names (whitespace, member order, equivalent spellings of a
// number). Two corners were not: text that is not Unicode (a byte that is no
// UTF-8, a lone surrogate escape) read as U+FFFD, so four different files carried
// one signature; and member names that differ only by case folding were both
// accepted while encoding/json decodes them into one field, so a signed report's
// typed fields could disagree with its raw members. A report is refused for
// either, as it is for a repeated member name.

func TestReportScanRefusesTextThatIsNotUnicode(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		want string
	}{
		{"a byte that is not UTF-8 in a string", "{\"failure_reason\":\"a\xffb\"}", "invalid UTF-8"},
		{"an overlong UTF-8 encoding", "{\"failure_reason\":\"a\xc0\xafb\"}", "invalid UTF-8"},
		{"a truncated UTF-8 sequence", "{\"failure_reason\":\"a\xe2\x82\"}", "invalid UTF-8"},
		{"a UTF-8 encoded surrogate", "{\"failure_reason\":\"a\xed\xa0\x80b\"}", "invalid UTF-8"},
		{"a byte that is not UTF-8 in a member name", "{\"fail\xffure\":1}", "invalid UTF-8"},
		{"a lone high surrogate escape", `{"failure_reason":"a\ud800b"}`, "surrogate"},
		{"a lone low surrogate escape", `{"failure_reason":"a\udfffb"}`, "surrogate"},
		{"a high surrogate escape and a letter", `{"failure_reason":"a\ud83dxb"}`, "surrogate"},
		{"a high surrogate escape and a high one", `{"failure_reason":"a\ud83d\ud83db"}`, "surrogate"},
		{"a high surrogate escape at the end of the string", `{"failure_reason":"a\ud83d"}`, "surrogate"},
		{"a lone surrogate escape in a member name", `{"fail\ud800ure":1}`, "surrogate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := scanJSON([]byte(tc.doc), reportLimits)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("scanJSON = %v, want a refusal that says %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "$") && !strings.Contains(err.Error(), "byte") {
				t.Errorf("the refusal does not say where: %v", err)
			}
		})
	}
	// What is Unicode is still read: multi-byte text, an escaped pair, a
	// non-ASCII member name, and the replacement character itself.
	for _, doc := range []string{
		"{\"failure_reason\":\"caf\xc3\xa9 \xe6\x97\xa5\xe6\x9c\xac \xf0\x9f\x98\x80\"}",
		`{"failure_reason":"😀 é 日"}`,
		"{\"caf\xc3\xa9\":1}",
		"{\"failure_reason\":\"a\xef\xbf\xbdb\"}",
		`{"failure_reason":"a�b"}`,
		`{"failure_reason":"\u0000 \u001f"}`,
	} {
		if err := scanJSON([]byte(doc), reportLimits); err != nil {
			t.Errorf("scanJSON(%q) = %v, want it read", doc, err)
		}
	}
	// Other documents (a keyring) keep their own rules.
	if err := scanJSON([]byte("{\"name\":\"a\xffb\"}"), keyringLimits); err != nil {
		t.Errorf("the keyring scan refused a byte it never refused: %v", err)
	}
}

func TestReportScanRefusesMemberNamesThatDifferOnlyByCaseFolding(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
	}{
		{"upper case", `{"all_passed":false,"ALL_PASSED":true}`},
		{"one capital", `{"all_passed":false,"All_passed":true}`},
		{"the long s, which folds to s", `{"all_passed":false,"all_pa` + "ſſ" + `ed":true}`},
		{"the Kelvin sign, which folds to k", `{"k":1,"` + "K" + `":2}`},
		{"a signature member in another case", `{"signature":"ab","Signature":"cd"}`},
		{"nested", `{"vm_records":[{"vmid":1,"VMID":2}]}`},
		{"escaped", `{"all_passed":false,"ALL_PASSED":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := scanJSON([]byte(tc.doc), reportLimits)
			if err == nil || !strings.Contains(err.Error(), "letter case") {
				t.Fatalf("scanJSON = %v, want a refusal that says the names differ only by letter case", err)
			}
		})
	}
	for _, doc := range []string{
		`{"all_passed":false,"all_passes":true}`,
		`{"a":{"all_passed":true},"b":{"all_passed":false}}`,
		`{"vm_records":[{"vmid":1},{"vmid":2}]}`,
		`{"x":1,"y":2,"z":3}`,
	} {
		if err := scanJSON([]byte(doc), reportLimits); err != nil {
			t.Errorf("scanJSON(%s) = %v, want it read", doc, err)
		}
	}
	// A keyring is not a report: its names are judged by its own loader.
	if err := scanJSON([]byte(`{"name":"a","Name":"b"}`), keyringLimits); err != nil {
		t.Errorf("the keyring scan refused names it never refused: %v", err)
	}
}

// The corners as the reviewer built them: a report signed with a value that
// holds U+FFFD verified with the same signature under three other spellings of
// that character; and a signed document with a fold-equal pair read as the
// shadowing member. Neither verifies now.
func TestAnAlternateSpellingOfASignedReportDoesNotVerify(t *testing.T) {
	public, private, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := &Report{ReportSchemaVersion: CurrentReportSchemaVersion, ReportID: "r", ValidationMode: ValidationModeFullIntegrity, FailureReason: "a�b"}
	if err := report.SignReport(private); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	signed := string(data)
	if _, valid, err := VerifyReportSignatureOnly(data); err != nil || !valid {
		t.Fatalf("the signed report does not verify as written: valid=%v err=%v", valid, err)
	}
	for name, spelling := range map[string]string{
		"a raw invalid byte":   "a\xffb",
		"a lone high escape":   `a\ud800b`,
		"a lone low escape":    `a\udfffb`,
		"a high escape, a low": `a𐀀b`, // a real character, so a different report: not this signature
	} {
		variant := strings.Replace(signed, "a�b", spelling, 1)
		if variant == signed {
			t.Fatalf("%s: the variant was not made", name)
		}
		if _, valid, err := VerifyReportSignatureOnly([]byte(variant)); err == nil && valid && name != "a high escape, a low" {
			t.Errorf("%s: the report verifies with %q in place of U+FFFD", name, spelling)
		}
	}

	// A signed document that holds all_passed twice, the second spelled with the
	// long s (U+017F), is refused rather than read as the later member.
	document := `{"report_schema_version":"1.7","report_id":"x","all_passed":false,"all_pa` + "ſſ" + `ed":true,"validation_mode":"full_integrity"}`
	canonical, err := CanonicalizeReportJSON([]byte(document))
	if err == nil {
		var members map[string]interface{}
		_ = json.Unmarshal([]byte(document), &members)
		members["signature"] = SignCanonical(canonical, private)
		members["public_key"] = hex.EncodeToString(public)
		forged, _ := json.Marshal(members)
		if _, valid, err := VerifyReportSignatureOnly(forged); err == nil && valid {
			t.Error("a signed report with a fold-equal pair of members verifies, and its typed all_passed disagrees with its raw all_passed")
		}
	}
}
