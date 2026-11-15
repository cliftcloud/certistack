// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Review R1-03 and R1-08. verify-report --unsigned and report show decide
// whether a report carries a signature by the members of its document, and the
// decoder reads the members without regard to case, so a signature under
// another spelling must not read as an unsigned report (it did: exit 0, with a
// real signature under the name "Signature", and a timestamp evaluated on a
// report declared unsigned); and a signature member that holds nothing usable is
// neither unsigned nor signed, which report show said "unsigned" about and
// --unsigned then refused.

// insertMemberText puts a `"name":value` member into a report file's text.
func insertMemberText(data []byte, member string) []byte {
	text := string(data)
	open := strings.Index(text, "{")
	return []byte(text[:open+1] + member + "," + text[open+1:])
}

func TestVerifyReportUnsignedRefusesASignatureUnderAnotherCase(t *testing.T) {
	m := newUnsignedMatrix(t)
	unsigned, err := os.ReadFile(m.unsigned)
	if err != nil {
		t.Fatal(err)
	}
	stub := `{"authority":"stub (not a trust anchor)","time":"2026-10-08T00:00:00Z","token":"AAAA","hash_algorithm":"sha256"}`
	sig := strings.Repeat("ab", 64)
	for name, member := range map[string]string{
		"Signature":           `"Signature":"` + sig + `"`,
		"SIGNATURE":           `"SIGNATURE":"` + sig + `"`,
		"Public_Key":          `"Public_Key":"` + strings.Repeat("cd", 32) + `"`,
		"Signer_Fingerprint":  `"Signer_Fingerprint":"SHA256:forged"`,
		"Signature_Timestamp": `"Signature_Timestamp":` + stub,
	} {
		path := filepath.Join(m.dir, "case-"+name+".json")
		if err := os.WriteFile(path, insertMemberText(unsigned, member), 0o600); err != nil {
			t.Fatal(err)
		}
		args := append(append([]string{"--unsigned", "--format", "json", "--expect-outcome", "pass"}, expectArgsForFixture...), path)
		stdout, _, err := runVerifyStreams(args...)
		if err == nil || exitOf(err) != exitCodeInfrastructure {
			t.Errorf("%s: exit %d (%v), want the report refused with %d", name, exitOf(err), err, exitCodeInfrastructure)
			continue
		}
		if !strings.Contains(err.Error(), "carries a signature") || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: the refusal %q does not say the report carries a signature, nor name the member", name, err)
		}
		if strings.Contains(err.Error(), "timestamp beside it") {
			t.Errorf("%s: the refusal talks of a timestamp being checked on an unsigned report: %v", name, err)
		}
		if stdout != "" {
			t.Errorf("%s: a refused report printed %q", name, stdout)
		}
	}
}

func TestReportShowSaysWhenASignatureMemberIsMalformedNotUnsigned(t *testing.T) {
	m := newUnsignedMatrix(t)
	unsigned, err := os.ReadFile(m.unsigned)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := os.ReadFile(m.signed)
	if err != nil {
		t.Fatal(err)
	}
	statusOf := func(label string, data []byte) (status, note string) {
		t.Helper()
		path := filepath.Join(m.dir, "show-"+strings.ReplaceAll(label, " ", "_")+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		stdout, _, err := runReportCommand(t, "report", "show", "--json", path)
		if err != nil {
			t.Fatalf("%s: report show failed: %v", label, err)
		}
		var view struct {
			Signature struct{ Status, Note string }
		}
		if err := json.Unmarshal([]byte(stdout), &view); err != nil {
			t.Fatalf("%s: %v\n%s", label, err, stdout)
		}
		return view.Signature.Status, view.Signature.Note
	}

	for label, want := range map[string]string{"unsigned": "unsigned", "signed": "not_checked"} {
		data := unsigned
		if label == "signed" {
			data = signed
		}
		if got, _ := statusOf(label, data); got != want {
			t.Errorf("%s: status %q, want %q", label, got, want)
		}
	}
	for label, member := range map[string]string{
		"signature empty":  `"signature":""`,
		"signature null":   `"signature":null`,
		"case variant":     `"Signature":"` + strings.Repeat("ab", 64) + `"`,
		"public key alone": `"public_key":"` + strings.Repeat("cd", 32) + `"`,
		"fingerprint only": `"signer_fingerprint":"SHA256:forged"`,
	} {
		status, note := statusOf(label, insertMemberText(unsigned, member))
		if status != "malformed" {
			t.Errorf("%s: status %q, want malformed", label, status)
			continue
		}
		// The advice is what verify-report will do with the same file.
		for _, want := range []string{"signature member", "--unsigned refuses"} {
			if !strings.Contains(note, want) {
				t.Errorf("%s: the note %q lacks %q", label, note, want)
			}
		}
		path := filepath.Join(m.dir, "show-"+strings.ReplaceAll(label, " ", "_")+".json")
		if _, _, err := runVerifyStreams("--unsigned", "--format", "json", path); err == nil || exitOf(err) != exitCodeInfrastructure {
			t.Errorf("%s: verify-report --unsigned = %v, want the refusal report show's advice says", label, err)
		}
	}

	// The text view says it too, and does not send the reader to --unsigned.
	path := filepath.Join(m.dir, "show-text.json")
	if err := os.WriteFile(path, insertMemberText(unsigned, `"signature":""`), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runReportCommand(t, "report", "show", path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "MALFORMED") || strings.Contains(stdout, "Judge it: certistack verify-report --unsigned") {
		t.Errorf("the text view of a malformed signature:\n%s", stdout)
	}
}
