// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// A trusted signer set passed to VerifyReport is a signer policy even
// when it is nil or empty, so "no trusted keys" accepts no report. Only
// omitting the argument gives signature-only verification.
func TestVerifyReportEmptyTrustSetAcceptsNothing(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	unrelated, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := BuildReport(&config.Plan{PlanID: "trust-set"}, "node1", time.Second, true, nil, "")
	if err := report.SignReport(priv); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	sets := map[string][]ed25519.PublicKey{
		"explicit nil set":   nil,
		"explicit empty set": {},
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"empty file":                  "",
		"empty JSON keyring":          `{"trusted_signers":[]}`,
		"legacy keyring with no keys": "# trusted signers\n\n",
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		keys, err := LoadKeyring(path)
		if err != nil {
			t.Fatalf("%s: LoadKeyring: %v", name, err)
		}
		sets[name] = keys
	}
	ring := &Keyring{TrustedSigners: []TrustedSigner{{Name: "only", PublicKey: hex.EncodeToString(pub)}}}
	ring.TrustedSigners = ring.TrustedSigners[:0]
	sets["keyring with its last key removed"] = ring.PublicKeys()
	// A keyring built by hand from entries that are not keys yields no keys
	// (the loader refuses such a file instead).
	sets["hand-built keyring of invalid keys"] = (&Keyring{TrustedSigners: []TrustedSigner{{Name: "typo", PublicKey: "not-a-key"}, {Name: "short", PublicKey: "abcd"}}}).PublicKeys()

	for name, set := range sets {
		verified, valid, err := VerifyReport(raw, set)
		if err == nil || valid || verified != nil {
			t.Errorf("%s: VerifyReport = (%v, %v, %v), want an untrusted-signer rejection", name, verified != nil, valid, err)
			continue
		}
		if !strings.Contains(err.Error(), "trusted signer set is empty") {
			t.Errorf("%s: error %q does not say the trusted set is empty", name, err)
		}
	}
	if _, valid, err := VerifyReport(raw, nil, []ed25519.PublicKey{}); err == nil || valid {
		t.Fatalf("two empty trusted sets accepted a report: valid=%v err=%v", valid, err)
	}

	// Positive and negative controls.
	if _, valid, err := VerifyReportSignatureOnly(raw); err != nil || !valid {
		t.Fatalf("signature-only verification (no trust argument) failed: valid=%v err=%v", valid, err)
	}
	if _, valid, err := VerifyReport(raw, []ed25519.PublicKey{pub}); err != nil || !valid {
		t.Fatalf("matching trusted key rejected: valid=%v err=%v", valid, err)
	}
	if _, valid, err := VerifyReport(raw, []ed25519.PublicKey{unrelated}); err == nil || valid || !strings.Contains(err.Error(), "not in trusted keyring") {
		t.Fatalf("unrelated trusted key accepted: valid=%v err=%v", valid, err)
	}
	if _, valid, err := VerifyReport(raw, []ed25519.PublicKey{unrelated}, []ed25519.PublicKey{pub}); err != nil || !valid {
		t.Fatalf("signer in the second trusted set rejected: valid=%v err=%v", valid, err)
	}
}

// The signature covers the RFC 8785 canonical payload, not the file's
// bytes. Whitespace and member order may change; any change to a signed value
// may not. The docs describe exactly this.
func TestVerifyReportCoversCanonicalPayloadNotFileBytes(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := BuildReport(&config.Plan{PlanID: "canonical"}, "node1", time.Second, false, nil, "")
	if err := report.SignReport(priv); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	trusted := []ed25519.PublicKey{pub}

	var indented bytes.Buffer
	if err := json.Indent(&indented, raw, "", "    "); err != nil {
		t.Fatal(err)
	}
	var reordered map[string]json.RawMessage
	if err := json.Unmarshal(raw, &reordered); err != nil {
		t.Fatal(err)
	}
	reorderedBytes, err := json.Marshal(reordered) // encoding/json sorts map keys
	if err != nil {
		t.Fatal(err)
	}
	for name, equivalent := range map[string][]byte{"reindented": indented.Bytes(), "reordered": reorderedBytes} {
		if bytes.Equal(equivalent, raw) {
			t.Fatalf("%s: the variant did not change the file bytes", name)
		}
		if _, valid, err := VerifyReport(equivalent, trusted); err != nil || !valid {
			t.Fatalf("%s: canonically equal report rejected: valid=%v err=%v", name, valid, err)
		}
	}

	changed := strings.Replace(string(raw), `"all_passed":false`, `"all_passed":true`, 1)
	if changed == string(raw) {
		t.Fatal("tamper pattern did not apply")
	}
	if _, valid, err := VerifyReport([]byte(changed), trusted); err == nil || valid {
		t.Fatalf("a changed signed value verified: valid=%v err=%v", valid, err)
	}
}
