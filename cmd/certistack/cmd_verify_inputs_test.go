// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/config"
)

// signedReportFile writes a report signed by a fresh key and returns its path,
// the signer's public key and the signer's private key.
func signedReportFile(t *testing.T, dir string) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := attest.BuildReport(&config.Plan{PlanID: "verify-inputs"}, "node-a", time.Second, true, nil, "")
	if err := attesttest.SignReport(report, priv); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, pub, priv
}

func runVerify(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	cmd := verifyReportCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), err
}

// An invocation that can be refused from its arguments alone is
// refused before the report is opened. The report path here does not exist,
// and its error must never be the one reported.
func TestVerifyReportRefusesBadArgumentsBeforeOpeningTheReport(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing-report.json")
	keyring := filepath.Join(dir, "keyring")
	pubFile := filepath.Join(dir, "signer.pub")
	genuine, _, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	inline := hex.EncodeToString(genuine)

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no trust source":                     {[]string{missing}, "an explicit --keyring, --public-key, or --trusted-key is required"},
		"keyring and public key":              {[]string{"--keyring", keyring, "--public-key", pubFile, missing}, "mutually exclusive"},
		"keyring and trusted key":             {[]string{"--keyring", keyring, "--trusted-key", inline, missing}, "mutually exclusive"},
		"all three":                           {[]string{"--keyring", keyring, "--public-key", pubFile, "--trusted-key", inline, missing}, "mutually exclusive"},
		"unsupported format":                  {[]string{"--format", "xml", "--keyring", keyring, missing}, "unsupported --format"},
		"empty keyring flag":                  {[]string{"--keyring", "", missing}, "--keyring must not be empty"},
		"empty public key flag":               {[]string{"--public-key", " ", missing}, "--public-key must not be empty"},
		"empty trusted key flag":              {[]string{"--trusted-key", "", missing}, "--trusted-key must not be empty"},
		"empty flag beside a real source":     {[]string{"--keyring", "", "--trusted-key", inline, missing}, "--keyring must not be empty"},
		"unsupported outcome":                 {[]string{"--expect-outcome", "maybe", "--trusted-key", inline, missing}, "unsupported --expect-outcome"},
		"empty expectation":                   {[]string{"--expect-node", "", "--trusted-key", inline, missing}, "--expect-node must not be empty"},
		"malformed inline key":                {[]string{"--trusted-key", "abcd", missing}, "invalid --trusted-key"},
		"public key file that does not exist": {[]string{"--public-key", pubFile, missing}, "failed to read public key"},
		"keyring file that does not exist":    {[]string{"--keyring", keyring, missing}, "failed to load keyring"},
	} {
		if _, err := runVerify(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: verify-report = %v, want an error containing %q", name, err, tc.want)
		}
	}

	// Control: with valid arguments the missing report is the reported fault.
	if _, err := runVerify(t, "--trusted-key", inline, missing); err == nil || !strings.Contains(err.Error(), "failed to read report") || !strings.Contains(err.Error(), missing) {
		t.Errorf("a valid invocation of a missing report: %v", err)
	}
}

// The report is a size-limited regular file. One over the limit is
// refused after reading none of it, and a directory is refused as such.
func TestVerifyReportRefusesOversizedOrNonRegularReports(t *testing.T) {
	dir := t.TempDir()
	_, pub, _ := signedReportFile(t, dir)
	huge := filepath.Join(dir, "huge.json")
	if err := os.WriteFile(huge, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(huge, attest.MaxReportFileBytes+1); err != nil {
		t.Fatal(err)
	}
	trusted := hex.EncodeToString(pub)
	var err error
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err = runVerify(t, "--trusted-key", trusted, huge)
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("a report one byte over the limit: %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
		t.Errorf("refusing an oversized report allocated %d bytes", allocated)
	}
	bigPlan := filepath.Join(dir, "big-plan.yaml")
	if err := os.WriteFile(bigPlan, []byte("#"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(bigPlan, maxExpectedPlanBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := runVerify(t, "--trusted-key", trusted, "--expect-plan", bigPlan, huge); err == nil || !strings.Contains(err.Error(), "expected plan") || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an oversized --expect-plan file: %v", err)
	}
	if _, err := runVerify(t, "--trusted-key", trusted, "--expect-plan", dir, huge); err == nil || !strings.Contains(err.Error(), "a directory, not a regular file") {
		t.Errorf("a directory as --expect-plan: %v", err)
	}
	if _, err := runVerify(t, "--trusted-key", trusted, dir); err == nil || !strings.Contains(err.Error(), "a directory, not a regular file") {
		t.Errorf("a directory as the report: %v", err)
	}
}

// Verify-report refuses a keyring whose entries contradict each other
// or are not keys, names the entries, and reports no trusted signer.
func TestVerifyReportRefusesContradictoryKeyring(t *testing.T) {
	dir := t.TempDir()
	reportPath, pubA, _ := signedReportFile(t, dir)
	pubB, _, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyA := hex.EncodeToString(pubA)
	keyring, err := json.Marshal(map[string]any{"trusted_signers": []map[string]string{
		{"name": "first-conflicting-label", "node": "wrong-node.example", "public_key": keyA, "fingerprint": attest.Fingerprint(pubB)},
		{"name": "malformed-anchor", "public_key": "not-an-ed25519-key"},
		{"name": "duplicate-conflicting-label", "node": "other-node.example", "public_key": strings.ToUpper(keyA), "fingerprint": attest.Fingerprint(pubA)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	keyringPath := filepath.Join(dir, "keyring.json")
	if err := os.WriteFile(keyringPath, keyring, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runVerify(t, "--keyring", keyringPath, reportPath)
	if err == nil {
		t.Fatalf("verify-report accepted the contradictory keyring:\n%s", out)
	}
	for _, want := range []string{"failed to load keyring", "entry 1", "entry 2", "entry 3"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lacks %q: %v", want, err)
		}
	}
	if strings.Contains(out, "TRUSTED") || strings.Contains(out, "first-conflicting-label") {
		t.Errorf("a signer was reported as trusted from a contradictory keyring:\n%s", out)
	}

	// Control: the same report against a coherent keyring names its signer.
	good, err := json.Marshal(map[string]any{"trusted_signers": []map[string]string{
		{"name": "controller-a", "node": "pve1", "public_key": strings.ToUpper(keyA), "fingerprint": attest.Fingerprint(pubA)},
		{"name": "controller-b", "public_key": hex.EncodeToString(pubB)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	goodPath := filepath.Join(dir, "good.json")
	if err := os.WriteFile(goodPath, good, 0600); err != nil {
		t.Fatal(err)
	}
	out, err = runVerify(t, "--keyring", goodPath, reportPath)
	if err != nil || !strings.Contains(out, `Signer Identity: TRUSTED ("controller-a")`) || !strings.Contains(out, "Signer Node: pve1") {
		t.Fatalf("verify-report against a coherent keyring: err=%v\n%s", err, out)
	}
}

// A keyring that lists no key cannot accept a report, and says so;
// keyring and public-key files are size-limited and read as plain
// files, however a Windows editor saved them.
func TestVerifyReportTrustFileInputs(t *testing.T) {
	dir := t.TempDir()
	reportPath, pub, _ := signedReportFile(t, dir)
	keyHex := hex.EncodeToString(pub)
	write := func(name string, content []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	for name, content := range map[string]string{"empty file": "", "empty list": `{"trusted_signers":[]}`, "comments only": "# every signer was revoked\n"} {
		if _, err := runVerify(t, "--keyring", write("empty-"+strings.ReplaceAll(name, " ", "-"), []byte(content)), reportPath); err == nil || !strings.Contains(err.Error(), "holds no trusted signer keys") {
			t.Errorf("%s: %v", name, err)
		}
	}

	bom := "\xef\xbb\xbf"
	for name, args := range map[string][]string{
		"public key with BOM and CRLF": {"--public-key", write("bom.pub", []byte(bom+keyHex+"\r\n"))},
		"public key in upper case":     {"--public-key", write("upper.pub", []byte(strings.ToUpper(keyHex)+"\n"))},
		"raw public key":               {"--public-key", write("raw.pub", pub)},
		"keyring list with BOM":        {"--keyring", write("bom.keys", []byte(bom+keyHex+"\r\n"))},
		"JSON keyring with BOM":        {"--keyring", write("bom.json", []byte(bom+`{"trusted_signers":[{"name":"n","public_key":"`+keyHex+`"}]}`))},
	} {
		if out, err := runVerify(t, append(args, reportPath)...); err != nil || !strings.Contains(out, "Audit Certificate Signature VALID") {
			t.Errorf("%s: err=%v\n%s", name, err, out)
		}
	}

	over := write("over.pub", append(bytes.Repeat([]byte(" "), attest.MaxPublicKeyFileBytes), keyHex...))
	if _, err := runVerify(t, "--public-key", over, reportPath); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an oversized public key file: %v", err)
	}
	overKeyring := write("over.keys", append(bytes.Repeat([]byte("\n"), attest.MaxKeyringFileBytes), keyHex...))
	if _, err := runVerify(t, "--keyring", overKeyring, reportPath); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an oversized keyring: %v", err)
	}
	if _, err := runVerify(t, "--public-key", write("short.pub", []byte(keyHex[:62])), reportPath); err == nil || !strings.Contains(err.Error(), "invalid public key format") {
		t.Errorf("a truncated public key: %v", err)
	}
}
