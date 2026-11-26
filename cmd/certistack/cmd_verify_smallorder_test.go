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
	"runtime"
	"strings"
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
)

// smallOrderKeys are the Ed25519 points of order 1, 2, 4 and 8. Go's
// ed25519.Verify accepts a signature made without any private key under each:
// R = the identity, S = 0 verifies for every message under the identity, and
// for one message in 2, 4 or 8 under the others. The all-zero key is what an
// unreplaced placeholder looks like.
func smallOrderKeys() map[string][]byte {
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return b
	}
	sign := func(b []byte) []byte {
		c := append([]byte(nil), b...)
		c[31] |= 0x80
		return c
	}
	a := decode("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	b := decode("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
	zero := make([]byte, 32)
	return map[string][]byte{
		"all zero (order 4)":          zero,
		"all zero, other sign":        sign(zero),
		"identity (order 1)":          append([]byte{1}, make([]byte, 31)...),
		"(0,-1) (order 2)":            append([]byte{0xec}, append(bytes.Repeat([]byte{0xff}, 30), 0x7f)...),
		"order 8, first":              a,
		"order 8, first, other sign":  sign(a),
		"order 8, second":             b,
		"order 8, second, other sign": sign(b),
	}
}

// forgedReportFile writes a report that names pub as its signer and carries
// the signature R = identity, S = 0, made with no private key, with a report
// ID chosen so that Go's own ed25519.Verify accepts it. It fails the test when
// no ID works, which would mean the threat did not reproduce.
func forgedReportFile(t *testing.T, dir string, pub ed25519.PublicKey) string {
	t.Helper()
	plan := mustLoadFixturePlan()
	sig := append([]byte{1}, make([]byte, 63)...)
	for i := 0; i < 512; i++ {
		report := fixtureReport(plan, reportFixture{mode: accept.OutcomePass})
		report.ReportID = fmt.Sprintf("forged-%d", i)
		report.PublicKey = hex.EncodeToString(pub)
		report.SignerFingerprint = attest.Fingerprint(pub)
		report.Signature = hex.EncodeToString(sig)
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := attest.CanonicalizeReportJSON(data)
		if err != nil {
			t.Fatal(err)
		}
		if ed25519.Verify(pub, canonical, sig) {
			path := filepath.Join(dir, "forged.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}
	}
	t.Fatalf("Go's ed25519.Verify rejected every forged report under %x: the small-order threat did not reproduce", []byte(pub))
	return ""
}

// A report "signed" without a private key under a small-order key is
// refused by verify-report at exit status 2, before any verdict is printed,
// whichever way that key was supplied as the trusted signer: a keyring entry
// (JSON or list), a --public-key file (hex or raw, so the all-zero placeholder
// file of 32 NUL bytes too), or --trusted-key.
func TestVerifyReportRefusesForgeryUnderSmallOrderTrustAnchors(t *testing.T) {
	expect := []string{"--expect-plan", fixturePlanPath, "--expect-node", fixtureNode, "--expect-version", fixtureVersion, "--expect-commit", fixtureCommit, "--expect-build-date", fixtureBuildDate, "--expect-validation-mode", attest.ValidationModeFullIntegrity}
	for name, enc := range smallOrderKeys() {
		dir := t.TempDir()
		keyHex := hex.EncodeToString(enc)
		report := forgedReportFile(t, dir, ed25519.PublicKey(enc))
		write := func(file string, content []byte) string {
			path := filepath.Join(dir, file)
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatal(err)
			}
			return path
		}
		for input, trust := range map[string][]string{
			"JSON keyring entry": {"--keyring", write("ring.json", []byte(`{"trusted_signers":[{"name":"prod-controller","node":"pve1","public_key":"`+keyHex+`"}]}`))},
			"list keyring entry": {"--keyring", write("ring.list", []byte(keyHex+"\n"))},
			"hex public key":     {"--public-key", write("hex.pub", []byte(keyHex+"\n"))},
			"raw public key":     {"--public-key", write("raw.pub", enc)},
			"inline trusted key": {"--trusted-key", keyHex},
		} {
			args := append(append(append([]string{"--format", "json"}, trust...), expect...), report)
			out, err := runVerifyReport(args...)
			if err == nil || out != "" || exitCodeForError(err) != exitCodeInfrastructure {
				t.Errorf("%s as a %s: verify-report = (exit %d, %v), stdout %q; want a refusal at status 2 with no verdict", name, input, exitCodeForError(err), err, out)
				continue
			}
			if !strings.Contains(err.Error(), "small-order") && !strings.Contains(err.Error(), "canonical") {
				t.Errorf("%s as a %s: the refusal does not say why: %v", name, input, err)
			}
		}
	}
}

// An honest key beside a small-order placeholder is refused as a
// whole, and a forged report under the placeholder is not accepted by the
// honest entry either. The honest report still verifies against the honest
// keyring alone.
func TestVerifyReportKeyringWithAPlaceholderIsRefusedWhole(t *testing.T) {
	dir := t.TempDir()
	honestPath, honest, _ := signedReportFile(t, dir)
	keyring := filepath.Join(dir, "ring.json")
	placeholder := strings.Repeat("00", 32)
	ring := `{"trusted_signers":[{"name":"prod-controller","public_key":"` + hex.EncodeToString(honest) + `"},{"name":"unreplaced placeholder","public_key":"` + placeholder + `"}]}`
	if err := os.WriteFile(keyring, []byte(ring), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runVerify(t, "--keyring", keyring, honestPath)
	if err == nil || out != "" || !strings.Contains(err.Error(), `entry 2 ("unreplaced placeholder")`) {
		t.Fatalf("keyring with a placeholder: err=%v stdout=%q", err, out)
	}
	clean := filepath.Join(dir, "clean.json")
	if err := os.WriteFile(clean, []byte(`{"trusted_signers":[{"name":"prod-controller","public_key":"`+hex.EncodeToString(honest)+`"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := runVerify(t, "--keyring", clean, honestPath); err != nil || !strings.Contains(out, "Report signature VALID") {
		t.Fatalf("the honest keyring was refused: err=%v\n%s", err, out)
	}
}

// Notes (c): every argument value is checked before any file is opened, so a
// malformed --trusted-key is refused before an --expect-plan file is read.
func TestVerifyReportChecksTheInlineKeyBeforeOpeningTheExpectedPlan(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(plan, []byte("#"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(plan, maxExpectedPlanBytes); err != nil {
		t.Fatal(err)
	}
	// A plan of exactly the read limit is opened and read in full; the bad
	// key must be refused without that.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := runVerify(t, "--trusted-key", "abcd", "--expect-plan", plan, filepath.Join(dir, "report.json"))
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "invalid --trusted-key") {
		t.Fatalf("a malformed --trusted-key: %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Errorf("the bad key was refused only after allocating %d bytes: the plan file was read first", allocated)
	}
	if _, err := runVerify(t, "--trusted-key", strings.Repeat("00", 32), "--expect-plan", plan, filepath.Join(dir, "report.json")); err == nil || !strings.Contains(err.Error(), "invalid --trusted-key") {
		t.Fatalf("an all-zero --trusted-key: %v", err)
	}
}
