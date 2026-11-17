// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// usableKeyProblem says why a loaded trust anchor is not a key that can anchor
// trust, judged by means independent of checkPublicKey: an independent curve
// membership oracle, and Go's own ed25519.Verify, which accepts a signature
// forged without any private key (R = identity, S = 0) under a small-order key
// for one message in 1, 2, 4 or 8. Sixty-four messages find every such key
// with odds above 99.99%.
func usableKeyProblem(key []byte) string {
	if len(key) != ed25519.PublicKeySize {
		return "wrong size"
	}
	if !onCurveOracle(key) {
		return "not a point on the curve"
	}
	forged := append([]byte{1}, make([]byte, 63)...)
	for i := 0; i < 64; i++ {
		if ed25519.Verify(key, []byte(fmt.Sprintf("message %d", i)), forged) {
			return "a signature forged without a private key verifies under it (small order)"
		}
	}
	return ""
}

// FuzzParseKeyring: whatever a keyring file holds, parsing it never panics,
// and a keyring that loads is a coherent trust set: canonical lower-case keys,
// each once, with its own fingerprint, every one a key that can anchor trust
// (a canonical point of the curve, of large order).
func FuzzParseKeyring(f *testing.F) {
	a := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	ah, bh := hex.EncodeToString(a), hex.EncodeToString(b)
	for _, content := range []string{
		"", "{}", `{"trusted_signers":[]}`, "# none\n", ah + "\n", ah + "\r\n" + strings.ToUpper(bh) + "\n", ah + "\n" + strings.ToUpper(ah) + "\n",
		`{"trusted_signers":[{"name":"a","public_key":"` + ah + `","fingerprint":"` + Fingerprint(a) + `"}]}`,
		`{"trusted_signers":[{"name":"a","public_key":"` + ah + `","fingerprint":"` + Fingerprint(b) + `"}]}`,
		`{"trusted_signers":[{"public_key":"` + ah + `"},{"public_key":"` + strings.ToUpper(ah) + `"}]}`,
		`{"trusted_signers":[{"public_key":"` + ah + `","public_key":"` + bh + `"}]}`,
		"\xef\xbb\xbf" + ah, "[", `{"trusted_signers":null}`, `{"trusted_signers":[null]}`, ah[:63] + "\n", ah + " # note\n",
	} {
		f.Add([]byte(content))
	}
	// Members that fold to a documented name, and a revocation mark.
	for _, content := range []string{
		`{"trusted_signers":[{"public_key":"` + ah + `","Public_Key":"` + bh + `"}]}`,
		`{"trusted_signers":[{"public_key":"` + ah + `"}],"TRUSTED_SIGNERS":[{"public_key":"` + bh + `"}]}`,
		`{"trusted_signers":[{"public_key":"` + ah + `","public_` + "K" + `ey":"` + bh + `"}]}`,
		`{"trusted_signers":[{"public_key":"` + ah + `","revoked":true}]}`,
		`{"trusted_signers":[{"name":"a","public_key":"` + ah + `","comment":"x"}],"version":2}`,
	} {
		f.Add([]byte(content))
	}
	// Keys that must be refused: small-order points, their non-canonical
	// encodings, and a value that is not a curve point.
	unusable := smallOrderEncodings(f)
	for name, enc := range nonCanonicalEncodings() {
		unusable["non-canonical: "+name] = enc
	}
	unusable["off the curve"] = append([]byte{2}, make([]byte, 31)...)
	for _, enc := range unusable {
		f.Add([]byte(hex.EncodeToString(enc) + "\n"))
		f.Add([]byte(`{"trusted_signers":[{"name":"prod-controller","public_key":"` + hex.EncodeToString(enc) + `"}]}`))
		f.Add([]byte(ah + "\n" + strings.ToUpper(hex.EncodeToString(enc)) + "\n"))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		kr, err := parseKeyring(data, "fuzz")
		if err != nil {
			if kr != nil {
				t.Fatalf("a keyring and an error together: %v", err)
			}
			return
		}
		seen := make(map[string]bool)
		for _, signer := range kr.TrustedSigners {
			raw, err := hex.DecodeString(signer.PublicKey)
			if err != nil || len(raw) != ed25519.PublicKeySize || signer.PublicKey != strings.ToLower(signer.PublicKey) {
				t.Fatalf("loaded an entry whose key is not canonical: %q", signer.PublicKey)
			}
			if signer.Fingerprint != Fingerprint(ed25519.PublicKey(raw)) {
				t.Fatalf("loaded an entry with a wrong fingerprint: %+v", signer)
			}
			if problem := usableKeyProblem(raw); problem != "" {
				t.Fatalf("loaded an entry whose key cannot anchor trust (%s): %q", problem, signer.PublicKey)
			}
			if seen[signer.PublicKey] {
				t.Fatalf("loaded the key %s twice", signer.PublicKey)
			}
			seen[signer.PublicKey] = true
			if found := kr.FindSigner(strings.ToUpper(signer.PublicKey)); found == nil || found.PublicKey != signer.PublicKey {
				t.Fatalf("a loaded key is not found: %+v", signer)
			}
		}
		if len(kr.PublicKeys()) != len(kr.TrustedSigners) {
			t.Fatalf("%d usable keys for %d entries", len(kr.PublicKeys()), len(kr.TrustedSigners))
		}
		if err := kr.Validate(); err != nil {
			t.Fatalf("a loaded keyring does not validate: %v", err)
		}
		// The key each entry loaded with is the one under the exact member name
		// "public_key": no case-folded look-alike member overrode it.
		if trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, utf8BOM)); bytes.HasPrefix(trimmed, []byte("{")) {
			var top map[string]json.RawMessage
			var entries []map[string]json.RawMessage
			if json.Unmarshal(trimmed, &top) != nil || json.Unmarshal(top["trusted_signers"], &entries) != nil || len(entries) != len(kr.TrustedSigners) {
				t.Fatalf("a loaded JSON keyring does not decode by exact member names")
			}
			for i, entry := range entries {
				var text string
				if json.Unmarshal(entry["public_key"], &text) != nil {
					t.Fatalf("entry %d loaded without an exact public_key member", i+1)
				}
				if key, err := parsePublicKeyHex(text); err != nil || hex.EncodeToString(key) != kr.TrustedSigners[i].PublicKey {
					t.Fatalf("entry %d loaded a key other than its public_key member's", i+1)
				}
			}
		}
	})
}
