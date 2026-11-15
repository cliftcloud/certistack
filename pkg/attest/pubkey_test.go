// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// The small-order Ed25519 points and their non-canonical encodings. None has a
// private key.
func hexBytes(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// smallOrderEncodings returns every canonical encoding of a point of order 1,
// 2, 4 or 8, by name: the y values of libsodium's blocklist, each with both
// signs of x that decode.
func smallOrderEncodings(t testing.TB) map[string][]byte {
	t.Helper()
	zero := make([]byte, 32)
	identity := append([]byte{1}, make([]byte, 31)...)
	minusOne := append([]byte{0xec}, append(bytes.Repeat([]byte{0xff}, 30), 0x7f)...)
	order8a := hexBytes(t, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	order8b := hexBytes(t, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
	withSign := func(b []byte) []byte {
		c := append([]byte(nil), b...)
		c[31] |= 0x80
		return c
	}
	return map[string][]byte{
		"order 4, x = +sqrt(-1) (all zero)": zero,
		"order 4, x = -sqrt(-1)":            withSign(zero),
		"order 1, the identity":             identity,
		"order 2, (0, -1)":                  minusOne,
		"order 8 (a), first sign":           order8a,
		"order 8 (a), second sign":          withSign(order8a),
		"order 8 (b), first sign":           order8b,
		"order 8 (b), second sign":          withSign(order8b),
	}
}

// nonCanonicalEncodings returns encodings that Go's ed25519 decodes to a point
// although they are not the canonical spelling of it.
func nonCanonicalEncodings() map[string][]byte {
	high := func(first byte) []byte { // y = 2^255-19+k as 0xed+k, 0xff.., 0x7f
		return append([]byte{first}, append(bytes.Repeat([]byte{0xff}, 30), 0x7f)...)
	}
	signedIdentity := append([]byte{1}, make([]byte, 31)...)
	signedIdentity[31] = 0x80 // y = 1 with the sign of x set, though x = 0
	signedMinusOne := append([]byte{0xec}, bytes.Repeat([]byte{0xff}, 31)...)
	return map[string][]byte{
		"y = p (0 again)":                         high(0xed),
		"y = p+1 (1 again)":                       high(0xee),
		"y = p+2":                                 high(0xef),
		"y = 2^255-1":                             append(bytes.Repeat([]byte{0xff}, 31), 0x7f),
		"identity with the sign of x set":         signedIdentity,
		"(0, -1) with the sign of x set":          signedMinusOne,
		"y = p with the sign of x set (2^256-19)": append([]byte{0xed}, bytes.Repeat([]byte{0xff}, 31)...),
	}
}

// onCurveOracle says whether a canonical encoding names a curve point, by the
// Euler criterion on x^2 = (y^2-1)/(d y^2+1). It shares no code with
// checkPublicKey, which decompresses with ModSqrt.
func onCurveOracle(enc []byte) bool {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	le := append([]byte(nil), enc...)
	le[31] &= 0x7f
	be := make([]byte, 32)
	for i := range le {
		be[31-i] = le[i]
	}
	y := new(big.Int).SetBytes(be)
	d := new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), p))
	d.Mod(d, p)
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, p)
	v := new(big.Int).Mul(d, y2)
	v.Add(v, big.NewInt(1))
	v.Mod(v, p)
	x2 := new(big.Int).Mul(u, new(big.Int).ModInverse(v, p))
	x2.Mod(x2, p)
	if x2.Sign() == 0 {
		return true
	}
	e := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	return new(big.Int).Exp(x2, e, p).Cmp(big.NewInt(1)) == 0
}

// forgedReportFor returns a report that names pub as its signer and carries the
// signature R = identity, S = 0, made without any private key, with a report ID
// chosen so that Go's own ed25519.Verify accepts it. It reports false when no
// ID among 512 works: for a small-order key of order n one in n do; for a
// genuine key none does.
func forgedReportFor(pub ed25519.PublicKey) ([]byte, bool) {
	identity := append([]byte{1}, make([]byte, 31)...)
	sig := append(identity, make([]byte, 32)...)
	for i := 0; i < 512; i++ {
		r := BuildReport(&config.Plan{PlanID: "forged-plan"}, "node1", time.Second, true, nil, "")
		r.ReportID = fmt.Sprintf("forged-%d", i)
		r.PublicKey = hex.EncodeToString(pub)
		r.SignerFingerprint = Fingerprint(pub)
		r.Signature = hex.EncodeToString(sig)
		data, err := json.Marshal(r)
		if err != nil {
			panic(err)
		}
		canonical, err := CanonicalizeReportJSON(data)
		if err != nil {
			panic(err)
		}
		if ed25519.Verify(pub, canonical, sig) {
			return data, true
		}
	}
	return nil, false
}

// A public key that cannot anchor trust is refused at every place a
// key becomes a trust anchor. The threat is real: Go's ed25519.Verify accepts
// a forged signature under each small-order key, for some messages, so the
// oracle below finds a forged report for every one of them, and none for a
// genuine key.
func TestSmallOrderPublicKeysAreRefused(t *testing.T) {
	for name, enc := range smallOrderEncodings(t) {
		if err := checkPublicKey(enc); err != errSmallOrderPoint {
			t.Errorf("%s (%x): checkPublicKey = %v, want the small-order refusal", name, enc, err)
		}
		if !onCurveOracle(enc) {
			t.Errorf("%s: the oracle says it is off the curve; the fixture is wrong", name)
		}
		if _, forged := forgedReportFor(ed25519.PublicKey(enc)); !forged {
			t.Errorf("%s: Go's ed25519.Verify rejected every forged report; the small-order threat this test guards against did not reproduce", name)
		}
	}
	for name, enc := range nonCanonicalEncodings() {
		if len(enc) != 32 {
			t.Fatalf("%s: fixture is %d bytes", name, len(enc))
		}
		if err := checkPublicKey(enc); err == nil {
			t.Errorf("%s (%x): a non-canonical encoding was accepted", name, enc)
		}
	}
}

// A value that is not a point on the curve can never verify anything; it is
// refused with that reason, and every genuine key passes.
func TestPublicKeysOffTheCurveAreRefusedAndGenuineKeysPass(t *testing.T) {
	refused := 0
	for y := 2; y < 300; y++ {
		enc := make([]byte, 32)
		enc[0], enc[1] = byte(y), byte(y>>8)
		if onCurveOracle(enc) {
			continue
		}
		refused++
		if err := checkPublicKey(enc); err != errNotOnCurve {
			t.Errorf("y=%d: checkPublicKey = %v, want the not-on-curve refusal", y, err)
		}
	}
	if refused == 0 {
		t.Fatal("found no off-curve encoding to test")
	}
	if err := checkPublicKey(append([]byte{2}, make([]byte, 31)...)); err == nil {
		t.Error("02 00..00 (the reporter's example) was accepted")
	}

	for i := 0; i < 300; i++ {
		pub, _ := newKey(t)
		if err := checkPublicKey(pub); err != nil {
			t.Fatalf("genuine key %x refused: %v", pub, err)
		}
		if !onCurveOracle(pub) {
			t.Fatalf("the oracle says genuine key %x is off the curve", pub)
		}
		if i < 20 {
			if _, forged := forgedReportFor(pub); forged {
				t.Fatalf("a report forged with no private key verified under genuine key %x", pub)
			}
		}
	}
	for _, size := range []int{0, 1, 31, 33, 64} {
		if err := checkPublicKey(make([]byte, size)); err == nil {
			t.Errorf("a %d-byte key was accepted", size)
		}
	}
}

// Every input that makes a key a trust anchor refuses these keys: a
// keyring entry (JSON and list), a --public-key style file (hex and raw), an
// inline key, a hand-built keyring, and the key a report embeds, whatever the
// trust set holds. The forged report is one Go's ed25519.Verify accepts.
func TestEveryTrustInputRefusesUnusablePublicKeys(t *testing.T) {
	dir := t.TempDir()
	all := smallOrderEncodings(t)
	for name, enc := range nonCanonicalEncodings() {
		all["non-canonical: "+name] = enc
	}
	all["not a curve point (02 00..00)"] = append([]byte{2}, make([]byte, 31)...)

	for name, enc := range all {
		keyHex := hex.EncodeToString(enc)
		pub := ed25519.PublicKey(enc)

		jsonPath := writeInput(t, dir, "ring.json", []byte(`{"trusted_signers":[{"name":"prod-controller","public_key":"`+keyHex+`"}]}`))
		if kr, err := LoadKeyringFile(jsonPath); err == nil || kr != nil || !strings.Contains(err.Error(), `entry 1 ("prod-controller"): its public key is not a usable Ed25519 key`) {
			t.Errorf("%s: JSON keyring: (%v, %v)", name, kr != nil, err)
		}
		listPath := writeInput(t, dir, "ring.list", []byte("# placeholder\n"+keyHex+"\n"))
		if kr, err := LoadKeyringFile(listPath); err == nil || kr != nil || !strings.Contains(err.Error(), "line 2: its public key is not a usable Ed25519 key") {
			t.Errorf("%s: list keyring: (%v, %v)", name, kr != nil, err)
		}
		if _, err := LoadKeyring(listPath); err == nil {
			t.Errorf("%s: LoadKeyring accepted it", name)
		}
		if key, err := LoadPublicKeyFile(writeInput(t, dir, "hex.pub", []byte(keyHex+"\n"))); err == nil || key != nil {
			t.Errorf("%s: hex public key file: (%x, %v)", name, key, err)
		}
		if len(enc) == ed25519.PublicKeySize {
			if key, err := LoadPublicKeyFile(writeInput(t, dir, "raw.pub", enc)); err == nil || key != nil {
				t.Errorf("%s: raw public key file: (%x, %v)", name, key, err)
			}
		}
		if key, err := ParsePublicKeyHex(keyHex); err == nil || key != nil {
			t.Errorf("%s: ParsePublicKeyHex: (%x, %v)", name, key, err)
		}
		ring := &Keyring{TrustedSigners: []TrustedSigner{{Name: "hand-built", PublicKey: keyHex}}}
		if err := ring.Validate(); err == nil {
			t.Errorf("%s: Validate accepted a hand-built entry", name)
		}
		if keys := ring.PublicKeys(); len(keys) != 0 {
			t.Errorf("%s: PublicKeys kept the entry", name)
		}
		if valid, err := VerifyCanonical([]byte("message"), strings.Repeat("00", 64), pub); valid || err == nil {
			t.Errorf("%s: VerifyCanonical: (%v, %v), want an error", name, valid, err)
		}

		// A report naming this key as its signer is refused, trusted or not.
		if report, forged := forgedReportFor(pub); forged {
			if _, valid, err := VerifyReport(report, []ed25519.PublicKey{pub}); valid || err == nil || !strings.Contains(err.Error(), "not a usable Ed25519 public key") {
				t.Errorf("%s: a forged report verified under a trust set holding its key: valid=%v err=%v", name, valid, err)
			}
			honest, _ := newKey(t)
			if _, valid, err := VerifyReport(report, []ed25519.PublicKey{honest}); valid || err == nil {
				t.Errorf("%s: a forged report verified under an unrelated trust set: valid=%v err=%v", name, valid, err)
			}
			if _, valid, err := VerifyReportSignatureOnly(report); valid || err == nil || !strings.Contains(err.Error(), "not a usable Ed25519 public key") {
				t.Errorf("%s: signature-only verification accepted a forged report: valid=%v err=%v", name, valid, err)
			}
		}
	}
}

// Residual case: VerifyReport(data, sets...) with no set collected is not
// signature-only verification; that has its own name.
func TestVerifyReportWithNoTrustSetIsAnError(t *testing.T) {
	_, stranger := newKey(t)
	report := signedReport(t, stranger)
	var sets [][]ed25519.PublicKey
	if r, valid, err := VerifyReport(report, sets...); err == nil || valid || r != nil || !strings.Contains(err.Error(), "no trusted signer set") {
		t.Fatalf("VerifyReport(data, no sets...) = (%v, %v, %v), want a refusal", r != nil, valid, err)
	}
	if _, valid, err := VerifyReport(report); err == nil || valid {
		t.Fatalf("VerifyReport(data) accepted a stranger's report: valid=%v err=%v", valid, err)
	}
	// Signature-only verification is explicit, and says nothing about the signer.
	if _, valid, err := VerifyReportSignatureOnly(report); err != nil || !valid {
		t.Fatalf("VerifyReportSignatureOnly: valid=%v err=%v", valid, err)
	}
	if _, valid, err := VerifyReport(report, []ed25519.PublicKey{stranger.Public().(ed25519.PublicKey)}); err != nil || !valid {
		t.Fatalf("a trusted signer was refused: valid=%v err=%v", valid, err)
	}
}

// The keyring fixture used across these tests must stay loadable when it holds
// genuine keys only.
func TestKeyringOfGenuineKeysStillLoads(t *testing.T) {
	var lines []string
	for i := 0; i < 5; i++ {
		pub, _ := newKey(t)
		lines = append(lines, hex.EncodeToString(pub))
	}
	path := filepath.Join(t.TempDir(), "ring")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	kr, err := LoadKeyringFile(path)
	if err != nil || len(kr.PublicKeys()) != 5 {
		t.Fatalf("keyring of genuine keys: %v", err)
	}
}
