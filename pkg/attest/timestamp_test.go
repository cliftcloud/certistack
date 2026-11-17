// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

var timestampTestTime = time.Date(2026, 10, 2, 12, 30, 0, 0, time.UTC)

func fixedStub() StubTimestamper {
	return StubTimestamper{Now: func() time.Time { return timestampTestTime }}
}

// signedTimestampTestReport returns a freshly signed report (no timestamp) and
// the key that signed it.
func signedTimestampTestReport(t *testing.T, planID string) (*Report, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := BuildReport(&config.Plan{PlanID: planID}, "node.example.invalid", 5*time.Second, true, nil, "")
	if err := report.SignReport(key); err != nil {
		t.Fatal(err)
	}
	return report, key
}

func marshalReport(t *testing.T, report *Report) []byte {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// withMember returns the report document with one member set to value (a
// value json.Marshal accepts); nil deletes the member.
func withMember(t *testing.T, document []byte, name string, value interface{}) []byte {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(document, &members); err != nil {
		t.Fatal(err)
	}
	if value == nil {
		delete(members, name)
	} else {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		members[name] = raw
	}
	out, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func stampedReport(t *testing.T, planID string) (*Report, ed25519.PrivateKey) {
	t.Helper()
	report, key := signedTimestampTestReport(t, planID)
	if err := report.AttachTimestamp(context.Background(), fixedStub()); err != nil {
		t.Fatal(err)
	}
	if report.SignatureTimestamp == nil {
		t.Fatal("AttachTimestamp with the stub left no signature_timestamp")
	}
	return report, key
}

// The timestamp is carried beside the signature and is not signed: a report
// with it and the same report without it have the same canonical bytes, so a
// signature made before the timestamp existed still verifies after it.
func TestTimestamp_NotPartOfTheSignedBytes(t *testing.T) {
	report, _ := stampedReport(t, "ts-canonical")
	withStamp := marshalReport(t, report)
	withoutStamp := withMember(t, withStamp, TimestampMember, nil)
	if bytes.Equal(withStamp, withoutStamp) {
		t.Fatal("test setup: the document with the timestamp equals the one without")
	}

	canonicalWith, err := CanonicalizeReportJSON(withStamp)
	if err != nil {
		t.Fatal(err)
	}
	canonicalWithout, err := CanonicalizeReportJSON(withoutStamp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonicalWith, canonicalWithout) {
		t.Fatalf("the timestamp changed the canonical bytes:\nwith:    %s\nwithout: %s", canonicalWith, canonicalWithout)
	}
	if bytes.Contains(canonicalWith, []byte(TimestampMember)) || bytes.Contains(canonicalWith, []byte("stub")) {
		t.Errorf("the canonical bytes carry the timestamp: %s", canonicalWith)
	}
}

// Every unsigned member can be dropped or changed without touching the signed
// bytes, and no other member can: the list is exactly the four.
func TestUnsignedReportMembers_AreExactlyTheSigningBlockAndTheTimestamp(t *testing.T) {
	want := []string{"signature", "public_key", "signer_fingerprint", "signature_timestamp"}
	if got := UnsignedReportMembers(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("UnsignedReportMembers = %v, want %v", got, want)
	}

	report, _ := stampedReport(t, "ts-unsigned-list")
	document := marshalReport(t, report)
	base, err := CanonicalizeReportJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range want {
		for name, changed := range map[string][]byte{
			"removed": withMember(t, document, member, nil),
			"changed": withMember(t, document, member, "changed"),
		} {
			got, err := CanonicalizeReportJSON(changed)
			if err != nil {
				t.Fatalf("%s %s: %v", member, name, err)
			}
			if !bytes.Equal(got, base) {
				t.Errorf("%s %s: the canonical bytes changed, so the member is signed", member, name)
			}
		}
	}
	for _, member := range []string{"report_id", "plan_id", "all_passed", "timestamp", "rto_seconds"} {
		got, err := CanonicalizeReportJSON(withMember(t, document, member, "changed"))
		if err != nil {
			t.Fatalf("%s: %v", member, err)
		}
		if bytes.Equal(got, base) {
			t.Errorf("%s: changing the member left the canonical bytes alone, so it is not signed", member)
		}
	}
}

func TestVerifyReport_WithoutTimestampBehavesAsBefore(t *testing.T) {
	report, _ := signedTimestampTestReport(t, "ts-none")
	verified, valid, err := VerifyReportSignatureOnly(marshalReport(t, report))
	if err != nil || !valid {
		t.Fatalf("an untimestamped report: valid=%v err=%v", valid, err)
	}
	if verified.SignatureTimestamp != nil {
		t.Errorf("an untimestamped report decoded with a timestamp: %+v", verified.SignatureTimestamp)
	}
	status, err := EvaluateTimestamp(verified)
	if err != nil || status.State != TimestampNone || status.Evidence() {
		t.Errorf("EvaluateTimestamp of an untimestamped report = %+v, %v; want none", status, err)
	}
}

func TestVerifyReport_AcceptsAStubTimestampAndKeepsTheSignatureValid(t *testing.T) {
	report, key := stampedReport(t, "ts-stub")
	public := key.Public().(ed25519.PublicKey)

	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := report.Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"signature_timestamp"`)) {
		t.Fatalf("the saved report lacks the member:\n%s", data)
	}

	verified, valid, err := VerifyReport(data, []ed25519.PublicKey{public})
	if err != nil || !valid {
		t.Fatalf("a stub-timestamped report: valid=%v err=%v", valid, err)
	}
	if verified.SignatureTimestamp == nil || *verified.SignatureTimestamp != *report.SignatureTimestamp {
		t.Fatalf("the verified report's timestamp = %+v, want %+v", verified.SignatureTimestamp, report.SignatureTimestamp)
	}
	if got := verified.SignatureTimestamp.HashAlgorithm; got != "sha256" {
		t.Errorf("hash_algorithm = %q, want sha256", got)
	}
	if got := verified.SignatureTimestamp.Authority; got != StubTimestampAuthority {
		t.Errorf("authority = %q, want %q", got, StubTimestampAuthority)
	}
}

// A timestamp never rescues a bad signature: the signature is judged first,
// whatever the timestamp looks like.
func TestVerifyReport_TamperedSignatureWithAValidLookingTimestampStillFails(t *testing.T) {
	report, _ := stampedReport(t, "ts-tampered")
	document := marshalReport(t, report)

	changed := withMember(t, document, "plan_id", "someone-elses-plan")
	if _, valid, err := VerifyReportSignatureOnly(changed); !errors.Is(err, ErrInvalidSignature) || valid {
		t.Fatalf("a changed signed member behind a timestamp: valid=%v err=%v, want ErrInvalidSignature", valid, err)
	}

	// A different signature with a timestamp made for the original: the
	// signature fails first; the timestamp is not consulted.
	other, _ := signedTimestampTestReport(t, "ts-tampered")
	swapped := withMember(t, document, "signature", other.Signature)
	if _, valid, err := VerifyReportSignatureOnly(swapped); !errors.Is(err, ErrInvalidSignature) || valid {
		t.Fatalf("a replaced signature behind a timestamp: valid=%v err=%v, want ErrInvalidSignature", valid, err)
	}
}

func TestStubVerifier_RejectsATokenOverADifferentSignature(t *testing.T) {
	a, _ := stampedReport(t, "ts-a")
	b, _ := signedTimestampTestReport(t, "ts-b")
	digestA, err := SignatureImprint(a.Signature)
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := SignatureImprint(b.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if digestA == digestB {
		t.Fatal("two reports signed with different keys have the same imprint")
	}

	if _, err := (StubVerifier{}).VerifyTimestamp(*a.SignatureTimestamp, digestA); err != nil {
		t.Fatalf("the stub verifier rejects its own token: %v", err)
	}
	_, err = (StubVerifier{}).VerifyTimestamp(*a.SignatureTimestamp, digestB)
	if err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("a token over another signature: err = %v, want a refusal saying it does not cover the signature", err)
	}

	// The same through the report: a's token attached to b is a refusal.
	b.SignatureTimestamp = a.SignatureTimestamp
	if _, err := EvaluateTimestamp(b); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("EvaluateTimestamp of a report carrying another report's token: err = %v", err)
	}
}

func TestVerifyReport_RefusesAMalformedTimestampMember(t *testing.T) {
	report, _ := stampedReport(t, "ts-malformed")
	document := marshalReport(t, report)
	good := *report.SignatureTimestamp

	member := func(change func(map[string]interface{})) interface{} {
		m := map[string]interface{}{
			"authority": good.Authority, "time": good.Time, "token": good.Token, "hash_algorithm": good.HashAlgorithm,
		}
		change(m)
		return m
	}
	cases := []struct {
		name  string
		value interface{}
		want  string
	}{
		{"a string", "yesterday", "must be an object"},
		{"an array", []string{"a"}, "must be an object"},
		{"a number", 7, "must be an object"},
		{"an empty object", map[string]interface{}{}, "missing authority"},
		{"no authority", member(func(m map[string]interface{}) { delete(m, "authority") }), "missing authority"},
		{"no time", member(func(m map[string]interface{}) { delete(m, "time") }), "missing time"},
		{"no token", member(func(m map[string]interface{}) { delete(m, "token") }), "missing token"},
		{"no hash_algorithm", member(func(m map[string]interface{}) { delete(m, "hash_algorithm") }), "missing hash_algorithm"},
		{"a number for the authority", member(func(m map[string]interface{}) { m["authority"] = 5 }), "authority must be a string"},
		{"an empty authority", member(func(m map[string]interface{}) { m["authority"] = "" }), "authority is empty"},
		{"a control character in the authority", member(func(m map[string]interface{}) { m["authority"] = "tsa\x1b[31m" }), "authority holds a control character"},
		{"a time that is not RFC 3339", member(func(m map[string]interface{}) { m["time"] = "2 Oct 2026" }), "not an RFC 3339 time"},
		{"a time with an offset", member(func(m map[string]interface{}) { m["time"] = "2026-10-02T14:30:00+02:00" }), "must be UTC"},
		{"a token that is not base64", member(func(m map[string]interface{}) { m["token"] = "not base64 !!" }), "token is not base64"},
		{"an empty token", member(func(m map[string]interface{}) { m["token"] = "" }), "token is empty"},
		{"an unknown member", member(func(m map[string]interface{}) { m["nonce"] = "x" }), `unknown member "nonce"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, valid, err := VerifyReportSignatureOnly(withMember(t, document, TimestampMember, tc.value))
			if err == nil || valid {
				t.Fatalf("a malformed signature_timestamp (%s) was accepted: valid=%v err=%v", tc.name, valid, err)
			}
			if !strings.Contains(err.Error(), TimestampMember) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %s and say %q", err, TimestampMember, tc.want)
			}
			if errors.Is(err, ErrInvalidSignature) {
				t.Errorf("a malformed timestamp is reported as an invalid signature: %v", err)
			}
		})
	}

	// JSON null is not "absent": the member is there and says nothing.
	bare := withMember(t, document, TimestampMember, nil)
	if _, _, err := VerifyReportSignatureOnly(append(bytes.TrimSuffix(bare, []byte("}")), []byte(`,"signature_timestamp":null}`)...)); err == nil || !strings.Contains(err.Error(), "must be an object") {
		t.Errorf("signature_timestamp: null: err = %v, want a refusal", err)
	}
}

func TestVerifyReport_RefusesAnUnknownHashAlgorithm(t *testing.T) {
	report, _ := stampedReport(t, "ts-hash")
	document := marshalReport(t, report)
	for _, algorithm := range []string{"sha1", "SHA256", "sha-256", "sha384", "md5", "", " sha256"} {
		bad := *report.SignatureTimestamp
		bad.HashAlgorithm = algorithm
		_, valid, err := VerifyReportSignatureOnly(withMember(t, document, TimestampMember, bad))
		if err == nil || valid {
			t.Errorf("hash_algorithm %q was accepted: valid=%v err=%v", algorithm, valid, err)
			continue
		}
		if !strings.Contains(err.Error(), "hash_algorithm") || !strings.Contains(err.Error(), "sha256") {
			t.Errorf("hash_algorithm %q: error = %q, want it to name hash_algorithm and say only sha256 is understood", algorithm, err)
		}
	}
}

func TestSignatureImprint_IsSHA256OfTheRawSignatureBytes(t *testing.T) {
	report, _ := signedTimestampTestReport(t, "ts-imprint")
	raw, err := hex.DecodeString(report.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		t.Fatalf("test setup: signature %q", report.Signature)
	}
	got, err := SignatureImprint(report.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(raw); got != want {
		t.Errorf("imprint = %x, want SHA-256 of the 64 raw signature bytes %x", got, want)
	}
	if wrong := sha256.Sum256([]byte(report.Signature)); got == wrong {
		t.Error("imprint is the SHA-256 of the signature's hex text, not of its bytes")
	}
	for _, bad := range []string{"", "zz", strings.Repeat("ab", 63), strings.Repeat("ab", 65)} {
		if _, err := SignatureImprint(bad); err == nil {
			t.Errorf("SignatureImprint(%q) did not fail", bad)
		}
	}
}

func TestSignReport_DropsAStaleTimestamp(t *testing.T) {
	report, key := stampedReport(t, "ts-stale")
	if err := report.SignReport(key); err != nil {
		t.Fatal(err)
	}
	if report.SignatureTimestamp != nil {
		t.Fatal("a second signature kept the timestamp of the first")
	}
	if bytes.Contains(marshalReport(t, report), []byte(TimestampMember)) {
		t.Error("the re-signed report still carries signature_timestamp")
	}
}

func TestNoTimestamper_IsTheCommunityDefaultAndAttachesNothing(t *testing.T) {
	report, _ := signedTimestampTestReport(t, "ts-no")
	if _, err := (NoTimestamper{}).Timestamp(context.Background(), [32]byte{}); !errors.Is(err, ErrNoTimestamp) {
		t.Errorf("NoTimestamper.Timestamp error = %v, want ErrNoTimestamp", err)
	}
	if err := report.AttachTimestamp(context.Background(), NoTimestamper{}); err != nil {
		t.Fatalf("attaching with NoTimestamper is an error: %v", err)
	}
	if report.SignatureTimestamp != nil || bytes.Contains(marshalReport(t, report), []byte(TimestampMember)) {
		t.Error("NoTimestamper left a signature_timestamp member")
	}
	var _ Timestamper = NoTimestamper{}
	var _ Timestamper = StubTimestamper{}
	var _ TimestampVerifier = StubVerifier{}
}

func TestAttachTimestamp_RefusesWhatCannotBeStamped(t *testing.T) {
	unsigned := BuildReport(&config.Plan{PlanID: "ts-unsigned"}, "node.example.invalid", time.Second, true, nil, "")
	if err := unsigned.AttachTimestamp(context.Background(), fixedStub()); err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Errorf("stamping an unsigned report: err = %v", err)
	}

	report, _ := signedTimestampTestReport(t, "ts-failing")
	failing := timestamperFunc(func(context.Context, [32]byte) (TimestampToken, error) {
		return TimestampToken{}, errors.New("the authority is down")
	})
	if err := report.AttachTimestamp(context.Background(), failing); err == nil || !strings.Contains(err.Error(), "the authority is down") {
		t.Errorf("a failing authority: err = %v", err)
	}
	if report.SignatureTimestamp != nil {
		t.Error("a failed timestamp left a member")
	}

	badToken := timestamperFunc(func(context.Context, [32]byte) (TimestampToken, error) {
		return TimestampToken{Authority: "x", Time: "soon", Token: "AAAA", HashAlgorithm: "sha256"}, nil
	})
	if err := report.AttachTimestamp(context.Background(), badToken); err == nil {
		t.Error("an authority that returned a malformed token was accepted")
	}
	if report.SignatureTimestamp != nil {
		t.Error("a malformed token was attached")
	}

	if err := report.AttachTimestamp(context.Background(), nil); err == nil {
		t.Error("a nil Timestamper was accepted")
	}
}

type timestamperFunc func(context.Context, [32]byte) (TimestampToken, error)

func (f timestamperFunc) Timestamp(ctx context.Context, digest [32]byte) (TimestampToken, error) {
	return f(ctx, digest)
}

// The stub is deterministic and holds no secret: anyone can write one, which is
// why it is never evidence.
func TestStubTimestamper_IsDeterministicAndForgeableByAnyone(t *testing.T) {
	report, _ := signedTimestampTestReport(t, "ts-forge")
	digest, _ := SignatureImprint(report.Signature)

	one, err := fixedStub().Timestamp(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	two, _ := fixedStub().Timestamp(context.Background(), digest)
	if one != two {
		t.Errorf("the stub is not deterministic: %+v vs %+v", one, two)
	}
	if one.Authority != StubTimestampAuthority || one.HashAlgorithm != "sha256" || one.Time != "2026-10-02T12:30:00Z" {
		t.Errorf("stub token = %+v", one)
	}

	// Forged by hand from the documented layout, with no code of the package.
	layout := "certistack-stub-timestamp-v1\n2000-01-01T00:00:00Z\n" + hex.EncodeToString(digest[:]) + "\n"
	forged := TimestampToken{Authority: StubTimestampAuthority, Time: "2000-01-01T00:00:00Z", Token: base64.StdEncoding.EncodeToString([]byte(layout)), HashAlgorithm: "sha256"}
	got, err := (StubVerifier{}).VerifyTimestamp(forged, digest)
	if err != nil || !got.Equal(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("a hand-made stub token: %v, %v", got, err)
	}

	// The time in the token and the time beside it must agree.
	disagreeing := forged
	disagreeing.Time = "2030-01-01T00:00:00Z"
	if _, err := (StubVerifier{}).VerifyTimestamp(disagreeing, digest); err == nil {
		t.Error("a stub token whose time disagrees with its member was accepted")
	}
	// A token of another authority is not the stub's to judge.
	foreign := forged
	foreign.Authority = "tsa.example.invalid"
	if _, err := (StubVerifier{}).VerifyTimestamp(foreign, digest); !errors.Is(err, ErrTimestampAuthorityUnknown) {
		t.Errorf("the stub verifier on another authority's token: err = %v, want ErrTimestampAuthorityUnknown", err)
	}
	// Garbage in the token is a refusal, not a panic.
	for _, token := range []string{"AAAA", base64.StdEncoding.EncodeToString([]byte("certistack-stub-timestamp-v1\n")), base64.StdEncoding.EncodeToString([]byte("other\nx\ny\n"))} {
		bad := forged
		bad.Token = token
		if _, err := (StubVerifier{}).VerifyTimestamp(bad, digest); err == nil {
			t.Errorf("stub token %q was accepted", token)
		}
	}
}

type fakeVerifier struct {
	authority string
	at        time.Time
	err       error
}

func (f fakeVerifier) VerifyTimestamp(token TimestampToken, digest [32]byte) (time.Time, error) {
	if token.Authority != f.authority {
		return time.Time{}, ErrTimestampAuthorityUnknown
	}
	return f.at, f.err
}

func TestEvaluateTimestamp_StatesAndNeverCountsTheStubAsEvidence(t *testing.T) {
	stamped, _ := stampedReport(t, "ts-eval")

	// The stub is stub: with no verifier, and even when the stub verifier is
	// configured as if it were a real one.
	for name, verifiers := range map[string][]TimestampVerifier{
		"no verifier":            nil,
		"the stub verifier":      {StubVerifier{}},
		"a verifier of the stub": {fakeVerifier{authority: StubTimestampAuthority, at: timestampTestTime}},
	} {
		status, err := EvaluateTimestamp(stamped, verifiers...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if status.State != TimestampStub || status.Evidence() {
			t.Errorf("%s: status = %+v, want the stub state and no evidence", name, status)
		}
		if !strings.Contains(status.Describe(), "stub timestamp, NOT evidence") {
			t.Errorf("%s: description = %q", name, status.Describe())
		}
		if !status.VerifiedTime.IsZero() {
			t.Errorf("%s: a stub carries a verified time: %v", name, status.VerifiedTime)
		}
	}

	// An authority this build has no verifier for: present, not verified.
	foreign, _ := signedTimestampTestReport(t, "ts-foreign")
	digest, _ := SignatureImprint(foreign.Signature)
	foreign.SignatureTimestamp = &TimestampToken{Authority: "tsa.example.invalid", Time: "2026-10-02T09:00:00Z", Token: base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), HashAlgorithm: "sha256"}
	_ = digest
	status, err := EvaluateTimestamp(foreign)
	if err != nil || status.State != TimestampUnverified || status.Evidence() {
		t.Fatalf("a foreign token with no verifier: %+v, %v", status, err)
	}
	if d := status.Describe(); !strings.Contains(d, "not verified") || !strings.Contains(d, "tsa.example.invalid") {
		t.Errorf("description = %q", d)
	}
	// A verifier for some other authority does not verify it either.
	if status, err = EvaluateTimestamp(foreign, fakeVerifier{authority: "other.example.invalid", at: timestampTestTime}); err != nil || status.State != TimestampUnverified {
		t.Errorf("a verifier of another authority: %+v, %v", status, err)
	}

	// A configured verifier that accepts it: verified, with the verifier's time.
	verifiedAt := time.Date(2026, 10, 2, 9, 0, 1, 0, time.UTC)
	status, err = EvaluateTimestamp(foreign, fakeVerifier{authority: "tsa.example.invalid", at: verifiedAt})
	if err != nil || status.State != TimestampVerified || !status.Evidence() || !status.VerifiedTime.Equal(verifiedAt) {
		t.Fatalf("an accepting verifier: %+v, %v", status, err)
	}
	if d := status.Describe(); !strings.HasPrefix(d, "verified at 2026-10-02T09:00:01Z by tsa.example.invalid") {
		t.Errorf("description = %q", d)
	}

	// A verifier that refuses it makes the report a refusal, not an unverified
	// timestamp.
	if _, err = EvaluateTimestamp(foreign, fakeVerifier{authority: "tsa.example.invalid", err: errors.New("bad token")}); err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Errorf("a refusing verifier: err = %v", err)
	}
}
