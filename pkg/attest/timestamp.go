// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// A signature proves that the holder of a key signed a report. It does not
// prove when: the signing key can sign a report today and say it was signed
// last year, and a key that is later stolen or retired can be made to "sign"
// old reports. A trusted timestamp closes that gap. A timestamp authority
// signs a statement that a digest existed at a time, and the statement can be
// checked later without trusting the signer's clock.
//
// This file is the seam where that plugs in, and nothing more: no RFC 3161
// client is implemented here. Community reports carry no timestamp
// (NoTimestamper), and the one implementation here, StubTimestamper, is a
// test double that proves nothing.
//
// The member. A timestamped report carries one more optional member beside its
// signature:
//
//	"signature_timestamp": {
//	  "authority":      "<who issued the token, a string>",
//	  "time":           "<RFC 3339 UTC, as the authority states it>",
//	  "token":          "<base64: the authority's token, opaque to this package>",
//	  "hash_algorithm": "sha256"
//	}
//
// The member is not part of the signed bytes. It timestamps the signature, as
// an RFC 3161 token timestamps whatever it is shown, so it can only be added
// after signing, and a report has the same canonical bytes with it and without
// it (see UnsignedReportMembers). The report's own "timestamp" member is a
// different thing: when the report was built, written by the signer and signed.
//
// The message imprint is the SHA-256 of the signature: of the 64 raw bytes of
// the Ed25519 signature (what the hex "signature" member decodes to), not of
// its hex text and not of the report. Because the signature covers the report,
// a token over the signature shows the whole signed report existed at the
// time. SignatureImprint computes it.
const (
	// TimestampMember is the report member that carries a timestamp token.
	TimestampMember = "signature_timestamp"
	// TimestampHashSHA256 is the only hash_algorithm of a message imprint this
	// release understands.
	TimestampHashSHA256 = "sha256"
	// StubTimestampAuthority is the authority string of a stub token. Anything
	// that sees it must treat the token as no evidence at all.
	StubTimestampAuthority = "stub (not a trust anchor)"

	stubTokenMagic            = "certistack-stub-timestamp-v1"
	maxTimestampAuthorityByte = 256
	maxTimestampTokenBase64   = 256 << 10
)

var (
	// ErrNoTimestamp is what a Timestamper returns when it has no authority to
	// ask: the report is left without the member and nothing has failed.
	ErrNoTimestamp = errors.New("no timestamp authority is configured")
	// ErrTimestampAuthorityUnknown is what a TimestampVerifier returns for a
	// token of an authority it does not handle, so another verifier can be
	// tried. It is not a verdict on the token.
	ErrTimestampAuthorityUnknown = errors.New("this verifier does not handle the token's timestamp authority")
)

// TimestampToken is the signature_timestamp member of a report.
type TimestampToken struct {
	Authority     string `json:"authority"`
	Time          string `json:"time"`
	Token         string `json:"token"`
	HashAlgorithm string `json:"hash_algorithm"`
}

// Timestamper asks a timestamp authority to timestamp a digest, the SHA-256
// imprint of a report's signature (SignatureImprint).
type Timestamper interface {
	Timestamp(ctx context.Context, digest [32]byte) (TimestampToken, error)
}

// TimestampVerifier checks a token against the digest it must cover and
// returns the time the authority attests. A verifier for one authority returns
// ErrTimestampAuthorityUnknown for a token of any other. Any other error is a
// refusal of the token.
type TimestampVerifier interface {
	VerifyTimestamp(token TimestampToken, digest [32]byte) (time.Time, error)
}

// NoTimestamper is the Community default: reports are local, and no authority
// is asked. AttachTimestamp with it leaves the report without the member.
type NoTimestamper struct{}

// Timestamp always returns ErrNoTimestamp.
func (NoTimestamper) Timestamp(context.Context, [32]byte) (TimestampToken, error) {
	return TimestampToken{}, ErrNoTimestamp
}

// StubTimestamper is a test double. Its token is a plain text structure
// (stubTokenMagic, the time and the hex digest, one per line) with no secret
// in it, no signature and no MAC, so anyone can write one for any digest and
// any time. It exists to exercise the member, the imprint check and the
// reporting, and for the fixtures of the verify page. It is never evidence,
// and every verifier in this repository says so (EvaluateTimestamp,
// "verify-report"). Now is the clock; nil means time.Now.
type StubTimestamper struct {
	Now func() time.Time
}

// Timestamp returns a stub token over digest.
func (s StubTimestamper) Timestamp(ctx context.Context, digest [32]byte) (TimestampToken, error) {
	if err := ctx.Err(); err != nil {
		return TimestampToken{}, err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	at := now().UTC().Truncate(time.Second).Format(time.RFC3339)
	raw := stubTokenMagic + "\n" + at + "\n" + hex.EncodeToString(digest[:]) + "\n"
	return TimestampToken{
		Authority:     StubTimestampAuthority,
		Time:          at,
		Token:         base64.StdEncoding.EncodeToString([]byte(raw)),
		HashAlgorithm: TimestampHashSHA256,
	}, nil
}

// StubVerifier checks that a stub token is well formed and covers a digest.
// It returns the time the stub token states, which is whatever its writer
// chose: a nil error from it is not evidence of anything, and EvaluateTimestamp
// never reports a stub token as verified.
type StubVerifier struct{}

// VerifyTimestamp checks a stub token's structure, its time and its imprint.
func (StubVerifier) VerifyTimestamp(token TimestampToken, digest [32]byte) (time.Time, error) {
	if token.Authority != StubTimestampAuthority {
		return time.Time{}, ErrTimestampAuthorityUnknown
	}
	if token.HashAlgorithm != TimestampHashSHA256 {
		return time.Time{}, fmt.Errorf("stub token: hash_algorithm %q is not %s", token.HashAlgorithm, TimestampHashSHA256)
	}
	raw, err := base64.StdEncoding.DecodeString(token.Token)
	if err != nil {
		return time.Time{}, fmt.Errorf("stub token is not base64: %w", err)
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) != 4 || lines[3] != "" || lines[0] != stubTokenMagic {
		return time.Time{}, errors.New("stub token is not a certistack stub token")
	}
	at, err := parseTimestampTime(lines[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("stub token: %w", err)
	}
	if lines[1] != token.Time {
		return time.Time{}, fmt.Errorf("stub token states %s, but the member's time is %s", lines[1], token.Time)
	}
	if want := hex.EncodeToString(digest[:]); lines[2] != want {
		return time.Time{}, fmt.Errorf("the stub token does not cover this signature (its imprint is %s, the signature's is %s)", lines[2], want)
	}
	return at, nil
}

// SignatureImprint returns the message imprint of a report: the SHA-256 of the
// raw bytes of the Ed25519 signature given as hex.
func SignatureImprint(sigHex string) ([32]byte, error) {
	raw, err := hex.DecodeString(sigHex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("the signature is not hexadecimal: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return [32]byte{}, fmt.Errorf("the signature is %d bytes, not %d", len(raw), ed25519.SignatureSize)
	}
	return sha256.Sum256(raw), nil
}

// parseTimestampTime reads the RFC 3339 UTC time of a timestamp member.
func parseTimestampTime(text string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}, fmt.Errorf("time %q is not an RFC 3339 time", boundedText(text))
	}
	if !strings.HasSuffix(text, "Z") {
		return time.Time{}, fmt.Errorf("time %q must be UTC (end in Z)", boundedText(text))
	}
	return parsed.UTC(), nil
}

func boundedText(text string) string {
	if len(text) > 64 {
		return text[:64] + "..."
	}
	return text
}

// Validate checks the token's shape: a printable authority, an RFC 3339 UTC
// time, a base64 token, and the one hash algorithm supported (sha256).
// It does not check that the token covers anything; that is a verifier's job.
func (t TimestampToken) Validate() error {
	if t.Authority == "" {
		return errors.New("authority is empty")
	}
	if len(t.Authority) > maxTimestampAuthorityByte || !utf8.ValidString(t.Authority) {
		return fmt.Errorf("authority is not valid text of at most %d bytes", maxTimestampAuthorityByte)
	}
	for _, r := range t.Authority {
		if unicode.IsControl(r) {
			return errors.New("authority holds a control character")
		}
	}
	if _, err := parseTimestampTime(t.Time); err != nil {
		return err
	}
	if t.Token == "" {
		return errors.New("token is empty")
	}
	if len(t.Token) > maxTimestampTokenBase64 {
		return fmt.Errorf("token is larger than %d bytes", maxTimestampTokenBase64)
	}
	if _, err := base64.StdEncoding.DecodeString(t.Token); err != nil {
		return errors.New("token is not base64")
	}
	if t.HashAlgorithm != TimestampHashSHA256 {
		return fmt.Errorf("hash_algorithm %q is not understood: this release timestamps only a %s imprint of the signature", boundedText(t.HashAlgorithm), TimestampHashSHA256)
	}
	return nil
}

// timestampMemberNames are the members of signature_timestamp, in the order
// they are checked.
var timestampMemberNames = []string{"authority", "time", "token", "hash_algorithm"}

// parseTimestampMember reads the decoded signature_timestamp member of a
// report document. The member is unsigned, so it is read strictly: an object
// of exactly the four members, each a string, and a valid token.
func parseTimestampMember(value interface{}) (*TimestampToken, error) {
	object, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an object with authority, time, token and hash_algorithm", TimestampMember)
	}
	var unknown []string
	for name := range object {
		known := false
		for _, want := range timestampMemberNames {
			known = known || name == want
		}
		if !known {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("%s has an unknown member %q: a verifier that does not know it cannot judge the timestamp", TimestampMember, boundedText(unknown[0]))
	}
	fields := make(map[string]string, len(timestampMemberNames))
	for _, name := range timestampMemberNames {
		raw, present := object[name]
		if !present {
			return nil, fmt.Errorf("%s is missing %s", TimestampMember, name)
		}
		text, isString := raw.(string)
		if !isString {
			return nil, fmt.Errorf("%s: %s must be a string", TimestampMember, name)
		}
		fields[name] = text
	}
	token := &TimestampToken{Authority: fields["authority"], Time: fields["time"], Token: fields["token"], HashAlgorithm: fields["hash_algorithm"]}
	if err := token.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", TimestampMember, err)
	}
	return token, nil
}

// AttachTimestamp asks ts to timestamp the report's signature and records the
// token as the report's signature_timestamp. The report must already be signed
// (the timestamp is over the signature), and signing it again drops the token,
// because it would cover the old signature. A Timestamper that returns
// ErrNoTimestamp (NoTimestamper) leaves the report as it is, without an error.
// A token that is not well formed is refused, and nothing is attached.
func (r *Report) AttachTimestamp(ctx context.Context, ts Timestamper) error {
	if ts == nil {
		return errors.New("no Timestamper given: pass NoTimestamper{} to attach none")
	}
	if r.Signature == "" {
		return errors.New("cannot timestamp an unsigned report: the timestamp is over the signature")
	}
	digest, err := SignatureImprint(r.Signature)
	if err != nil {
		return fmt.Errorf("cannot timestamp the report: %w", err)
	}
	token, err := ts.Timestamp(ctx, digest)
	if errors.Is(err, ErrNoTimestamp) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("timestamp the report signature: %w", err)
	}
	if err := token.Validate(); err != nil {
		return fmt.Errorf("the timestamp authority returned a token that is not well formed: %w", err)
	}
	r.SignatureTimestamp = &token
	return nil
}

// TimestampState is what a verifier can say about a report's timestamp.
type TimestampState string

const (
	// TimestampNone: the report carries no signature_timestamp.
	TimestampNone TimestampState = "none"
	// TimestampStub: the member is a stub token, which anyone can forge. It is
	// never evidence.
	TimestampStub TimestampState = "stub"
	// TimestampUnverified: the member is well formed, but no configured
	// verifier handles its authority, so it proves nothing here.
	TimestampUnverified TimestampState = "unverified"
	// TimestampVerified: a configured verifier accepted the token for this
	// report's signature. This is the only state that is evidence.
	TimestampVerified TimestampState = "verified"
)

// TimestampStatus is the result of EvaluateTimestamp.
type TimestampStatus struct {
	State     TimestampState
	Authority string
	// ClaimedTime is the time the member states. Unless State is
	// TimestampVerified it is the writer's claim and proves nothing.
	ClaimedTime string
	// VerifiedTime is the time a verifier attested; zero unless State is
	// TimestampVerified.
	VerifiedTime time.Time
}

// Evidence reports whether the timestamp proves the signature existed at a
// time. Only a verified token does.
func (s TimestampStatus) Evidence() bool { return s.State == TimestampVerified }

// Describe is the one-line account of the status the verifier prints.
func (s TimestampStatus) Describe() string {
	switch s.State {
	case TimestampStub:
		return fmt.Sprintf("stub timestamp, NOT evidence (authority %q; a stub holds no secret, so anyone can forge one)", s.Authority)
	case TimestampUnverified:
		return fmt.Sprintf("present, not verified (this build has no verifier for authority %q, so it is not evidence here)", s.Authority)
	case TimestampVerified:
		return fmt.Sprintf("verified at %s by %s", s.VerifiedTime.UTC().Format(time.RFC3339), s.Authority)
	default:
		return "none"
	}
}

// EvaluateTimestamp judges the signature_timestamp of a verified report. A
// report without one is TimestampNone. A stub token is checked for its shape
// and imprint and is always TimestampStub, whatever verifiers are given. Any
// other token goes to the verifiers in turn: one that returns
// ErrTimestampAuthorityUnknown is passed over, one that accepts makes it
// TimestampVerified, and one that refuses makes the whole report a refusal. If
// none handles the authority the token is TimestampUnverified.
//
// A token that does not cover the report's signature is an error, not an
// unverified timestamp: someone attached a timestamp of another signature.
func EvaluateTimestamp(r *Report, verifiers ...TimestampVerifier) (TimestampStatus, error) {
	if r == nil || r.SignatureTimestamp == nil {
		return TimestampStatus{State: TimestampNone}, nil
	}
	token := *r.SignatureTimestamp
	if err := token.Validate(); err != nil {
		return TimestampStatus{}, fmt.Errorf("%s: %w", TimestampMember, err)
	}
	digest, err := SignatureImprint(r.Signature)
	if err != nil {
		return TimestampStatus{}, fmt.Errorf("%s: %w", TimestampMember, err)
	}
	status := TimestampStatus{State: TimestampUnverified, Authority: token.Authority, ClaimedTime: token.Time}
	if token.Authority == StubTimestampAuthority {
		if _, err := (StubVerifier{}).VerifyTimestamp(token, digest); err != nil {
			return TimestampStatus{}, fmt.Errorf("%s: %w", TimestampMember, err)
		}
		status.State = TimestampStub
		return status, nil
	}
	for _, verifier := range verifiers {
		if verifier == nil {
			continue
		}
		at, err := verifier.VerifyTimestamp(token, digest)
		if errors.Is(err, ErrTimestampAuthorityUnknown) {
			continue
		}
		if err != nil {
			return TimestampStatus{}, fmt.Errorf("%s by %s is refused: %w", TimestampMember, boundedText(token.Authority), err)
		}
		status.State = TimestampVerified
		status.VerifiedTime = at.UTC()
		return status, nil
	}
	return status, nil
}

// unsignedReportMembers are the members of a report document that the
// signature does not cover: the signing block, and the timestamp of the
// signature. Canonicalization drops them (and only them) before it signs or
// verifies, so a report is the same canonical bytes with them and without.
// Every consumer of the list, the signer, the verifier and any other
// implementation of the signature check, must drop the same four.
var unsignedReportMembers = [...]string{"signature", "public_key", "signer_fingerprint", TimestampMember}

// UnsignedReportMembers returns the members dropped from a report before its
// canonical bytes are signed or verified.
func UnsignedReportMembers() []string {
	return append([]string(nil), unsignedReportMembers[:]...)
}
