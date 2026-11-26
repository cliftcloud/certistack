// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// Signer attests a finished report. The Community Edition has none: its reports are written unsigned.
// The Enterprise Edition supplies one.
type Signer interface {
	// SignReport sets the report's signature members, over its canonical form, or returns an error.
	SignReport(report *Report) error
}

// CanonicalForm is the report in the form a signature covers: RFC 8785 canonical
// JSON of the whole report with only the unsigned members (signature,
// public_key, signer_fingerprint and signature_timestamp, see
// UnsignedReportMembers) left out. A Signer signs exactly these bytes, and
// verify-report verifies a signature against exactly these bytes, so the result
// does not depend on whether the report carries a signature already. A report
// over the size or structure limits of MaxReportFileBytes is an error.
func (r *Report) CanonicalForm() ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report for signing: %w", err)
	}
	canonical, err := CanonicalizeReportJSON(data)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize report: %w", err)
	}
	return canonical, nil
}

// AttachSignature sets the report's signature members from hexSignature, a
// signature made with the private key of publicKey over r.CanonicalForm(): the
// signature, the public key and the signer's fingerprint, consistently. Any
// timestamp the report carried covered an earlier signature, so it is dropped.
//
// The signature is checked before it is attached, with the verifier's own
// checks: a signature over other bytes, by another key, of the wrong length or
// not in hexadecimal, and a public key that cannot anchor trust (the wrong size,
// not on the curve, or of small order), are errors that leave the report
// unchanged. A report is therefore never given a signature that verify-report
// would refuse, and the report is not to be changed between the signing and this
// call, because everything but the unsigned members is signed.
func (r *Report) AttachSignature(hexSignature string, publicKey ed25519.PublicKey) error {
	canonical, err := r.CanonicalForm()
	if err != nil {
		return fmt.Errorf("cannot attach a signature: %w", err)
	}
	signature, err := hex.DecodeString(hexSignature)
	if err != nil {
		return fmt.Errorf("cannot attach a signature: it is not hexadecimal: %w", err)
	}
	valid, err := VerifyCanonical(canonical, hexSignature, publicKey)
	if err != nil {
		return fmt.Errorf("cannot attach a signature: %w", err)
	}
	if !valid {
		return errors.New("cannot attach a signature: it does not verify against the report's canonical form (CanonicalForm) under the given public key; sign those bytes with the private key of that public key, after the last change to the report")
	}
	r.Signature = hex.EncodeToString(signature)
	r.PublicKey = hex.EncodeToString(publicKey)
	r.SignerFingerprint = Fingerprint(publicKey)
	r.SignatureTimestamp = nil
	return nil
}

// isNilSigner is whether signer is nil: a nil interface, or an interface that
// holds a nil pointer, which a call could dereference.
func isNilSigner(signer Signer) bool {
	if signer == nil {
		return true
	}
	switch value := reflect.ValueOf(signer); value.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Interface, reflect.Chan:
		return value.IsNil()
	}
	return false
}

// callSigner calls signer.SignReport and turns a panic into an error, so that a
// failing signer fails the call and does not bring the process down after the
// run's node was cleaned up and before its report was written.
func callSigner(signer Signer, report *Report) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("the signer panicked: %v", recovered)
		}
	}()
	return signer.SignReport(report)
}

// restoreReport puts back the report as snapshot (its JSON, taken before the
// signer was called) has it, with no signature members: a signer that failed or
// that rewrote the report leaves neither a half-signed nor a rewritten one.
func restoreReport(report *Report, snapshot []byte) {
	*report = Report{}
	if err := json.Unmarshal(snapshot, report); err != nil {
		// The snapshot is this package's own marshaling of a Report.
		report.clearSignature()
		return
	}
	report.clearSignature()
}

// clearSignature removes every signature member from the report.
func (r *Report) clearSignature() {
	r.Signature, r.PublicKey, r.SignerFingerprint = "", "", ""
	r.SignatureTimestamp = nil
}

// ApplySigner has signer attest the finished report, once. With no signer (a nil
// interface) it signs nothing and leaves the report unsigned: that is the
// Community Edition, which has no signer. The report then carries no signature
// members, even if it arrived with some, as one decoded from a node worker's
// result can, so a saved report never carries signature members unless a Signer
// put them there. A signer that is an interface holding a nil pointer is an
// error, not "no signer".
//
// Whoever signs a report calls this one function, so the rule is made once: a
// signer that returns an error, that returns without signing, or that leaves a
// signature that does not verify under the public key the report carries, fails
// the call and leaves the report with no signature members at all. A report is
// never left half signed.
func ApplySigner(report *Report, signer Signer) error {
	if signer == nil {
		if report != nil {
			report.clearSignature()
		}
		return nil
	}
	if isNilSigner(signer) {
		// An interface that holds a nil pointer is a signer that was meant to
		// sign and holds nothing to sign with (a controller whose key is missing).
		// It is not "no signer": the run fails rather than finish unsigned.
		if report != nil {
			report.clearSignature()
		}
		return errors.New("a signer was supplied but holds nothing to sign with (a nil signer): the report is left unsigned and the run must not count it as signed")
	}
	if report == nil {
		return errors.New("there is no report to sign")
	}
	// Signing is over the report's whole content, so a signature left from an
	// earlier signing is not carried into this one.
	report.clearSignature()
	// What the signer is asked to attest: the content the controller checked. A
	// signer attests it; it does not rewrite it. The canonical form is the
	// content without the unsigned members, so a signer that adds only the
	// signature members leaves it as it was.
	before, err := report.CanonicalForm()
	if err != nil {
		return fmt.Errorf("the report cannot be signed: %w", err)
	}
	snapshot, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("the report cannot be signed: %w", err)
	}
	if err := callSigner(signer, report); err != nil {
		restoreReport(report, snapshot)
		return err
	}
	if after, err := report.CanonicalForm(); err != nil {
		restoreReport(report, snapshot)
		return fmt.Errorf("the report the signer left cannot be canonicalized: %w", err)
	} else if !bytes.Equal(before, after) {
		restoreReport(report, snapshot)
		return errors.New("the signer changed the report it was asked to attest (something other than the signature members): the report is left as the controller checked it, unsigned, and no signature is accepted for content nobody checked")
	}
	if report.Signature == "" {
		report.clearSignature()
		return errors.New("the signer returned without signing the report")
	}
	data, err := json.Marshal(report)
	if err != nil {
		report.clearSignature()
		return fmt.Errorf("failed to marshal the signed report: %w", err)
	}
	if _, valid, err := VerifyReportSignatureOnly(data); err != nil || !valid {
		report.clearSignature()
		if err == nil {
			err = ErrInvalidSignature
		}
		return fmt.Errorf("the signer left a signature that does not verify under the public key it set: %w", err)
	}
	return nil
}
