// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package attesttest makes signed reports for tests. FOR TESTS ONLY: nothing in
// a product binary may import it.
//
// The Community Edition writes its reports unsigned and has no code that reads a
// private key, generates a key pair or makes a signature. What it keeps is the
// verifier, and the verifier's tests (and those of the controller, the runner and
// the Enterprise Edition) need signed reports to verify. This package makes
// them: a throwaway key pair, a function that signs a report with a key, and a
// Signer that can be handed to the runner or the controller as the Enterprise
// Edition's real signer is. A repository test checks that no product package
// imports it.
package attesttest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// GenerateKeyPair makes a throwaway Ed25519 key pair for a test.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}
	return pub, priv, nil
}

// SignCanonical signs canonical bytes with priv and returns the hex-encoded
// signature. Like ed25519.Sign it panics for a key of the wrong size.
func SignCanonical(canonical []byte, priv ed25519.PrivateKey) string {
	return hex.EncodeToString(ed25519.Sign(priv, canonical))
}

// SignReport signs the report with priv, as the Enterprise Edition's signer
// does: it signs the report's canonical form and attaches the result with
// (*attest.Report).AttachSignature. A key of the wrong size, or one whose public
// half is not the key's own, is an error.
func SignReport(report *attest.Report, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("cannot sign report: an Ed25519 private key is %d bytes, not %d", ed25519.PrivateKeySize, len(priv))
	}
	report.Signature, report.PublicKey, report.SignerFingerprint, report.SignatureTimestamp = "", "", "", nil
	canonical, err := report.CanonicalForm()
	if err != nil {
		return fmt.Errorf("cannot sign report: %w", err)
	}
	public, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("cannot sign report: the private key has no Ed25519 public key")
	}
	return report.AttachSignature(SignCanonical(canonical, priv), public)
}

// Signer is an attest.Signer for tests. It signs with a key it holds, counts its
// calls, and can be made to fail.
type Signer struct {
	mu    sync.Mutex
	key   ed25519.PrivateKey
	calls int
	err   error
}

// NewSigner returns a Signer that signs with key.
func NewSigner(key ed25519.PrivateKey) *Signer {
	return &Signer{key: key}
}

// NewFailingSigner returns a Signer whose every call fails with err.
func NewFailingSigner(err error) *Signer {
	return &Signer{err: err}
}

// SignReport counts the call, then signs the report or fails as the Signer was
// made to.
func (s *Signer) SignReport(report *attest.Report) error {
	s.mu.Lock()
	s.calls++
	err, key := s.err, s.key
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return SignReport(report, key)
}

// Calls is the number of times SignReport has been called.
func (s *Signer) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Public is the public key a report signed by s carries.
func (s *Signer) Public() ed25519.PublicKey {
	if len(s.key) != ed25519.PrivateKeySize {
		return nil
	}
	return s.key.Public().(ed25519.PublicKey)
}

var _ attest.Signer = (*Signer)(nil)
