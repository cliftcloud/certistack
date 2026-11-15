// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// The Community Edition has no code that makes a signature, generates a key pair
// or reads a private key. The verifier's tests, in this package, still need
// signed reports to verify, so this file (test code, not product code) makes
// them, the way the Enterprise Edition's signer does: sign CanonicalForm and
// attach the result with AttachSignature. It repeats what pkg/attest/attesttest
// does for the other packages' tests; this package's own tests cannot import
// that one without an import cycle.

// GenerateKeyPair makes a throwaway Ed25519 key pair for a test.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}
	return pub, priv, nil
}

// SignCanonical signs canonical bytes with priv and returns the hex signature.
func SignCanonical(canonicalBytes []byte, priv ed25519.PrivateKey) string {
	return hex.EncodeToString(ed25519.Sign(priv, canonicalBytes))
}

// SignReport signs the report with priv for a test, as a Signer does.
func (r *Report) SignReport(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("cannot sign report: an Ed25519 private key is %d bytes, not %d", ed25519.PrivateKeySize, len(priv))
	}
	r.clearSignature()
	canonical, err := r.CanonicalForm()
	if err != nil {
		return fmt.Errorf("cannot sign report: %w", err)
	}
	return r.AttachSignature(SignCanonical(canonical, priv), priv.Public().(ed25519.PublicKey))
}
