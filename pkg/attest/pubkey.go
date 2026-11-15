// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
)

// Ed25519 public keys are 32 bytes, but not every 32 bytes is a key that can
// anchor trust. Go's ed25519.Verify accepts the small-order points: for the
// identity (01 00..00) the signature R = 01 00..00, S = 0 verifies for every
// message, and for the other seven small-order points and their non-canonical
// encodings it verifies for one message in two, four or eight. Anyone can
// produce such a signature without any private key, so a report "signed" under
// such a key would verify as trusted. An all-zero key (a placeholder nobody
// replaced) is one of them. A value that is not a curve point at all can never
// verify anything, so a keyring that holds one has an anchor that is silently
// inactive. checkPublicKey therefore refuses, at every place a public key
// becomes a trust anchor and for the key a report embeds, any encoding that
// is not a canonical curve point of large order.

var (
	edOne = big.NewInt(1)
	// edP is the field prime 2^255 - 19.
	edP = new(big.Int).Sub(new(big.Int).Lsh(edOne, 255), big.NewInt(19))
	// edD is the curve constant d = -121665/121666 mod p, in -x^2 + y^2 = 1 + d x^2 y^2.
	edD = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), edP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, edP)
	}()
)

var (
	errNonCanonicalPoint = errors.New("its encoding is not canonical (the y coordinate is not below 2^255-19, or the sign of a zero x is set)")
	errNotOnCurve        = errors.New("it is not a point on the Ed25519 curve, so it can never verify a signature")
	errSmallOrderPoint   = errors.New("it is a small-order point, for which anyone can forge a signature without a private key (a placeholder such as 64 zeros is not a key)")
)

// checkPublicKey refuses an Ed25519 public key that cannot anchor trust: one
// of the wrong size, an encoding that is not canonical, a value that is not
// on the curve, or a point of order 1, 2, 4 or 8. A key that passes may still
// be one nobody holds the private key for; that is for the operator.
func checkPublicKey(key []byte) error {
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("an Ed25519 public key is %d bytes, not %d", ed25519.PublicKeySize, len(key))
	}
	x, y, err := decodePoint(key)
	if err != nil {
		return err
	}
	// The point has order dividing 8 exactly when eight times it is the identity.
	for i := 0; i < 3; i++ {
		x, y = doublePoint(x, y)
	}
	if x.Sign() == 0 && y.Cmp(edOne) == 0 {
		return errSmallOrderPoint
	}
	return nil
}

// decodePoint decompresses a canonical Ed25519 point encoding (RFC 8032
// section 5.1.3) into affine coordinates.
func decodePoint(enc []byte) (x, y *big.Int, err error) {
	var be [32]byte
	for i := range be {
		be[31-i] = enc[i]
	}
	sign := be[0] >> 7
	be[0] &= 0x7f
	y = new(big.Int).SetBytes(be[:])
	if y.Cmp(edP) >= 0 {
		return nil, nil, errNonCanonicalPoint
	}
	// x^2 = (y^2 - 1) / (d y^2 + 1); the denominator is never zero, because
	// -1/d is not a square, but a zero is refused all the same.
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, edP)
	u := new(big.Int).Sub(y2, edOne)
	u.Mod(u, edP)
	v := new(big.Int).Mul(edD, y2)
	v.Add(v, edOne)
	v.Mod(v, edP)
	if v.Sign() == 0 {
		return nil, nil, errNotOnCurve
	}
	x2 := u.Mul(u, new(big.Int).ModInverse(v, edP))
	x2.Mod(x2, edP)
	x = new(big.Int).ModSqrt(x2, edP)
	if x == nil {
		return nil, nil, errNotOnCurve
	}
	if x.Sign() == 0 && sign == 1 {
		return nil, nil, errNonCanonicalPoint
	}
	if x.Bit(0) != uint(sign) {
		x.Sub(edP, x)
	}
	return x, y, nil
}

// doublePoint doubles an affine point with the unified twisted Edwards
// addition law for a = -1, which is complete on this curve: neither
// denominator is ever zero.
func doublePoint(x, y *big.Int) (*big.Int, *big.Int) {
	xx := new(big.Int).Mul(x, x)
	xx.Mod(xx, edP)
	yy := new(big.Int).Mul(y, y)
	yy.Mod(yy, edP)
	dxxyy := new(big.Int).Mul(xx, yy)
	dxxyy.Mod(dxxyy, edP)
	dxxyy.Mul(dxxyy, edD)
	dxxyy.Mod(dxxyy, edP)

	// x3 = 2xy / (1 + d x^2 y^2), y3 = (y^2 + x^2) / (1 - d x^2 y^2)
	xNum := new(big.Int).Mul(x, y)
	xNum.Lsh(xNum, 1)
	xNum.Mod(xNum, edP)
	xDen := new(big.Int).Add(edOne, dxxyy)
	xDen.Mod(xDen, edP)
	yNum := new(big.Int).Add(yy, xx)
	yNum.Mod(yNum, edP)
	yDen := new(big.Int).Sub(edOne, dxxyy)
	yDen.Mod(yDen, edP)

	x3 := xNum.Mul(xNum, new(big.Int).ModInverse(xDen, edP))
	x3.Mod(x3, edP)
	y3 := yNum.Mul(yNum, new(big.Int).ModInverse(yDen, edP))
	y3.Mod(y3, edP)
	return x3, y3
}
