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
	"io"
	"math"
	"strconv"
	"testing"

	"github.com/gowebpki/jcs"
)

// A reference report checker and canonicalizer built on encoding/json, the
// oracle the one-pass scanner is held to. They tokenize and decode the
// document several times, so a large report costs 38 times its size and a
// many-member object seconds; what they accept is what every signed report
// needs accepted.

const oracleMaxDepth = 10000

func oracleCheckJSONDocument(data []byte, numbers bool) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := oracleCheckUniqueKeys(dec, "$", 0, numbers); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("unexpected data after the top-level JSON value")
	}
	return nil
}

func oracleCheckUniqueKeys(dec *json.Decoder, path string, depth int, numbers bool) error {
	if depth > oracleMaxDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels at %s", oracleMaxDepth, path)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("non-string object key at %s", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q at %s", key, path)
			}
			seen[key] = struct{}{}
			if err := oracleCheckUniqueKeys(dec, path+"."+key, depth+1, numbers); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for index := 0; dec.More(); index++ {
			if err := oracleCheckUniqueKeys(dec, fmt.Sprintf("%s[%d]", path, index), depth+1, numbers); err != nil {
				return err
			}
		}
	default:
		if number, ok := tok.(json.Number); ok && numbers {
			return oracleCheckSignableNumber(number, path)
		}
		return nil
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

func oracleCheckSignableNumber(number json.Number, path string) error {
	f, err := strconv.ParseFloat(string(number), 64)
	if err != nil {
		return fmt.Errorf("number at %s cannot be represented as an IEEE-754 double", path)
	}
	if math.Abs(f) >= maxSignedInteger && f == math.Trunc(f) {
		return fmt.Errorf("an integer of 2^53 or more at %s cannot be signed exactly", path)
	}
	return nil
}

// oracleDecode is the reference decode of a checked document.
func oracleDecode(data []byte) (map[string]interface{}, error) {
	var rawMap map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&rawMap); err != nil {
		return nil, err
	}
	return rawMap, nil
}

// oracleCanonicalize is CanonicalizeReportJSON as it was: two tokenizing
// passes, two decodes, a marshal and the RFC 8785 transform.
func oracleCanonicalize(reportBytes []byte) ([]byte, error) {
	if err := oracleCheckJSONDocument(reportBytes, true); err != nil {
		return nil, fmt.Errorf("failed to decode report JSON: %w", err)
	}
	rawMap, err := oracleDecode(reportBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode report JSON: %w", err)
	}
	delete(rawMap, "signature")
	delete(rawMap, "public_key")
	delete(rawMap, "signer_fingerprint")
	rawWithoutSig, err := json.Marshal(rawMap)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(rawWithoutSig)
}

// oracleAccepts is whether the reference verifier reads a document at all: it
// passes the duplicate and number check and decodes to a generic object.
func oracleAccepts(data []byte) bool {
	if oracleCheckJSONDocument(data, true) != nil {
		return false
	}
	_, err := oracleDecode(data)
	return err == nil
}

// signWithOracle signs members (a report's members, with or without the three
// unsigned ones) over the canonical form the reference pipeline computes, and
// returns the signed document. It exists to build a genuinely signed document
// of a shape the current signer refuses, to show that the verifier refuses the
// shape and not a bad signature.
func signWithOracle(t testing.TB, key ed25519.PrivateKey, members map[string]json.RawMessage) []byte {
	t.Helper()
	for _, unsigned := range []string{"signature", "public_key", "signer_fingerprint"} {
		delete(members, unsigned)
	}
	payload, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := oracleCanonicalize(payload)
	if err != nil {
		t.Fatalf("the old pipeline cannot canonicalize the fixture: %v", err)
	}
	public := key.Public().(ed25519.PublicKey)
	for name, value := range map[string]string{
		"signature":          SignCanonical(canonical, key),
		"public_key":         hex.EncodeToString(public),
		"signer_fingerprint": Fingerprint(public),
	} {
		encoded, _ := json.Marshal(value)
		members[name] = encoded
	}
	signed, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
