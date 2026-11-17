// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// RFC 8785 canonicalizes every number as an IEEE-754 double. From 2^53 on a
// double stands for several integers, so a report whose signed integer were
// changed to a neighbour that rounds to the same double would verify:
// changing retention_days 9007199254740993 to 9007199254740992 would keep
// the signature. Such an integer is refused when
// a report is signed and when one is verified, so the claim that changing any
// signed value invalidates the signature is true.
func TestIntegersBeyondTheExactDoubleRangeCannotBeSignedOrVerified(t *testing.T) {
	pub, priv := newKey(t)

	for _, retention := range []int{9007199254740993, 9007199254740992, 1 << 60} {
		r := BuildReport(&config.Plan{PlanID: "p"}, "n", time.Second, true, nil, "")
		r.RetentionDays = retention
		if err := r.SignReport(priv); err == nil || !strings.Contains(err.Error(), "cannot be signed exactly") || r.Signature != "" {
			t.Errorf("retention_days %d: SignReport = %v (signature %q), want a refusal", retention, err, r.Signature)
		}
	}

	// The largest safe integer signs, and changing it invalidates the signature.
	r := BuildReport(&config.Plan{PlanID: "p"}, "n", time.Second, true, nil, "")
	r.RetentionDays = 9007199254740991
	if err := r.SignReport(priv); err != nil {
		t.Fatalf("2^53-1 could not be signed: %v", err)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	trusted := []ed25519.PublicKey{pub}
	if _, valid, err := VerifyReport(data, trusted); err != nil || !valid {
		t.Fatalf("a report with retention_days 2^53-1: valid=%v err=%v", valid, err)
	}
	for _, changed := range []string{"9007199254740990", "9007199254740992", "9007199254740993"} {
		tampered := bytes.Replace(data, []byte("9007199254740991"), []byte(changed), 1)
		if bytes.Equal(tampered, data) {
			t.Fatal("no replacement")
		}
		if _, valid, err := VerifyReport(tampered, trusted); valid || err == nil {
			t.Errorf("retention_days changed to %s still verifies: valid=%v err=%v", changed, valid, err)
		}
	}

	// A report carrying such an integer in any member, including one this
	// release does not know, is refused before its signature is judged.
	for name, member := range map[string]string{
		"integer 2^53+1":       `9007199254740993`,
		"integer 2^53":         `9007199254740992`,
		"negative":             `-9007199254740993`,
		"integer spelled 1e20": `1e20`,
		"integer with .0":      `9007199254740993.0`,
		"overflowing exponent": `1e999`,
		"nested in an array":   `[1, 9007199254740993]`,
		"nested in an object":  `{"deep": {"n": 9007199254740993}}`,
	} {
		doc := strings.TrimSuffix(string(data), "}") + `,"future_counter":` + member + `}`
		if _, valid, err := VerifyReport([]byte(doc), trusted); valid || err == nil || !strings.Contains(err.Error(), "IEEE-754") {
			t.Errorf("%s: VerifyReport = valid=%v err=%v, want the number refused", name, valid, err)
		}
	}

	// Numbers that a double holds exactly, or that are not integers, are fine.
	for _, member := range []string{`0`, `-1`, `1e3`, `12.5`, `0.1`, `4503599627370497.5`, `9007199254740991`, `-9007199254740991`, `1.7976931348623157e-300`} {
		doc := strings.TrimSuffix(string(data), "}") + `,"future_counter":` + member + `}`
		// The signature no longer matches the added member; what matters is that
		// the number itself is not what is refused.
		if _, _, err := VerifyReport([]byte(doc), trusted); err == nil || strings.Contains(err.Error(), "IEEE-754") || strings.Contains(err.Error(), "cannot be signed exactly") {
			t.Errorf("%s: VerifyReport error = %v, want the signature mismatch, not a number refusal", member, err)
		}
	}
}
