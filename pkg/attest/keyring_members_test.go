// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func containsKey(keys []ed25519.PublicKey, want ed25519.PublicKey) bool {
	for _, key := range keys {
		if key.Equal(want) {
			return true
		}
	}
	return false
}

// encoding/json matches a keyring member to its field ignoring case
// and Unicode folding and lets the last match win, while the duplicate check
// compares names exactly. A member spelled "Public_Key", "PUBLIC_KEY", with
// the Kelvin sign U+212A for its k or the long s U+017F for an s, beside the
// documented member would silently replace the key a reader sees. Each is
// refused with the documented spelling named, at the top level and in an entry,
// whichever comes first.
func TestKeyringMembersThatFoldToADocumentedNameAreRefused(t *testing.T) {
	a, _ := newKey(t)
	b, _ := newKey(t)
	ah, bh := hex.EncodeToString(a), hex.EncodeToString(b)
	entry := func(members string) string {
		return `{"trusted_signers":[{"name":"prod-controller","public_key":"` + ah + `"` + members + `}]}`
	}
	list := `[{"name":"prod-controller","public_key":"` + ah + `"}]`
	listB := `[{"name":"prod-controller","public_key":"` + bh + `"}]`

	for name, tc := range map[string]struct{ content, want string }{
		"case variant of public_key":        {entry(`,"Public_Key":"` + bh + `"`), `entry 1: member "Public_Key" reads as "public_key"`},
		"upper-case public_key":             {entry(`,"PUBLIC_KEY":"` + bh + `"`), `member "PUBLIC_KEY" reads as "public_key"`},
		"Kelvin sign in public_key":         {entry(`,"public_` + "K" + `ey":"` + bh + `"`), `reads as "public_key"`},
		"case variant of fingerprint":       {entry(`,"Fingerprint":"` + Fingerprint(b) + `"`), `reads as "fingerprint"`},
		"case variant of name":              {entry(`,"NAME":"other"`), `reads as "name"`},
		"case variant of node":              {entry(`,"Node":"other"`), `reads as "node"`},
		"variant before the documented one": {`{"trusted_signers":[{"PUBLIC_KEY":"` + bh + `","public_key":"` + ah + `"}]}`, `reads as "public_key"`},
		"variant alone in an entry":         {`{"trusted_signers":[{"name":"n","Public_Key":"` + ah + `"}]}`, `reads as "public_key"`},
		"upper-case list beside the list":   {`{"trusted_signers":` + list + `,"TRUSTED_SIGNERS":` + listB + `}`, `the keyring: member "TRUSTED_SIGNERS" reads as "trusted_signers"`},
		"long s in the list name":           {`{"trusted_signers":` + list + `,"trusted_` + "ſ" + `igners":` + listB + `}`, `reads as "trusted_signers"`},
		"variant list without the real one": {`{"Trusted_Signers":` + list + `}`, `reads as "trusted_signers"`},
		"variant in a later entry":          {`{"trusted_signers":[{"name":"a","public_key":"` + ah + `"},{"name":"b","public_key":"` + bh + `","Public_key":"` + ah + `"}]}`, `entry 2: member "Public_key"`},
	} {
		kr, err := LoadKeyringFile(keyringFixture(t, tc.content))
		if err == nil || kr != nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: LoadKeyringFile = (%v, %v), want an error containing %q", name, kr != nil, err, tc.want)
			continue
		}
		if strings.Contains(err.Error(), ah) || strings.Contains(err.Error(), bh) {
			t.Errorf("%s: the error quotes a key: %v", name, err)
		}
	}

	// Controls: exact names load, unknown members are still ignored, and a
	// longer name that merely starts like a documented one is not a variant.
	for name, content := range map[string]string{
		"exact members":               entry(`,"fingerprint":"` + Fingerprint(a) + `","node":"pve1","created_at":"2026-09-30"`),
		"unknown members are ignored": entry(`,"comment":"rotated in September","public_key_comment":"x","tags":["a"]`),
		"only exact spelling matches": entry(`,"names":"x","node_id":"y"`),
	} {
		kr, err := LoadKeyringFile(keyringFixture(t, content))
		if err != nil || !containsKey(kr.PublicKeys(), a) || len(kr.PublicKeys()) != 1 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A revocation mark is not evaluated, so a key marked
// revoked would silently stay trusted; the entry is refused, and the error says
// to remove the entry to revoke a key.
func TestKeyringRevokedMemberIsRefused(t *testing.T) {
	a, _ := newKey(t)
	for name, member := range map[string]string{
		`"revoked": true`:     `"revoked":true`,
		`"revoked": false`:    `"revoked":false`,
		`"Revoked": true`:     `"Revoked":true`,
		`"revocation": "..."`: `"revocation":"compromised 2026-09-01"`,
		`"revoked_at": "..."`: `"revoked_at":"2026-09-01T00:00:00Z"`,
		`"revokedAt": "..."`:  `"revokedAt":"2026-09-01T00:00:00Z"`,
		`"REVOKED_BY": "..."`: `"REVOKED_BY":"alice"`,
	} {
		content := `{"trusted_signers":[{"name":"old-controller","public_key":"` + hex.EncodeToString(a) + `",` + member + `}]}`
		kr, err := LoadKeyringFile(keyringFixture(t, content))
		if err == nil || kr != nil || !strings.Contains(err.Error(), "remove the entry to revoke a key") || !strings.Contains(err.Error(), "entry 1") {
			t.Errorf("%s: LoadKeyringFile = (%v, %v), want a refusal telling the operator to remove the entry", name, kr != nil, err)
		}
	}
	// Removing the entry is the revocation, and the rest of the keyring works.
	b, _ := newKey(t)
	content := `{"trusted_signers":[{"name":"current","public_key":"` + hex.EncodeToString(b) + `"}]}`
	if kr, err := LoadKeyringFile(keyringFixture(t, content)); err != nil || containsKey(kr.PublicKeys(), a) || !containsKey(kr.PublicKeys(), b) {
		t.Fatalf("keyring after removing the revoked entry: %v", err)
	}
}

// A keyring entry marked revoked by its value, not its member name
// ("status": "revoked", as other tools write it), loaded and its key stayed
// trusted: a report the operator meant to reject verified as from a trusted
// signer, although the documentation says an entry marked revoked refuses the
// keyring. It is refused like a member named revoked.
func TestKeyringEntryMarkedRevokedByAValueIsRefused(t *testing.T) {
	a, _ := newKey(t)
	for name, member := range map[string]string{
		`"status": "revoked"`:         `"status":"revoked"`,
		`"state": "Revoked"`:          `"state":"Revoked"`,
		`"status": " REVOKED "`:       `"status":" REVOKED "`,
		`"comment": "revoked after…"`: `"comment":"revoked after the leak"`,
		`"trust": "revocation"`:       `"trust":"revocation pending"`,
	} {
		content := `{"trusted_signers":[{"name":"old-controller","public_key":"` + hex.EncodeToString(a) + `",` + member + `}]}`
		kr, err := LoadKeyringFile(keyringFixture(t, content))
		if err == nil || kr != nil || !strings.Contains(err.Error(), "remove the entry to revoke a key") || !strings.Contains(err.Error(), "entry 1") {
			t.Errorf("%s: LoadKeyringFile = (%v, %v), want a refusal telling the operator to remove the entry", name, kr != nil, err)
		}
	}
	// Values that do not say revoked are labels, as before.
	for name, member := range map[string]string{
		"status active": `"status":"active"`,
		"a comment":     `"comment":"not revoked, rotated in September"`,
		"a number":      `"status":1`,
	} {
		content := `{"trusted_signers":[{"name":"controller","public_key":"` + hex.EncodeToString(a) + `",` + member + `}]}`
		if kr, err := LoadKeyringFile(keyringFixture(t, content)); err != nil || !containsKey(kr.PublicKeys(), a) {
			t.Errorf("%s: LoadKeyringFile = %v, want the entry loaded", name, err)
		}
	}
}
