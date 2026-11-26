// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// A keyring is the set of keys accepted today and has no memory of time. The
// documented signer procedures (revoke a signer by deleting its entry, keep
// the old keyring to verify its reports; docs/troubleshooting.md) rest on
// exactly these behaviors: a retained key accepts a report whatever date it
// claims, including one after the key was replaced, one before the key existed
// and one made to look old; the entry's created_at is a label nothing
// evaluates; and removing the key rejects the genuine history it signed. If the
// verifier ever learns validity windows or revocation, this test fails on
// purpose and the documentation must change with it.
func TestKeyringHasNoTemporalAuthorization(t *testing.T) {
	oldPub, oldPriv := newKey(t)
	newPub, newPriv := newKey(t)
	dir := t.TempDir()
	entry := func(pub ed25519.PublicKey, created string) string {
		return fmt.Sprintf(`{"name":"controller-a","node":"pve1","public_key":%q,"created_at":%q}`, hex.EncodeToString(pub), created)
	}
	retained := writeInput(t, dir, "retained.json", []byte(`{"trusted_signers":[`+entry(oldPub, "2026-01-01T00:00:00Z")+`,`+entry(newPub, "2026-09-30T00:00:00Z")+`]}`))
	currentOnly := writeInput(t, dir, "current.json", []byte(`{"trusted_signers":[`+entry(newPub, "2026-09-30T00:00:00Z")+`]}`))

	signedAt := func(key ed25519.PrivateKey, timestamp string) []byte {
		t.Helper()
		report := BuildReport(&config.Plan{PlanID: "lifecycle", Name: "Lifecycle"}, "pve1", time.Second, true, nil, "")
		report.ValidationMode = ValidationModeFullIntegrity
		report.Timestamp = timestamp
		if err := report.SignReport(key); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	oldKeyReports := map[string][]byte{
		"a genuine report from before the rotation":        signedAt(oldPriv, "2026-03-01T12:00:00Z"),
		"a report dated after the key was replaced":        signedAt(oldPriv, "2026-10-15T12:00:00Z"),
		"a report dated to look old, signed today":         signedAt(oldPriv, "2026-02-01T00:00:00Z"),
		"a report dated before the entry's own created_at": signedAt(oldPriv, "2025-06-01T00:00:00Z"),
	}
	currentReport := signedAt(newPriv, "2026-10-15T12:00:00Z")

	verifyWith := func(path string, report []byte) error {
		kr, err := LoadKeyringFile(path)
		if err != nil {
			t.Fatal(err)
		}
		_, valid, err := VerifyReport(report, kr.PublicKeys())
		if err == nil && !valid {
			err = fmt.Errorf("not valid")
		}
		return err
	}
	for name, report := range oldKeyReports {
		if err := verifyWith(retained, report); err != nil {
			t.Errorf("%s, with the old key retained: %v; the lifecycle documentation says a retained key accepts it", name, err)
		}
		if err := verifyWith(currentOnly, report); err == nil || !strings.Contains(err.Error(), "untrusted signer") {
			t.Errorf("%s, with the old key removed: %v; the lifecycle documentation says removing a key rejects everything it signed", name, err)
		}
	}
	for label, path := range map[string]string{"retained": retained, "current only": currentOnly} {
		if err := verifyWith(path, currentReport); err != nil {
			t.Errorf("a report of the current key, keyring %s: %v", label, err)
		}
	}
}
