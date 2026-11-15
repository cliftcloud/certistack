// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
)

// The reported case, through the compiled verifier's command. A
// keyring has no memory of time, and docs/architecture.md (the signer
// lifecycle, item 9 of the attestation section) builds its rotation and
// retirement procedure on exactly that: a retained key accepts what it signed
// whatever date the report claims, including one after the key was replaced,
// one before the key existed and one made to look old; a keyring without the
// key rejects all of it at status 2; and the rotation's two keyrings, the
// historical one for archived reports and the active one for new ones, each
// accept their own and no other. If the verifier ever learns validity windows
// or revocation this test fails on purpose and the lifecycle text must change
// with it.
func TestVerifyReportSignerLifecycle(t *testing.T) {
	oldPublic, oldPrivate, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	type entry struct {
		key     ed25519.PublicKey
		created string
	}
	keyring := func(name string, entries ...entry) string {
		t.Helper()
		var members []string
		for _, entry := range entries {
			members = append(members, fmt.Sprintf(`{"name":"controller-a","node":"pve1","public_key":%q,"created_at":%q}`, hex.EncodeToString(entry.key), entry.created))
		}
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, []byte(`{"trusted_signers":[`+strings.Join(members, ",")+`]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	oldEntry, newEntry := entry{oldPublic, "2026-01-01T00:00:00Z"}, entry{newPublic, "2026-09-30T00:00:00Z"}
	retained := keyring("retained", oldEntry, newEntry) // the rotation's overlap
	activeOnly := keyring("active", newEntry)           // after the old key is removed
	historical := keyring("historical", oldEntry)       // for archived reports only
	signedAt := func(name string, key ed25519.PrivateKey, timestamp string) string {
		t.Helper()
		report := campaignFixtureReport(mustLoadFixturePlan(), campaignFixture{mode: accept.OutcomePass})
		report.ValidationMode = attest.ValidationModeFullIntegrity
		report.Timestamp = timestamp
		if err := attesttest.SignReport(report, key); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	oldReports := map[string]string{
		"a genuine report from before the rotation":        signedAt("old-genuine", oldPrivate, "2026-03-01T12:00:00Z"),
		"a report dated after the key was replaced":        signedAt("old-after", oldPrivate, "2026-10-15T12:00:00Z"),
		"a report dated to look old, signed today":         signedAt("old-backdated", oldPrivate, "2026-02-01T00:00:00Z"),
		"a report dated before the entry's own created_at": signedAt("old-precreation", oldPrivate, "2025-06-01T00:00:00Z"),
	}
	newReport := signedAt("new", newPrivate, "2026-10-15T12:00:00Z")

	verify := func(keyringPath, report string) error {
		t.Helper()
		_, err := runVerifyReport("--keyring", keyringPath, "--format", "json", report)
		return err
	}
	for label, report := range oldReports {
		if err := verify(retained, report); err != nil {
			t.Errorf("%s, with the old key retained: %v; the lifecycle text says a retained key accepts it", label, err)
		}
		if err := verify(historical, report); err != nil {
			t.Errorf("%s, in the historical keyring: %v; the lifecycle text says it verifies there", label, err)
		}
		if err := verify(activeOnly, report); err == nil || exitCodeForError(err) != exitCodeInfrastructure || !strings.Contains(err.Error(), "untrusted signer") {
			t.Errorf("%s, with the old key removed: %v (status %d); the lifecycle text says it fails as an untrusted signer at status 2", label, err, exitCodeForError(err))
		}
	}
	for label, path := range map[string]string{"the overlap keyring": retained, "the active keyring": activeOnly} {
		if err := verify(path, newReport); err != nil {
			t.Errorf("a report of the new key, %s: %v", label, err)
		}
	}
	// A verifier that has not been given the new key rejects every new report:
	// the lifecycle text rolls the keyring out before the controller changes.
	if err := verify(historical, newReport); err == nil || exitCodeForError(err) != exitCodeInfrastructure || !strings.Contains(err.Error(), "untrusted signer") {
		t.Errorf("a report of the new key against the historical keyring: %v (status %d); want an untrusted signer at status 2", err, exitCodeForError(err))
	}
}
