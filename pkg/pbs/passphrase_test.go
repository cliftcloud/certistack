// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A passphrase-protected key without its passphrase, or with the
// wrong one, failed inside proxmox-backup-client, whose output CertiStack
// withholds, so the operator saw only an exit status.
func TestCheckKeyPassphrase(t *testing.T) {
	protected := filepath.Join(t.TempDir(), "protected.enc")
	body := `{"kdf":{"Scrypt":{"n":65536,"r":8,"p":1,"salt":"c2FsdA=="}},"created":"2026-09-27T05:00:00Z","data":"AAAA","fingerprint":"aa:bb"}`
	if err := os.WriteFile(protected, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	plain := testKey(t, "aa:bb")
	for _, tc := range []struct {
		key, passphrase, want string
	}{
		{plain, "", ""},
		{plain, "anything", ""},
		{protected, "", "protected by a passphrase: set PBS_ENCRYPTION_PASSWORD"},
		{protected, "abcd", "shorter than any PBS key passphrase"},
		{protected, "correct horse", ""},
	} {
		err := CheckKeyPassphrase(tc.key, tc.passphrase)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Fatalf("CheckKeyPassphrase(%s, %q) = %v, want %q", filepath.Base(tc.key), tc.passphrase, err, tc.want)
		}
		if err != nil && tc.passphrase != "" && strings.Contains(err.Error(), tc.passphrase) {
			t.Fatalf("the passphrase leaked into %q", err)
		}
	}
}

func TestCommandFailureNamesKeyPassphraseRefusals(t *testing.T) {
	exit := errors.New("exit status 255")
	for output, want := range map[string]string{
		"Error: decryption failed - wrong password?\n":   "does not unlock CERTISTACK_PBS_KEYFILE",
		"Error: Passphrase is too short!\n":              "too short to be the key's passphrase",
		"Error: no password input mechanism available\n": "set PBS_ENCRYPTION_PASSWORD",
	} {
		err := commandFailure("restore source configuration", exit, []byte(output))
		if !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "Error:") {
			t.Fatalf("output %q: %v, want %q in CertiStack's words", output, err, want)
		}
	}
	// Anything else stays withheld.
	err := commandFailure("restore source configuration", exit, []byte("secret-looking output"))
	if strings.Contains(err.Error(), "secret-looking") || !strings.Contains(err.Error(), "withheld") {
		t.Fatalf("unknown output was not withheld: %v", err)
	}
}
