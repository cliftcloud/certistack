// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"testing"
)

const signOnlyFiles = `[
  {"filename":"index.json.blob","crypt-mode":"sign-only","size":652},
  {"filename":"qemu-server.conf.blob","crypt-mode":"sign-only","size":480},
  {"filename":"drive-scsi0.img.fidx","crypt-mode":"sign-only","size":34359738368}
]`

// The report says a manifest's signature was verified only when a key
// verified it. A listing that says a snapshot is signed, read without a key,
// verified nothing: the evidence must not claim it did, in the layout or the
// profile, and the configured key is what turns the claim on.
func TestASignedListingIsVerifiedOnlyByAConfiguredKey(t *testing.T) {
	const snapshot = "vm/7011/2026-09-27T03:00:00Z"
	for name, cfg := range map[string]Config{"without a key": {}, "with a key": {Keyfile: testKey(t, "")}} {
		fakeBackupClient(t, signOnlyFiles, "cores: 2\nscsi0: pbs:vm-7011-disk-0\n")
		client := &Client{cfg: cfg}
		layout, err := client.LoadVMLayout(context.Background(), snapshot, t.TempDir())
		if err != nil {
			t.Fatalf("%s: LoadVMLayout: %v", name, err)
		}
		profile, err := client.LoadVMProfile(context.Background(), snapshot, t.TempDir())
		if err != nil {
			t.Fatalf("%s: LoadVMProfile: %v", name, err)
		}
		keyed := cfg.Keyfile != ""
		if layout.SignatureVerified != keyed || profile.SignatureVerified != keyed {
			t.Errorf("%s: SignatureVerified layout %v, profile %v; want %v", name, layout.SignatureVerified, profile.SignatureVerified, keyed)
		}
		if layout.CryptMode != CryptModeSignOnly || profile.CryptMode != CryptModeSignOnly {
			t.Errorf("%s: crypt mode layout %q, profile %q, want sign-only", name, layout.CryptMode, profile.CryptMode)
		}
	}
}
