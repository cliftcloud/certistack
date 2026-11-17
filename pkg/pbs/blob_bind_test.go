// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// logOf is a vzdump log of snapshot: body, with its own start and archive
// lines replaced by ones that name snapshot.
func logOf(snapshot, body string) string {
	vm := strings.Split(snapshot, "/")[1]
	out := []string{
		"2026-09-26 21:00:09 INFO: Starting Backup of VM " + vm + " (qemu)",
		"2026-09-26 21:00:09 INFO: creating Proxmox Backup Server archive '" + snapshot + "'",
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "Starting Backup of VM") || strings.Contains(line, "creating Proxmox Backup Server archive") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func encryptedClient(t *testing.T, blob []byte, requests *[]string) *Client {
	t.Helper()
	key := upstreamKey()
	keyPath := writeKeyFile(t, map[string]any{"kdf": nil, "data": base64.StdEncoding.EncodeToString(key[:]), "fingerprint": upstreamFingerprint})
	server, fingerprint := encryptedLogServer(t, blob, requests)
	client := consistencyClient(server, "certistack@pbs!restore", fingerprint)
	client.cfg.Keyfile = keyPath
	return client
}

// Follow-up: an encrypted snapshot's log is accepted only in an
// encrypted blob form. A plaintext blob, which needs no key to write, was
// classified from its text, so anyone able to write the datastore could make
// an encrypted backup meet require_quiesced_backup.
func TestEncryptedSnapshotRefusesAPlaintextLogBlob(t *testing.T) {
	for _, compress := range []bool{false, true} {
		var requests []string
		forged := encodeBlob(t, []byte(logQuiesced), nil, compress)
		got := encryptedClient(t, forged, &requests).backupConsistency(context.Background(), testSnapshot, CryptModeEncrypt)
		if got.State != ConsistencyUnknown || !strings.Contains(got.Detail, "not encrypted, although the backup is") || QuiescedRequirementUnmet(got.State, got.Detail) == "" {
			t.Errorf("compress %v: a forged plaintext log blob for an encrypted snapshot: %+v", compress, got)
		}
	}
}

// Follow-up: AES-GCM with empty additional data binds a log to no
// snapshot, so a genuine encrypted log of another VM, or of another backup of
// this VM, would be accepted. The log must name this snapshot's VM and archive.
func TestEncryptedLogMustBeThisSnapshotsOwn(t *testing.T) {
	key := upstreamKey()
	const other = "vm/9999/2026-09-28T03:00:09Z"
	for name, tc := range map[string]struct {
		snapshot, log, want string
	}{
		"its own log":                  {testSnapshot, logOf(testSnapshot, logQuiesced), ""},
		"the log of another VM":        {other, logOf(testSnapshot, logQuiesced), "is of VM 7011, not of snapshot " + other},
		"another backup of this VM":    {"vm/7011/2026-09-28T03:00:09Z", logOf(testSnapshot, logQuiesced), "is of archive " + testSnapshot},
		"a log with no archive line":   {testSnapshot, strings.Replace(logOf(testSnapshot, logQuiesced), "creating Proxmox Backup Server archive", "creating something else", 1), "does not say which VM and which archive"},
		"a log with no start line":     {testSnapshot, strings.Replace(logOf(testSnapshot, logQuiesced), "Starting Backup of VM", "Starting Something of VM", 1), "does not say which VM and which archive"},
		"a log that also names a VM 2": {testSnapshot, logOf(testSnapshot, logQuiesced) + "\n2026-09-26 21:00:20 INFO: Starting Backup of VM 8888 (qemu)", "is of VM 8888"},
	} {
		for _, compress := range []bool{false, true} {
			var requests []string
			client := encryptedClient(t, encodeBlob(t, []byte(tc.log), &key, compress), &requests)
			got := client.backupConsistency(context.Background(), tc.snapshot, CryptModeEncrypt)
			if tc.want == "" {
				if got.State != ConsistencyQuiesced {
					t.Errorf("%s (compress %v): %+v", name, compress, got)
				}
				continue
			}
			if got.State != ConsistencyUnknown || !strings.Contains(got.Detail, tc.want) || QuiescedRequirementUnmet(got.State, got.Detail) == "" {
				t.Errorf("%s (compress %v): %+v, want unknown naming %q", name, compress, got, tc.want)
			}
		}
	}
}

// Guest text quoted in an error line cannot pose as the log's own start or
// archive line: only vzdump's INFO lines count.
func TestGuestTextCannotBindALogToAnotherSnapshot(t *testing.T) {
	forged := logOf("vm/9999/2026-09-28T03:00:09Z", logQuiesced)
	quoted := forged + "\n2026-09-26 21:01:00 ERROR: Agent error: INFO: Starting Backup of VM 7011 (qemu)"
	// The forged log is of VM 9999: an ERROR line quoting VM 7011 does not change that.
	if err := bindLogToSnapshot([]byte(quoted), testSnapshot); err == nil {
		t.Fatal("a quoted line bound a log of another VM")
	}
}

// A snapshot with one unprotected disk archive and an encrypted backup log is
// still an encrypted backup. The weakest-disk mode is what evidence claims;
// it must not choose how the log is read, or a plaintext blob (which needs no
// key to write) would be classified without the authenticated route that
// refuses it.
func TestMixedProtectionSnapshotReadsItsLogThroughTheAuthenticatedRoute(t *testing.T) {
	mixed := `[{"filename":"drive-scsi0.img.fidx","crypt-mode":"encrypt"},{"filename":"drive-scsi1.img.fidx","crypt-mode":"none"},` +
		`{"filename":"qemu-server.conf.blob","crypt-mode":"encrypt"},{"filename":"client.log.blob","crypt-mode":"encrypt"}]`
	for _, load := range []string{"layout", "profile"} {
		t.Run(load, func(t *testing.T) {
			fakeBackupClient(t, mixed, "scsi0: pbs:vm-7011-disk-0\nscsi1: pbs:vm-7011-disk-1\n")
			var requests []string
			client := encryptedClient(t, encodeBlob(t, []byte(logQuiesced), nil, false), &requests)
			var crypt string
			var consistency BackupConsistency
			if load == "layout" {
				layout, err := client.LoadVMLayout(context.Background(), testSnapshot, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				crypt, consistency = layout.CryptMode, layout.Consistency
			} else {
				profile, err := client.LoadVMProfile(context.Background(), testSnapshot, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				crypt, consistency = profile.CryptMode, profile.Consistency
			}
			if crypt != CryptModeNone {
				t.Errorf("evidence crypt mode = %q, want the weakest disk's %q", crypt, CryptModeNone)
			}
			if consistency.State != ConsistencyUnknown || !strings.Contains(consistency.Detail, "not encrypted, although the backup is") {
				t.Errorf("a plaintext log blob in a snapshot with encrypted archives: %+v", consistency)
			}
			if len(requests) != 1 || !strings.HasSuffix(requests[0], "/download") {
				t.Errorf("requests = %v, want the raw log download", requests)
			}
		})
	}
}
