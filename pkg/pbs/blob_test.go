// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/scrypt"
)

// upstreamKey is the key Proxmox Backup Server's own fingerprint test uses
// (pbs-key-config, fingerprint_checks): the bytes 0 to 31, whose fingerprint
// PBS prints as below.
func upstreamKey() [32]byte {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

const upstreamFingerprint = "0e:ab:d4:46:0b:6e:b9:ca:34:50:23:de:e2:b7:78:c7:90:e5:4a:16:83:b9:65:9c:0a:57:ae:19:90:90:15:9b"

func writeKeyFile(t *testing.T, doc map[string]any) string {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pbs.enc")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// gcmSeal encrypts as pbs-tools' CryptConfig does: AES-256-GCM, a 16-byte IV
// and no additional data, returning the ciphertext and the 16-byte tag.
func gcmSeal(t *testing.T, key []byte, iv, plaintext []byte) (ciphertext, tag []byte) {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, iv, plaintext, nil)
	return sealed[:len(sealed)-16], sealed[len(sealed)-16:]
}

// encodeBlob builds a PBS data blob the way DataBlob::encode does:
// (magic || crc32 || [iv || tag ||] data).
func encodeBlob(t *testing.T, content []byte, key *[32]byte, compress bool) []byte {
	t.Helper()
	payload := content
	if compress {
		encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			t.Fatal(err)
		}
		payload = encoder.EncodeAll(content, nil)
		encoder.Close()
	}
	header := make([]byte, 12)
	var out []byte
	switch {
	case key == nil && !compress:
		copy(header, uncompressedBlobMagic[:])
		out = append(header, payload...)
	case key == nil && compress:
		copy(header, compressedBlobMagic[:])
		out = append(header, payload...)
	default:
		magic := encryptedBlobMagic
		if compress {
			magic = encryptedCompressedBlobMagic
		}
		copy(header, magic[:])
		iv := bytes.Repeat([]byte{7}, 16)
		ciphertext, tag := gcmSeal(t, key[:], iv, payload)
		out = append(append(append(header, iv...), tag...), ciphertext...)
	}
	return out
}

// The key file is read as PBS reads it, and PBS's own fingerprint
// for a key is reproduced.
func TestLoadPBSKeyMatchesPBSFingerprints(t *testing.T) {
	key := upstreamKey()
	sum, err := keyFingerprint(&key)
	if err != nil {
		t.Fatal(err)
	}
	if got := formatFingerprint(hex.EncodeToString(sum[:])); got != upstreamFingerprint {
		t.Fatalf("fingerprint = %s, want PBS's %s", got, upstreamFingerprint)
	}
	plain := writeKeyFile(t, map[string]any{"kdf": nil, "data": base64.StdEncoding.EncodeToString(key[:]), "fingerprint": upstreamFingerprint})
	loaded, err := loadPBSKey(plain, "")
	if err != nil || *loaded != key {
		t.Fatalf("plain key: %v", err)
	}
	// A key file whose recorded fingerprint is not its key's is refused, as PBS does.
	wrong := writeKeyFile(t, map[string]any{"kdf": nil, "data": base64.StdEncoding.EncodeToString(key[:]), "fingerprint": strings.Repeat("00:", 31) + "00"})
	if _, err := loadPBSKey(wrong, ""); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("wrong fingerprint: %v", err)
	}
	// Passphrase-protected keys, both KDFs PBS writes: data is iv || tag ||
	// AES-256-GCM of the key under the derived key.
	salt := bytes.Repeat([]byte{9}, 32)
	scryptKey, err := scrypt.Key([]byte("correct horse"), salt, 1024, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	pbkdf2Key, err := pbkdf2.Key(sha256.New, "correct horse", salt, 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		kdf     map[string]any
		derived []byte
	}{
		"scrypt": {map[string]any{"Scrypt": map[string]any{"n": 1024, "r": 8, "p": 1, "salt": base64.StdEncoding.EncodeToString(salt)}}, scryptKey},
		"pbkdf2": {map[string]any{"PBKDF2": map[string]any{"iter": 1000, "salt": base64.StdEncoding.EncodeToString(salt)}}, pbkdf2Key},
	} {
		iv := bytes.Repeat([]byte{3}, 16)
		ciphertext, tag := gcmSeal(t, tc.derived, iv, key[:])
		data := append(append(append([]byte(nil), iv...), tag...), ciphertext...)
		path := writeKeyFile(t, map[string]any{"kdf": tc.kdf, "data": base64.StdEncoding.EncodeToString(data), "fingerprint": upstreamFingerprint})
		loaded, err := loadPBSKey(path, "correct horse")
		if err != nil || *loaded != key {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := loadPBSKey(path, "wrong passphrase"); err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
			t.Errorf("%s with a wrong passphrase: %v", name, err)
		}
		if _, err := loadPBSKey(path, ""); err == nil || !strings.Contains(err.Error(), "PBS_ENCRYPTION_PASSWORD") {
			t.Errorf("%s without a passphrase: %v", name, err)
		}
	}
	// A KDF costing more than PBS itself allows is refused before it runs.
	huge := writeKeyFile(t, map[string]any{"kdf": map[string]any{"Scrypt": map[string]any{"n": 1 << 22, "r": 64, "p": 64, "salt": "AAAA"}}, "data": base64.StdEncoding.EncodeToString(make([]byte, 80))})
	if _, err := loadPBSKey(huge, "correct horse"); err == nil || !strings.Contains(err.Error(), "outside what PBS allows") {
		t.Fatalf("an unbounded scrypt cost: %v", err)
	}
	// Not a key file, and errors never carry the key.
	for name, content := range map[string]string{"text": "-----BEGIN PROXMOX BACKUP KEY-----", "short data": `{"kdf":null,"data":"AAAA"}`} {
		path := filepath.Join(t.TempDir(), "bad")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPBSKey(path, ""); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A blob is decrypted only if it authenticates under the key.
func TestDecodeBlob(t *testing.T) {
	key := upstreamKey()
	other := key
	other[0] ^= 1
	content := []byte(strings.Repeat("INFO: starting new backup job\nINFO: issuing guest-agent 'fs-freeze' command\n", 200))
	for _, compress := range []bool{false, true} {
		for _, encrypted := range []bool{false, true} {
			var k *[32]byte
			if encrypted {
				k = &key
			}
			blob := encodeBlob(t, content, k, compress)
			got, err := decodeBlob(blob, &key, len(content))
			if err != nil || !bytes.Equal(got, content) {
				t.Errorf("compress %v encrypted %v: %v, %d bytes", compress, encrypted, err, len(got))
			}
			if !encrypted {
				continue
			}
			// Wrong key, changed ciphertext, changed tag, no key, cut short.
			if _, err := decodeBlob(blob, &other, len(content)); err == nil {
				t.Errorf("compress %v: a wrong key decrypted the blob", compress)
			}
			for name, index := range map[string]int{"tag": blobHeaderLen + 16, "ciphertext": len(blob) - 1} {
				changed := append([]byte(nil), blob...)
				changed[index] ^= 0x80
				if _, err := decodeBlob(changed, &key, len(content)); err == nil {
					t.Errorf("compress %v: a changed %s was accepted", compress, name)
				}
			}
			if _, err := decodeBlob(blob, nil, len(content)); err == nil || !strings.Contains(err.Error(), "no key") {
				t.Errorf("compress %v without a key: %v", compress, err)
			}
			if _, err := decodeBlob(blob[:encryptedBlobHeaderLen-1], &key, len(content)); err == nil {
				t.Errorf("compress %v: a blob cut inside its header was accepted", compress)
			}
		}
	}
	if _, err := decodeBlob([]byte("not a blob at all!!"), &key, 10); err == nil || !strings.Contains(err.Error(), "unknown magic") {
		t.Errorf("unknown magic: %v", err)
	}
	// Output is bounded whatever the blob claims: a compressed megabyte of
	// zeros times a hundred is cut at the limit.
	bomb := encodeBlob(t, make([]byte, 100<<20), &key, true)
	got, err := decodeBlob(bomb, &key, maxClientLogBytes)
	if err != nil || len(got) != maxClientLogBytes+1 {
		t.Fatalf("a decompression bomb: %d bytes, %v; want the limit and a byte", len(got), err)
	}
}

// encryptedLogServer stands in for the PBS API serving the raw log blob.
func encryptedLogServer(t *testing.T, blob []byte, requests *[]string) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests = append(*requests, r.URL.Path)
		if r.URL.Path != "/api2/json/admin/datastore/pbs-data/download" || r.Header.Get("Authorization") != "PBSAPIToken=certistack@pbs!restore:s3cret" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Query().Get("file-name") != "client.log.blob" {
			t.Errorf("unexpected query %s", r.URL.RawQuery)
		}
		_, _ = w.Write(blob)
	}))
	t.Cleanup(server.Close)
	sum := sha256.Sum256(server.Certificate().Raw)
	return server, hex.EncodeToString(sum[:])
}

// An encrypted backup's log used to be reported unknown without being
// read, so an encrypted backup could never meet require_quiesced_backup. It is
// now fetched raw and decrypted with the key, and classified like any log.
func TestEncryptedBackupLogIsDecryptedAndClassified(t *testing.T) {
	key := upstreamKey()
	keyPath := writeKeyFile(t, map[string]any{"kdf": nil, "data": base64.StdEncoding.EncodeToString(key[:]), "fingerprint": upstreamFingerprint})
	for _, compress := range []bool{false, true} {
		var requests []string
		blob := encodeBlob(t, []byte(logQuiesced), &key, compress)
		server, fingerprint := encryptedLogServer(t, blob, &requests)
		client := consistencyClient(server, "certistack@pbs!restore", fingerprint)
		client.cfg.Keyfile = keyPath
		got := client.backupConsistency(context.Background(), testSnapshot, CryptModeEncrypt)
		if got.State != ConsistencyQuiesced || QuiescedRequirementUnmet(got.State, got.Detail) != "" {
			t.Fatalf("compress %v: an encrypted backup with a quiesced log: %+v", compress, got)
		}
		if len(requests) != 1 || !strings.HasSuffix(requests[0], "/download") {
			t.Fatalf("requests = %v, want the raw download", requests)
		}
		// A refused freeze in the encrypted log is found too.
		requests = nil
		refusal := encodeBlob(t, []byte(logOf(testSnapshot, logFreezeDenied)), &key, compress)
		server2, fingerprint2 := encryptedLogServer(t, refusal, &requests)
		client = consistencyClient(server2, "certistack@pbs!restore", fingerprint2)
		client.cfg.Keyfile = keyPath
		if got := client.backupConsistency(context.Background(), testSnapshot, CryptModeEncrypt); got.State != ConsistencyCrash {
			t.Fatalf("compress %v: an encrypted log with a refused freeze: %+v", compress, got)
		}
	}
	// A log that does not authenticate under the key is unknown, never a state.
	var requests []string
	other := key
	other[5] ^= 0xff
	server, fingerprint := encryptedLogServer(t, encodeBlob(t, []byte(logQuiesced), &other, true), &requests)
	client := consistencyClient(server, "certistack@pbs!restore", fingerprint)
	client.cfg.Keyfile = keyPath
	got := client.backupConsistency(context.Background(), testSnapshot, CryptModeEncrypt)
	if got.State != ConsistencyUnknown || !strings.Contains(got.Detail, "could not be decrypted") || QuiescedRequirementUnmet(got.State, got.Detail) == "" {
		t.Fatalf("a log under another key: %+v", got)
	}
	if strings.Contains(got.Detail, keyPath) || strings.Contains(got.Detail, "s3cret") {
		t.Fatalf("the reason names a secret: %q", got.Detail)
	}
	// No key configured: unknown, with the reason, before any request.
	requests = nil
	client = consistencyClient(server, "certistack@pbs!restore", fingerprint)
	if got := client.backupConsistency(context.Background(), testSnapshot, CryptModeEncrypt); got.State != ConsistencyUnknown || !strings.Contains(got.Detail, "no key is configured") || len(requests) != 0 {
		t.Fatalf("no key: %+v (requests %v)", got, requests)
	}
	// A log the API does not have is still the snapshot having none.
	client.cfg.Keyfile = keyPath
	missing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	t.Cleanup(missing.Close)
	sum := sha256.Sum256(missing.Certificate().Raw)
	client = consistencyClient(missing, "certistack@pbs!restore", hex.EncodeToString(sum[:]))
	client.cfg.Keyfile = keyPath
	if got := client.backupConsistency(context.Background(), testSnapshot, CryptModeEncrypt); got.State != ConsistencyUnknown || !strings.Contains(got.Detail, "no backup log") {
		t.Fatalf("no log: %+v", got)
	}
}
