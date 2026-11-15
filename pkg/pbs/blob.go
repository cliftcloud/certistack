// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/scrypt"
)

// This file reads what proxmox-backup-client cannot hand over: the backup
// log (client.log.blob) of an encrypted snapshot. The log is a PBS data blob
// outside the snapshot's manifest, encrypted with the backup's key, and the
// PBS API serves it only as the raw blob. The formats are those of Proxmox
// Backup Server's pbs-datastore (data_blob.rs, file_formats.rs) and
// pbs-key-config, and pbs-tools' CryptConfig, at 4404a84: AES-256-GCM with a
// 16-byte IV and a 16-byte tag, optional zstd compression before encryption.
// AES-GCM authenticates the log with the key, which the manifest's signature
// does not do for a plaintext log.

// blobMagic values, from file_formats.rs.
var (
	uncompressedBlobMagic        = [8]byte{66, 171, 56, 7, 190, 131, 112, 161}
	compressedBlobMagic          = [8]byte{49, 185, 88, 66, 111, 182, 163, 127}
	encryptedBlobMagic           = [8]byte{123, 103, 133, 190, 34, 45, 76, 240}
	encryptedCompressedBlobMagic = [8]byte{230, 89, 27, 191, 11, 191, 216, 11}
)

const (
	blobHeaderLen          = 8 + 4 // magic, CRC32
	encryptedBlobHeaderLen = blobHeaderLen + 16 + 16
	// maxRawLogBytes bounds the raw blob read from the API: a log of at most
	// maxClientLogBytes compresses to no more than that plus headers, and the
	// authenticated decryption needs the whole blob.
	maxRawLogBytes = 8 << 20
)

// decodeBlob returns the content of a PBS data blob, decrypted with key when
// the blob is encrypted and decompressed when it is compressed, and at most
// limit+1 bytes of it. A blob that does not authenticate under key, or is
// malformed, is an error: nothing of it is returned.
func decodeBlob(raw []byte, key *[32]byte, limit int) ([]byte, error) {
	if len(raw) < blobHeaderLen {
		return nil, fmt.Errorf("blob too small (%d bytes)", len(raw))
	}
	var magic [8]byte
	copy(magic[:], raw[:8])
	switch magic {
	case uncompressedBlobMagic:
		return boundedCopy(raw[blobHeaderLen:], limit), nil
	case compressedBlobMagic:
		return zstdDecode(raw[blobHeaderLen:], limit)
	case encryptedBlobMagic, encryptedCompressedBlobMagic:
	default:
		return nil, errors.New("not a PBS data blob (unknown magic)")
	}
	if len(raw) < encryptedBlobHeaderLen {
		return nil, fmt.Errorf("encrypted blob too small (%d bytes)", len(raw))
	}
	if key == nil {
		return nil, errors.New("the blob is encrypted and no key is configured")
	}
	iv, tag, ciphertext := raw[blobHeaderLen:blobHeaderLen+16], raw[blobHeaderLen+16:encryptedBlobHeaderLen], raw[encryptedBlobHeaderLen:]
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(append(sealed, ciphertext...), tag...)
	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, errors.New("the blob does not authenticate with the key (a different key, or a blob that was changed)")
	}
	if magic == encryptedCompressedBlobMagic {
		return zstdDecode(plain, limit)
	}
	return boundedCopy(plain, limit), nil
}

func boundedCopy(data []byte, limit int) []byte {
	if len(data) > limit+1 {
		data = data[:limit+1]
	}
	return append([]byte(nil), data...)
}

// zstdDecode decompresses at most limit+1 bytes, within a bounded window and
// memory, so a hostile blob cannot expand without limit.
func zstdDecode(payload []byte, limit int) ([]byte, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(payload),
		zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxWindow(32<<20), zstd.WithDecoderMaxMemory(64<<20))
	if err != nil {
		return nil, fmt.Errorf("start decompression: %w", err)
	}
	defer decoder.Close()
	content, err := io.ReadAll(io.LimitReader(decoder, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	return content, nil
}

// pbsKeyFile is the JSON of a PBS key file (pbs-key-config's KeyConfig).
type pbsKeyFile struct {
	KDF *struct {
		Scrypt *struct {
			N    uint64 `json:"n"`
			R    uint64 `json:"r"`
			P    uint64 `json:"p"`
			Salt string `json:"salt"`
		} `json:"Scrypt"`
		PBKDF2 *struct {
			Iter int    `json:"iter"`
			Salt string `json:"salt"`
		} `json:"PBKDF2"`
	} `json:"kdf"`
	Data        string `json:"data"`
	Fingerprint string `json:"fingerprint"`
}

// pbsFingerprintInput is sha256("Proxmox Backup Encryption Key Fingerprint"),
// from crypt_config.rs.
var pbsFingerprintInput = [32]byte{
	110, 208, 239, 119, 71, 31, 255, 77, 85, 199, 168, 254, 74, 157, 182, 33,
	97, 64, 127, 19, 76, 114, 93, 223, 48, 153, 45, 37, 236, 69, 237, 38,
}

// keyFingerprint is a key's fingerprint as PBS computes it: the SHA-256 of the
// fixed input followed by the key's derived id key, PBKDF2-HMAC-SHA-256 of the
// key with the salt "_id_key" in 10 rounds.
func keyFingerprint(key *[32]byte) ([32]byte, error) {
	idKey, err := pbkdf2.Key(sha256.New, string(key[:]), []byte("_id_key"), 10, 32)
	if err != nil {
		return [32]byte{}, err
	}
	hash := sha256.New()
	hash.Write(pbsFingerprintInput[:])
	hash.Write(idKey)
	var sum [32]byte
	copy(sum[:], hash.Sum(nil))
	return sum, nil
}

// loadPBSKey reads the raw 32-byte key out of a PBS key file, unlocking it
// with passphrase when the file is protected, and checks it against the
// fingerprint the file records. Neither the key nor the passphrase appears in
// an error.
func loadPBSKey(path, passphrase string) (*[32]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the key file: %w", err)
	}
	var file pbsKeyFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, errors.New("the key file is not a PBS key file")
	}
	stored, err := base64.StdEncoding.DecodeString(file.Data)
	if err != nil {
		return nil, errors.New("the key file's data is not base64")
	}
	var raw []byte
	if file.KDF == nil {
		raw = stored
	} else {
		derived, err := deriveKeyFromPassphrase(file, passphrase)
		if err != nil {
			return nil, err
		}
		if len(stored) < 32 {
			return nil, errors.New("the key file's data is too short")
		}
		block, err := aes.NewCipher(derived)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCMWithNonceSize(block, 16)
		if err != nil {
			return nil, err
		}
		sealed := append(append([]byte(nil), stored[32:]...), stored[16:32]...)
		raw, err = gcm.Open(nil, stored[:16], sealed, nil)
		if err != nil {
			return nil, errors.New("PBS_ENCRYPTION_PASSWORD does not unlock the key file (wrong passphrase)")
		}
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("the key is %d bytes, not 32", len(raw))
	}
	var key [32]byte
	copy(key[:], raw)
	if want := normalizeFingerprint(file.Fingerprint); want != "" {
		sum, err := keyFingerprint(&key)
		if err != nil {
			return nil, err
		}
		if got := hex.EncodeToString(sum[:]); got != want {
			return nil, errors.New("the key's fingerprint is not the one the key file records")
		}
	}
	return &key, nil
}

// deriveKeyFromPassphrase runs the key file's KDF over the passphrase. A KDF
// whose cost is beyond what PBS itself allows (1025 MiB for scrypt) is refused.
func deriveKeyFromPassphrase(file pbsKeyFile, passphrase string) ([]byte, error) {
	if len(passphrase) < minKeyPassphraseBytes {
		return nil, errors.New("the key file is protected by a passphrase: set PBS_ENCRYPTION_PASSWORD")
	}
	switch {
	case file.KDF.Scrypt != nil:
		s := file.KDF.Scrypt
		salt, err := base64.StdEncoding.DecodeString(s.Salt)
		if err != nil {
			return nil, errors.New("the key file's salt is not base64")
		}
		if s.N < 2 || s.N&(s.N-1) != 0 || s.N > 1<<22 || s.R < 1 || s.R > 64 || s.P < 1 || s.P > 64 || 128*s.N*s.R*s.P > 1025<<20 {
			return nil, errors.New("the key file's scrypt parameters are outside what PBS allows")
		}
		return scrypt.Key([]byte(passphrase), salt, int(s.N), int(s.R), int(s.P), 32)
	case file.KDF.PBKDF2 != nil:
		p := file.KDF.PBKDF2
		salt, err := base64.StdEncoding.DecodeString(p.Salt)
		if err != nil {
			return nil, errors.New("the key file's salt is not base64")
		}
		if p.Iter < 1 || p.Iter > 100_000_000 {
			return nil, errors.New("the key file's PBKDF2 iteration count is outside what PBS allows")
		}
		return pbkdf2.Key(sha256.New, passphrase, salt, p.Iter, 32)
	}
	return nil, errors.New("the key file names a key derivation function CertiStack does not know")
}

// blobKey is the raw key of this client's key file, loaded once. It is nil
// with an error when there is no key file or it cannot be unlocked.
func (c *Client) blobKey() (*[32]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blobKeyLoaded {
		return c.blobKeyValue, c.blobKeyErr
	}
	c.blobKeyLoaded = true
	if strings.TrimSpace(c.cfg.Keyfile) == "" {
		c.blobKeyErr = errors.New("no key is configured (CERTISTACK_PBS_KEYFILE)")
		return nil, c.blobKeyErr
	}
	c.blobKeyValue, c.blobKeyErr = loadPBSKey(c.cfg.Keyfile, c.cfg.EncryptionPassword)
	return c.blobKeyValue, c.blobKeyErr
}
