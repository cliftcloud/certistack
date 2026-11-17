// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/diskslot"
)

// PBS crypt modes, as `snapshot files` reports them per archive.
const (
	CryptModeNone     = "none"
	CryptModeSignOnly = "sign-only"
	CryptModeEncrypt  = "encrypt"
)

// maxKeyfileBytes bounds an encryption key file. A PBS key is a small JSON
// document; anything larger is not one.
const maxKeyfileBytes = 64 << 10

// ValidateKeyfile checks a PBS encryption key file before it is used: an
// absolute path to a regular file (not a symlink) of key size that only its
// owner can read. The key decrypts every backup made with it, so a key other
// users could read is refused rather than used.
func ValidateKeyfile(p string) error {
	if !path.IsAbs(p) { // node paths are Linux paths
		return fmt.Errorf("PBS encryption key path must be absolute")
	}
	info, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("PBS encryption key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("PBS encryption key is not a regular file")
	}
	if info.Size() == 0 || info.Size() > maxKeyfileBytes {
		return fmt.Errorf("PBS encryption key is %d bytes, not a key file", info.Size())
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("PBS encryption key is readable by other users (mode %04o); make it owner-only (chmod 600)", info.Mode().Perm())
	}
	// A paperkey printout, a PEM master key or a passphrase file is not a
	// key file; say so now rather than at the first restore.
	if _, err := KeyfileFingerprint(p); err != nil {
		return err
	}
	return nil
}

// minKeyPassphraseBytes is the shortest passphrase PBS accepts for a key.
const minKeyPassphraseBytes = 5

// CheckKeyPassphrase refuses, before anything is restored, a
// passphrase-protected key (its "kdf" is set) without a passphrase, or with
// one shorter than PBS accepts. Only PBS can tell whether a passphrase is
// the right one; commandFailure names that refusal when it comes.
func CheckKeyPassphrase(p, passphrase string) error {
	data, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("PBS encryption key: %w", err)
	}
	var key struct {
		KDF json.RawMessage `json:"kdf"`
	}
	if err := json.Unmarshal(data, &key); err != nil {
		return fmt.Errorf("PBS encryption key is not a PBS key file")
	}
	if len(key.KDF) == 0 || string(key.KDF) == "null" {
		return nil
	}
	if passphrase == "" {
		return fmt.Errorf("CERTISTACK_PBS_KEYFILE is protected by a passphrase: set PBS_ENCRYPTION_PASSWORD")
	}
	if len(passphrase) < minKeyPassphraseBytes {
		return fmt.Errorf("PBS_ENCRYPTION_PASSWORD is shorter than any PBS key passphrase (at least %d characters)", minKeyPassphraseBytes)
	}
	return nil
}

// ParseSnapshotCryptMode returns the strongest crypt mode of any archive in
// `proxmox-backup-client snapshot files --output-format json`: encrypt, then
// sign-only, then none. A listing without crypt modes counts as none.
func ParseSnapshotCryptMode(data []byte) (string, error) {
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return "", fmt.Errorf("parse PBS snapshot files JSON: %w", err)
	}
	modes := make(map[string]bool)
	collectCryptModes(decoded, modes)
	switch {
	case modes[CryptModeEncrypt]:
		return CryptModeEncrypt, nil
	case modes[CryptModeSignOnly]:
		return CryptModeSignOnly, nil
	default:
		return CryptModeNone, nil
	}
}

func collectCryptModes(value any, modes map[string]bool) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			collectCryptModes(item, modes)
		}
	case map[string]any:
		for key, item := range typed {
			if mode, ok := item.(string); ok && key == "crypt-mode" {
				modes[mode] = true
			}
			collectCryptModes(item, modes)
		}
	}
}

// ParseSnapshotDiskCryptMode returns the weakest crypt mode among the
// snapshot's disk archives (none, then sign-only, then encrypt): the
// protection every restored disk actually had, which is what evidence may
// claim. A snapshot whose disks are only partly encrypted reports the
// weaker mode.
func ParseSnapshotDiskCryptMode(data []byte) (string, error) {
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return "", fmt.Errorf("parse PBS snapshot files JSON: %w", err)
	}
	rank := map[string]int{CryptModeNone: 0, CryptModeSignOnly: 1, CryptModeEncrypt: 2}
	weakest, found := CryptModeEncrypt, false
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			if name, ok := typed["filename"].(string); ok {
				if _, isDisk := diskslot.ArchiveSlot(name); isDisk {
					mode, _ := typed["crypt-mode"].(string)
					if _, known := rank[mode]; !known {
						mode = CryptModeNone // unreported counts as unprotected
					}
					if !found || rank[mode] < rank[weakest] {
						weakest = mode
					}
					found = true
				}
			}
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(decoded)
	if !found {
		return CryptModeNone, nil
	}
	return weakest, nil
}

// checkSnapshotKey reads a snapshot's crypt mode and fails early, with a
// message an operator can act on, when it is encrypted and no key was
// configured. Without this the first restore fails with the PBS client's
// own error, which CertiStack withholds because it can carry credentials.
func (c *Client) checkSnapshotKey(snapshot string, files []byte) (string, error) {
	mode, err := ParseSnapshotCryptMode(files)
	if err != nil {
		return "", err
	}
	if mode == CryptModeEncrypt && c.cfg.Keyfile == "" {
		return "", fmt.Errorf("PBS snapshot %s is encrypted: set CERTISTACK_PBS_KEYFILE to its encryption key (for a PBS storage managed by Proxmox VE, /etc/pve/priv/storage/<storage>.enc)", snapshot)
	}
	c.mu.Lock()
	if c.cryptModes == nil {
		c.cryptModes = make(map[string]string)
	}
	c.cryptModes[snapshot] = mode
	c.mu.Unlock()
	return mode, nil
}

// KeyfileFingerprint returns the fingerprint a PBS key file records for
// itself ("fingerprint" in the key's JSON), normalized, or "" when the file
// has none. Reading it needs no passphrase: only the key data is protected.
func KeyfileFingerprint(p string) (string, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("read PBS encryption key: %w", err)
	}
	var key struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(data, &key); err != nil {
		return "", fmt.Errorf("PBS encryption key is not a PBS key file (JSON): %w", err)
	}
	return normalizeFingerprint(key.Fingerprint), nil
}

func normalizeFingerprint(fingerprint string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fingerprint), ":", ""))
}

// checkKeyMatches refuses, before any restore, a configured key that is not
// the one the snapshot was encrypted or signed with. PBS lists each
// snapshot's key fingerprint; a wrong key would otherwise fail inside the
// PBS client with an error CertiStack must withhold. When either side has
// no fingerprint the check is skipped and PBS decides.
func (c *Client) checkKeyMatches(ctx context.Context, snapshot, mode string) error {
	if c.cfg.Keyfile == "" || mode == CryptModeNone {
		return nil
	}
	keyFingerprint, err := KeyfileFingerprint(c.cfg.Keyfile)
	if err != nil || keyFingerprint == "" {
		return err
	}
	snapshotFingerprint, err := c.snapshotKeyFingerprint(ctx, snapshot)
	if err != nil || snapshotFingerprint == "" {
		return err
	}
	if snapshotFingerprint != keyFingerprint {
		return fmt.Errorf("CERTISTACK_PBS_KEYFILE is not this backup's key: PBS snapshot %s was made with key fingerprint %s, the configured key has %s", snapshot, formatFingerprint(snapshotFingerprint), formatFingerprint(keyFingerprint))
	}
	return nil
}

// snapshotKeyFingerprint reads the snapshot's key fingerprint from its
// group's `snapshot list`, once per group.
func (c *Client) snapshotKeyFingerprint(ctx context.Context, snapshot string) (string, error) {
	parts := strings.SplitN(snapshot, "/", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid PBS snapshot path %q", snapshot)
	}
	group := parts[0] + "/" + parts[1]
	c.mu.Lock()
	fingerprints, cached := c.groupFingerprints[group]
	c.mu.Unlock()
	if !cached {
		args := append([]string{"snapshot", "list", group, "--output-format", "json"}, c.targetArgs()...)
		output, err := c.run(ctx, 30*time.Second, args...)
		if err != nil {
			return "", listFailure("list PBS snapshots for "+group, err, []byte(output))
		}
		if fingerprints, err = parseSnapshotFingerprints([]byte(output), group); err != nil {
			return "", err
		}
		c.mu.Lock()
		if c.groupFingerprints == nil {
			c.groupFingerprints = make(map[string]map[string]string)
		}
		c.groupFingerprints[group] = fingerprints
		c.mu.Unlock()
	}
	return fingerprints[snapshot], nil
}

// parseSnapshotFingerprints maps each snapshot path in a `snapshot list`
// to its normalized key fingerprint, for entries that report one.
func parseSnapshotFingerprints(data []byte, group string) (map[string]string, error) {
	var entries []struct {
		BackupType  string          `json:"backup-type"`
		BackupID    string          `json:"backup-id"`
		BackupTime  json.RawMessage `json:"backup-time"`
		Fingerprint string          `json:"fingerprint"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse PBS snapshot list JSON: %w", err)
	}
	fingerprints := make(map[string]string)
	for _, entry := range entries {
		if entry.Fingerprint == "" || entry.BackupType+"/"+entry.BackupID != group {
			continue
		}
		backupTime, err := parseBackupTime(entry.BackupTime)
		if err != nil {
			continue
		}
		fingerprints[group+"/"+backupTime.UTC().Format(time.RFC3339)] = normalizeFingerprint(entry.Fingerprint)
	}
	return fingerprints, nil
}

// formatFingerprint shows a normalized fingerprint the way PBS prints it.
func formatFingerprint(fingerprint string) string {
	var pairs []string
	for i := 0; i+2 <= len(fingerprint); i += 2 {
		pairs = append(pairs, fingerprint[i:i+2])
	}
	return strings.Join(pairs, ":")
}

// keyArgs returns the --keyfile arguments for a restore or map of the
// snapshot. The key goes only to encrypted and signed snapshots: with a key
// configured, the PBS client requires a valid manifest signature, so passing
// it for an unsigned snapshot (an older backup in the same group, or another
// VM's) makes that restore fail. The crypt mode comes from the snapshot's
// file list, read here if no earlier call cached it.
func (c *Client) keyArgs(ctx context.Context, snapshot string) ([]string, error) {
	if c.cfg.Keyfile == "" {
		return nil, nil
	}
	c.mu.Lock()
	mode, known := c.cryptModes[snapshot]
	c.mu.Unlock()
	if !known {
		files, err := c.snapshotFiles(ctx, snapshot)
		if err != nil {
			return nil, err
		}
		if mode, err = c.checkSnapshotKey(snapshot, files); err != nil {
			return nil, err
		}
	}
	if mode == CryptModeNone {
		return nil, nil
	}
	return []string{"--keyfile", c.cfg.Keyfile}, nil
}

// restoreKeyArgs is keyArgs for `restore`, which also takes --crypt-mode. A
// restore given neither a key nor a crypt mode loads the PBS client's own
// default key (encryption-key.json in the user's PBS configuration), if one
// exists, and then requires a signed manifest: whether an unprotected
// snapshot restored would depend on files in the service account's home.
// Without a key it asks for no encryption explicitly. `map` has no such
// option; its client runs in a home without configuration (buildEnv).
func (c *Client) restoreKeyArgs(ctx context.Context, snapshot string) ([]string, error) {
	args, err := c.keyArgs(ctx, snapshot)
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		args = []string{"--crypt-mode", "none"}
	}
	return args, nil
}
