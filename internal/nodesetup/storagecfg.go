// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// StorageSection is one storage of PVE's /etc/pve/storage.cfg: its type (dir,
// pbs, lvmthin, ...), its ID and its properties as the file writes them.
type StorageSection struct {
	Type  string
	ID    string
	Props map[string]string
}

// maxStorageConfigBytes bounds the file the setup reads from the node.
const maxStorageConfigBytes = 1 << 20

// storageHeader is a section's first line: "type: id".
var storageHeader = regexp.MustCompile(`^([a-z][a-z0-9]*):\s+(\S+)\s*$`)

// ParseStorageConfig reads PVE's storage.cfg: sections that start with
// "type: id" at the start of a line, each followed by indented "key value"
// lines. A property line before any section, or a header that is not of that
// form, is an error: a file that does not read as PVE writes it is not guessed
// at.
func ParseStorageConfig(data []byte) ([]StorageSection, error) {
	if len(data) > maxStorageConfigBytes {
		return nil, fmt.Errorf("storage.cfg is larger than %d bytes", maxStorageConfigBytes)
	}
	var sections []StorageSection
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), maxStorageConfigBytes)
	number := 0
	for scanner.Scan() {
		number++
		raw := scanner.Text()
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		if raw[0] != ' ' && raw[0] != '\t' {
			m := storageHeader.FindStringSubmatch(raw)
			if m == nil {
				return nil, fmt.Errorf("storage.cfg line %d does not start a storage (want \"type: id\"): %q", number, raw)
			}
			sections = append(sections, StorageSection{Type: m[1], ID: m[2], Props: map[string]string{}})
			continue
		}
		if len(sections) == 0 {
			return nil, fmt.Errorf("storage.cfg line %d is a property outside any storage: %q", number, raw)
		}
		key, value, _ := strings.Cut(strings.TrimSpace(raw), " ")
		if key == "" {
			continue
		}
		sections[len(sections)-1].Props[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read storage.cfg: %w", err)
	}
	return sections, nil
}

// PBSStorage is a Proxmox Backup Server storage that PVE is configured with:
// what the setup can offer as the PBS to read backups from.
type PBSStorage struct {
	ID          string
	Server      string
	Port        int
	Datastore   string
	Namespace   string
	Fingerprint string // as the file writes it; NormalizeFingerprint makes it the controller's form
	// Encrypted is true when PVE encrypts this storage's backups (an
	// encryption-key line): reading them needs the key, which PVE keeps on the
	// node in EncryptionKeyPath.
	Encrypted bool
	// MasterKey is true when the storage also encrypts each backup's key with a
	// master public key; reading still needs the storage's own key.
	MasterKey bool
}

// EncryptionKeyPath is where PVE keeps a PBS storage's encryption key on the
// node.
func (s PBSStorage) EncryptionKeyPath() string {
	return "/etc/pve/priv/storage/" + s.ID + ".enc"
}

// Repository is the PBS repository string for the read-only token on this
// storage's server and datastore: user!token@server:port:datastore.
func (s PBSStorage) Repository(tokenID string) string {
	host := s.Server
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s@%s:%d:%s", tokenID, host, s.Port, s.Datastore)
}

// PBSStorages are the pbs storages of a parsed storage.cfg, in ID order. One
// without a server or a datastore is left out: it cannot be read from.
func PBSStorages(sections []StorageSection) []PBSStorage {
	var out []PBSStorage
	for _, section := range sections {
		if section.Type != "pbs" {
			continue
		}
		storage := PBSStorage{
			ID:          section.ID,
			Server:      section.Props["server"],
			Port:        8007,
			Datastore:   section.Props["datastore"],
			Namespace:   section.Props["namespace"],
			Fingerprint: section.Props["fingerprint"],
			Encrypted:   section.Props["encryption-key"] != "",
			MasterKey:   section.Props["master-pubkey"] != "",
		}
		if port, err := strconv.Atoi(section.Props["port"]); err == nil && port > 0 && port <= 65535 {
			storage.Port = port
		}
		if storage.Server == "" || storage.Datastore == "" {
			continue
		}
		out = append(out, storage)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DirStorage is a directory storage of storage.cfg, for the overlays.
type DirStorage struct {
	ID      string
	Path    string
	Content []string
	Shared  bool
	Nodes   []string // the nodes it is limited to; empty for every node
	// Disabled is the storage's "disable" flag: PVE does not use it.
	Disabled bool
}

// OnNode reports whether the storage is defined for the node.
func (s DirStorage) OnNode(node string) bool {
	if len(s.Nodes) == 0 {
		return true
	}
	for _, n := range s.Nodes {
		if n == node {
			return true
		}
	}
	return false
}

// HasContent reports whether the storage holds the given content type.
func (s DirStorage) HasContent(kind string) bool {
	for _, c := range s.Content {
		if c == kind {
			return true
		}
	}
	return false
}

// DirStorages are the dir storages of a parsed storage.cfg.
func DirStorages(sections []StorageSection) []DirStorage {
	var out []DirStorage
	for _, section := range sections {
		if section.Type != "dir" {
			continue
		}
		_, disabled := section.Props["disable"]
		storage := DirStorage{ID: section.ID, Path: section.Props["path"], Shared: section.Props["shared"] == "1", Disabled: disabled && section.Props["disable"] != "0"}
		for _, c := range strings.Split(section.Props["content"], ",") {
			if c = strings.TrimSpace(c); c != "" {
				storage.Content = append(storage.Content, c)
			}
		}
		for _, n := range strings.Split(section.Props["nodes"], ",") {
			if n = strings.TrimSpace(n); n != "" {
				storage.Nodes = append(storage.Nodes, n)
			}
		}
		out = append(out, storage)
	}
	return out
}

// StorageIDTaken reports whether any storage of the file has this ID.
func StorageIDTaken(sections []StorageSection, id string) bool {
	for _, section := range sections {
		if section.ID == id {
			return true
		}
	}
	return false
}

// fingerprintForm is a SHA-256 certificate fingerprint as PBS_FINGERPRINT holds it.
var fingerprintForm = regexp.MustCompile(`^([0-9a-f]{2}:){31}[0-9a-f]{2}$`)

// NormalizeFingerprint returns a PBS certificate fingerprint as the controller
// writes PBS_FINGERPRINT (32 lower-case hex pairs joined by colons), or an
// error for anything else.
func NormalizeFingerprint(fingerprint string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(fingerprint))
	if !fingerprintForm.MatchString(f) {
		return "", fmt.Errorf("%q is not a SHA-256 certificate fingerprint (32 pairs of hex digits joined by colons)", fingerprint)
	}
	return f, nil
}
