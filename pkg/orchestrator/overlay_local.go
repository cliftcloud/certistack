// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

// storageConfigPath is PVE's storage configuration, in the cluster file
// system. Reading it needs no PVE API call, so it answers when the storage
// status does not.
const storageConfigPath = "/etc/pve/storage.cfg"

const maxStorageConfigBytes = 1 << 20

// localStorage is the part of a PVE storage's configuration that says whether
// its directory is the storage: the type and content, whether it is disabled
// or limited to other nodes, where it lives and whether that is a mount point
// PVE expects.
type localStorage struct {
	Type         string
	Path         string
	Content      string
	Disable      string
	IsMountpoint string
	Nodes        string
}

var (
	storageSectionExpr = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_-]*):\s+(\S+)\s*$`)
	storageOptionExpr  = regexp.MustCompile(`^\s+(\S+)(?:\s+(.*?))?\s*$`)
)

// parseStorageConfig reads the section of storage id from storage.cfg, in
// PVE's section-config format: a "type: id" line, then indented "key value"
// lines.
func parseStorageConfig(data io.Reader, id string) (localStorage, bool, error) {
	var found, in bool
	var storage localStorage
	scanner := bufio.NewScanner(data)
	scanner.Buffer(make([]byte, 64<<10), maxStorageConfigBytes)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			match := storageSectionExpr.FindStringSubmatch(line)
			in = match != nil && match[2] == id
			if in {
				if found {
					return localStorage{}, false, fmt.Errorf("storage %q is configured twice", id)
				}
				found, storage.Type = true, match[1]
			}
			continue
		}
		if !in {
			continue
		}
		match := storageOptionExpr.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		switch match[1] {
		case "path":
			storage.Path = match[2]
		case "content":
			storage.Content = match[2]
		case "disable":
			// PVE writes a disabled storage's flag with no value ("disable"
			// on a line of its own); a flag given without a value is set,
			// not the empty string that reads as enabled.
			storage.Disable = match[2]
			if strings.TrimSpace(match[2]) == "" {
				storage.Disable = "1"
			}
		case "is_mountpoint":
			storage.IsMountpoint = match[2]
		case "nodes":
			storage.Nodes = match[2]
		}
	}
	if err := scanner.Err(); err != nil {
		return localStorage{}, false, err
	}
	return storage, found, nil
}

// readStorageConfig reads storage id's configuration from the node's copy of
// the cluster's storage.cfg.
func readStorageConfig(id string) (localStorage, error) {
	file, err := os.Open(storageConfigPath)
	if err != nil {
		return localStorage{}, err
	}
	defer file.Close()
	storage, found, err := parseStorageConfig(io.LimitReader(file, maxStorageConfigBytes), id)
	if err != nil {
		return localStorage{}, err
	}
	if !found {
		return localStorage{}, fmt.Errorf("storage %q is not in %s", id, storageConfigPath)
	}
	return storage, nil
}

// pveBool reads PVE's boolean spellings; ok is false for anything else.
func pveBool(value string) (result, ok bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "yes", "on", "true":
		return true, true
	case "0", "no", "off", "false", "":
		return false, true
	}
	return false, false
}

// networkStorageTypes are file-based storages PVE mounts when it activates
// them, at their path.
var networkStorageTypes = map[string]bool{"nfs": true, "cifs": true, "cephfs": true, "glusterfs": true}

var localStorageTypes = map[string]bool{"dir": true, "btrfs": true, "nfs": true, "cifs": true, "cephfs": true, "glusterfs": true}

// expectedMountPoint is where PVE expects a mount for the storage, or "": the
// path a network storage is mounted at, and the is_mountpoint of a directory
// storage (a boolean stands for its path).
func (s localStorage) expectedMountPoint() (string, error) {
	if s.IsMountpoint != "" {
		if enabled, ok := pveBool(s.IsMountpoint); ok {
			if !enabled {
				return "", nil
			}
			return s.Path, nil
		}
		if !path.IsAbs(s.IsMountpoint) {
			return "", fmt.Errorf("is_mountpoint %q is neither a boolean nor an absolute path", s.IsMountpoint)
		}
		return path.Clean(s.IsMountpoint), nil
	}
	if networkStorageTypes[s.Type] {
		return s.Path, nil
	}
	return "", nil
}

// confirmLocalOverlayStorage is what the node itself can establish about a
// storage whose PVE status did not answer, from its configuration and the
// mount table. PVE's status answer would say the storage is active, which
// for a mounted storage means it is mounted; without it, the directory
// `pvesm path` resolves is only a directory, and beneath an absent mount it is
// an ordinary directory of another file system whose free space says nothing
// about the storage. It returns what it confirmed, or why the
// directory is not the storage.
func (o *Orchestrator) confirmLocalOverlayStorage(storage, dir string) (string, error) {
	read := o.storageConfigFn
	if read == nil {
		read = readStorageConfig
	}
	config, err := read(storage)
	if err != nil {
		return "", fmt.Errorf("its configuration could not be read on the node, so its directory %s cannot be confirmed to be the storage: %w", dir, err)
	}
	if disabled, ok := pveBool(config.Disable); disabled || !ok {
		return "", fmt.Errorf("storage %q is disabled in the cluster's storage configuration", storage)
	}
	switch {
	case !localStorageTypes[config.Type]:
		return "", fmt.Errorf("storage %q is type %q; it must be file-based (dir, nfs, cifs, cephfs, btrfs, glusterfs)", storage, config.Type)
	case !contentAllows(config.Content, "images"):
		return "", fmt.Errorf("storage %q does not allow disk images (content %q)", storage, config.Content)
	case config.Nodes != "" && !contentAllows(config.Nodes, o.opts.NodeName):
		return "", fmt.Errorf("storage %q is limited to nodes %s, not %s", storage, config.Nodes, o.opts.NodeName)
	case config.Path == "" || path.Clean(config.Path) != path.Clean(dir):
		return "", fmt.Errorf("storage %q is configured at %q, but pvesm resolves it to %s", storage, config.Path, dir)
	}
	mountPoint, err := config.expectedMountPoint()
	if err != nil {
		return "", fmt.Errorf("storage %q: %w", storage, err)
	}
	if mountPoint == "" {
		return fmt.Sprintf("configuration confirmed: %s storage in %s, no mount expected", config.Type, dir), nil
	}
	mounted := o.mountPointFn
	if mounted == nil {
		return "", errors.New("the mount table cannot be read here")
	}
	ok, err := mounted(mountPoint)
	if err != nil {
		return "", fmt.Errorf("storage %q's mount %s could not be checked: %w", storage, mountPoint, err)
	}
	if !ok {
		return "", fmt.Errorf("storage %q is expected to be mounted at %s, but nothing is mounted there: PVE has not activated it, and the directory that is there belongs to another file system, so CertiStack does not use it; activate the storage in PVE (pvesm status) or mount it, then run again", storage, mountPoint)
	}
	return fmt.Sprintf("configuration and mount confirmed: %s storage mounted at %s", config.Type, mountPoint), nil
}

// contentAllows reports whether the comma-separated list has want.
func contentAllows(list, want string) bool {
	for _, item := range strings.Split(list, ",") {
		if strings.TrimSpace(item) == want {
			return true
		}
	}
	return false
}
