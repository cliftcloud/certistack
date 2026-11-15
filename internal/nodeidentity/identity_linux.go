// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build linux

package nodeidentity

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
)

// pveLocalLink is PVE's own link to this node's directory in its cluster file
// system: nodes/<name>. A variable so that a test can point it elsewhere.
var pveLocalLink = "/etc/pve/local"

// readLocalName is the basename of the target of /etc/pve/local, else the short
// host name where the link does not exist. A link that exists and cannot be read
// is an error: guessing from the host name there would be the unchecked answer
// this package exists to avoid.
func readLocalName() (string, error) {
	target, err := os.Readlink(pveLocalLink)
	switch {
	case err == nil:
		name, err := NameFromLinkTarget(target)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", pveLocalLink, err)
		}
		return name, nil
	case errors.Is(err, fs.ErrNotExist):
		return shortHostName()
	default:
		return "", fmt.Errorf("read %s: %w", pveLocalLink, err)
	}
}

// pveDir is PVE's cluster file system, mounted at /etc/pve on a node. A
// variable so that a test can point it elsewhere.
var pveDir = "/etc/pve"

// lookPath finds a program on the PATH; a variable so that a test can say which
// programs the host has.
var lookPath = exec.LookPath

// onPVENode is true when pveDir is a directory (or cannot be told apart from
// one: only a missing path proves it is not there), or when pveversion or qm,
// PVE's own tools, are on the PATH. Any one is enough: the answer is "evidently
// not a PVE node" only when none of them is there.
func onPVENode() bool {
	if info, err := os.Stat(pveDir); err == nil && info.IsDir() || err != nil && !errors.Is(err, fs.ErrNotExist) {
		return true
	}
	for _, tool := range []string{"pveversion", "qm"} {
		if _, err := lookPath(tool); err == nil {
			return true
		}
	}
	return false
}
