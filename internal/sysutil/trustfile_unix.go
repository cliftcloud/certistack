//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// currentUID is the user CertiStack runs as; tests replace it.
var currentUID = os.Getuid

// UnsafeToTrust says why the file at path, whose information (os.Stat) is info,
// cannot be trusted as what (a known_hosts file, an SSH identity), or nil: group
// or other users can write it, or it is owned by a user who is neither the one
// running CertiStack nor root, so that user could do what risk says. It is
// OpenSSH's StrictModes rule for the files sshd trusts.
func UnsafeToTrust(path string, info os.FileInfo, what, risk string) error {
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return &UntrustedFileError{
			Path:    path,
			Problem: fmt.Sprintf("%s %s can be written by group or other users (mode %04o), and any of them could %s", what, path, perm, risk),
			Fix:     "make it writable by you alone: chmod 600 " + shellWord(path),
		}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := int(stat.Uid); uid != 0 && uid != currentUID() {
		return &UntrustedFileError{
			Path:    path,
			Problem: fmt.Sprintf("%s %s is owned by %s, who is neither root nor the user CertiStack runs as, %s, and could %s", what, path, userLabel(uid), userLabel(currentUID()), risk),
			Fix:     fmt.Sprintf("give it to yourself: sudo chown %s %s", shellWord(userName(currentUID())), shellWord(path)),
		}
	}
	return nil
}

// userName is the login name of uid, or the number when it has none.
func userName(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(uid)
}

// userLabel names uid in a message: "alice (uid 1001)", or "uid 1001".
func userLabel(uid int) string {
	if name := userName(uid); name != strconv.Itoa(uid) {
		return fmt.Sprintf("%s (uid %d)", name, uid)
	}
	return fmt.Sprintf("uid %d", uid)
}
