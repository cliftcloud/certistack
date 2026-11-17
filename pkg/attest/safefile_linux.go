// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace atomically renames from to to, failing if to exists. A
// filesystem without RENAME_NOREPLACE (NFS, some FUSE mounts) falls back to a
// hard link, which is equally atomic and equally refuses an existing entry.
func renameNoReplace(from, to string) error {
	err := unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
		return linkNoReplace(from, to)
	}
	return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
}
