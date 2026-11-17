//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// errRenameWithoutReplacingUnsupported says a file cannot be renamed here
// without possibly replacing the name it takes.
var errRenameWithoutReplacingUnsupported = errors.New("renaming without replacing is not supported here")

// renameWithoutReplacing renames staged to path with renameat2(2) and
// RENAME_NOREPLACE: path is taken only if it is free, atomically, and a file
// there fails with an error that is os.ErrExist. A kernel or file system that
// does not know the flag gives errRenameWithoutReplacingUnsupported; any
// other error is returned as it came.
func renameWithoutReplacing(staged, path string) error {
	err := unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOTSUP):
		return errRenameWithoutReplacingUnsupported
	default:
		return err
	}
}
