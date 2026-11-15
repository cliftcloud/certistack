//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/cliftcloud/certistack/internal/journal"
)

// FileIdentityOf reads the identity of the regular file at path: its device
// and inode, and its creation time where the filesystem records one. A symlink
// or anything else that is not a regular file has no identity of a file this
// run created.
func FileIdentityOf(path string) (journal.FileIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return journal.FileIdentity{}, err
	}
	if !info.Mode().IsRegular() {
		return journal.FileIdentity{}, fmt.Errorf("%s: %w", path, errNotRegular)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return journal.FileIdentity{}, fmt.Errorf("%s: the kernel's file identity is not available", path)
	}
	id := journal.FileIdentity{Dev: uint64(stat.Dev), Ino: uint64(stat.Ino)}
	var statx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &statx); err == nil && statx.Mask&unix.STATX_BTIME != 0 {
		id.BtimeNS = statx.Btime.Sec*1e9 + int64(statx.Btime.Nsec)
	}
	return id, nil
}

// PublishNoReplace makes the file at src appear at dst without ever replacing
// something at dst: a hard link, which fails with EEXIST if dst exists, and
// where the filesystem has no hard links, renameat2 with RENAME_NOREPLACE.
// Something already at dst is left as it is, and the error wraps
// ErrPublishExists. On success src may still exist (a link leaves both names);
// the caller removes it.
func PublishNoReplace(src, dst string) error {
	err := os.Link(src, dst)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrExist):
		return fmt.Errorf("%s: %w", dst, ErrPublishExists)
	case !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.ENOTSUP) && !errors.Is(err, syscall.EOPNOTSUPP) && !errors.Is(err, syscall.EMLINK):
		return err
	}
	// No hard links here: the move must still refuse to replace.
	if renameErr := unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, dst, unix.RENAME_NOREPLACE); renameErr != nil {
		if errors.Is(renameErr, syscall.EEXIST) {
			return fmt.Errorf("%s: %w", dst, ErrPublishExists)
		}
		return fmt.Errorf("publish %s: the filesystem supports neither hard links (%v) nor a rename that refuses to replace (%v)", dst, err, renameErr)
	}
	return nil
}
