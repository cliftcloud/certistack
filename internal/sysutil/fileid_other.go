//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"errors"
	"fmt"
	"os"

	"github.com/cliftcloud/certistack/internal/journal"
)

// FileIdentityOf is unavailable off Linux: the worker runs on a Proxmox node,
// and nothing here may claim a file is this run's without the kernel's word.
func FileIdentityOf(path string) (journal.FileIdentity, error) {
	if _, err := os.Lstat(path); err != nil {
		return journal.FileIdentity{}, err
	}
	return journal.FileIdentity{}, fmt.Errorf("%s: %w", path, errors.New("file identity needs Linux"))
}

// PublishNoReplace refuses to replace: with a hard link, which fails when dst exists.
func PublishNoReplace(src, dst string) error {
	if err := os.Link(src, dst); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s: %w", dst, ErrPublishExists)
		}
		return err
	}
	return nil
}
