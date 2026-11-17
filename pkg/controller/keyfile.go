// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/cliftcloud/certistack/pkg/pbs"
)

const maxKeyfileSourceBytes = 64 << 10

func checkKeyfileInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("PBS encryption key must be a regular file, not a symlink or device")
	}
	if info.Size() == 0 || info.Size() > maxKeyfileSourceBytes {
		return fmt.Errorf("PBS encryption key is not a key file (size %d bytes)", info.Size())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("PBS encryption key is accessible to other users (mode %04o); make it owner-only (chmod 600)", info.Mode().Perm())
	}
	return nil
}

// readKeyfileSource validates the original key, then reads from that same
// checked descriptor. A protected staging copy must not hide unsafe source
// permissions, or reopen a path that changed after validation.
func readKeyfileSource(source string) ([]byte, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return nil, fmt.Errorf("PBS encryption key (CERTISTACK_PBS_KEYFILE): %w", err)
	}
	if err := checkKeyfileInfo(info); err != nil {
		return nil, err
	}
	f, err := openKeyfileSource(source)
	if err != nil {
		return nil, fmt.Errorf("open PBS encryption key: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened PBS encryption key: %w", err)
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("PBS encryption key changed while opening it")
	}
	if err := checkKeyfileInfo(opened); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyfileSourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read PBS encryption key: %w", err)
	}
	if len(data) == 0 || len(data) > maxKeyfileSourceBytes {
		return nil, fmt.Errorf("PBS encryption key is not a key file (read %d bytes)", len(data))
	}
	return data, nil
}

func stagePBSKeyfile(source, destination, passphrase string) error {
	data, err := readKeyfileSource(source)
	if err != nil {
		return err
	}
	if err := os.WriteFile(destination, data, 0600); err != nil {
		return err
	}
	// Check the bytes that will be uploaded, without reopening the source.
	return pbs.CheckKeyPassphrase(destination, passphrase)
}
