// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultScratchDir is the private node-local directory for temporary
// recovery overlays and diagnostic artifacts.
const DefaultScratchDir = "/var/lib/certistack/scratch"

// EnsurePrivateDirectory creates path when absent and verifies that it is a
// private directory owned by the current process user. It never changes the
// mode or ownership of an existing directory.
func EnsurePrivateDirectory(path string) error {
	if err := validatePrivateDirectoryPath(path); err != nil {
		return err
	}
	if err := validateNoSymlinkComponents(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("create private directory: %w", err)
	}
	return ValidatePrivateDirectory(path)
}

// CheckPrivateDirectory says, changing nothing, whether EnsurePrivateDirectory
// would succeed on path: an existing directory must pass ValidatePrivateDirectory,
// and a missing one must be creatable, meaning its nearest existing ancestor
// is a directory this process can create in. existed reports which it was. A
// diagnostic uses it for a directory the worker will prepare.
func CheckPrivateDirectory(path string) (existed bool, err error) {
	if err := validatePrivateDirectoryPath(path); err != nil {
		return false, err
	}
	if err := validateNoSymlinkComponents(path); err != nil {
		return false, err
	}
	_, err = os.Lstat(path)
	if err == nil {
		return true, ValidatePrivateDirectory(path)
	}
	if !os.IsNotExist(err) {
		return false, fmt.Errorf("stat private directory: %w", err)
	}
	for ancestor := filepath.Dir(path); ; ancestor = filepath.Dir(ancestor) {
		info, statErr := os.Stat(ancestor)
		if statErr == nil {
			if !info.IsDir() {
				return false, fmt.Errorf("%s exists but is not a directory, so %s cannot be created", ancestor, path)
			}
			if err := writableDirectory(ancestor); err != nil {
				return false, fmt.Errorf("%s does not exist and cannot be created: %w", path, err)
			}
			return false, nil
		}
		if !os.IsNotExist(statErr) {
			return false, fmt.Errorf("inspect %s: %w", ancestor, statErr)
		}
		if filepath.Dir(ancestor) == ancestor {
			return false, fmt.Errorf("no part of %s exists", path)
		}
	}
}

// ValidatePrivateDirectory verifies a caller-owned directory without changing
// its permissions or following any symlink in the path.
func ValidatePrivateDirectory(path string) error {
	if err := validatePrivateDirectoryPath(path); err != nil {
		return err
	}
	if err := validateNoSymlinkComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat private directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private directory must not be a symlink")
	}
	if !info.IsDir() {
		return fmt.Errorf("private directory is not a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		return fmt.Errorf("private directory must have mode 0700 (got %04o)", info.Mode().Perm())
	}
	if err := validatePrivateDirectoryOwner(info); err != nil {
		return err
	}
	return nil
}

func validateNoSymlinkComponents(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("private directory path must not traverse symlink %s", current)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect private directory path: %w", err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func validatePrivateDirectoryPath(path string) error {
	if path == "" {
		return fmt.Errorf("private directory path must not be empty")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("private directory path must be absolute")
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("private directory path must be clean")
	}
	if path == string(filepath.Separator) {
		return fmt.Errorf("filesystem root cannot be a private directory")
	}
	for _, sharedPath := range []string{"/tmp", "/var/tmp", filepath.Clean(os.TempDir())} {
		if path == sharedPath {
			return fmt.Errorf("shared temporary directory %s is not allowed", path)
		}
	}
	return nil
}
