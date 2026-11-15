//go:build !unix && !windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import "os"

// This platform has no no-follow or non-blocking open. The caller still
// refuses a path that is not the regular file it inspected.
func openInput(path string, _ bool) (*os.File, error) {
	return os.Open(path)
}

func createExclusive(path string, perm os.FileMode, _ bool) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
}

func replaceFile(from, to string) error {
	return os.Rename(from, to)
}

func renameNoReplace(from, to string) error {
	return linkNoReplace(from, to)
}

func syncDirectory(string) error {
	return nil
}

func linkUnsupported(error) bool {
	return true
}
