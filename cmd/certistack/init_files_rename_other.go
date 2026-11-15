//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import "errors"

// errRenameWithoutReplacingUnsupported says a file cannot be renamed here
// without possibly replacing the name it takes.
var errRenameWithoutReplacingUnsupported = errors.New("renaming without replacing is not supported here")

// renameWithoutReplacing is not available off Linux: the caller falls back to
// creating the final name exclusively and copying the plan into it.
func renameWithoutReplacing(staged, path string) error {
	return errRenameWithoutReplacingUnsupported
}
