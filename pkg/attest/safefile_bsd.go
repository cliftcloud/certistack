//go:build unix && !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

// renameNoReplace publishes from at to with a hard link, which is atomic and
// fails if to exists.
func renameNoReplace(from, to string) error {
	return linkNoReplace(from, to)
}
