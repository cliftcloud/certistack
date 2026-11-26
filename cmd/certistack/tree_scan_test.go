// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import "strings"

// skippedTreeDir is a directory the scans of the source tree leave out:
// version control, dependencies, built output, and hidden directories other
// than .github, which a developer's checkout may hold untracked.
func skippedTreeDir(name string) bool {
	switch name {
	case ".git", "node_modules", "site", "bin", "dist":
		return true
	}
	return strings.HasPrefix(name, ".") && name != "." && name != ".." && name != ".github"
}
