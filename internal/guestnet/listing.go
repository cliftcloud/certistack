// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"strings"
	"unicode/utf8"
)

// listingEntries are the entries of a guestfish "ls" result. guestfish prints
// one entry per line, exactly as the file system holds it, so a name with a
// space in it ("Wired connection 1.nmconnection", NetworkManager's own default
// for an automatic connection) is one entry. Splitting on white space instead
// (strings.Fields) cut it into "Wired", "connection" and "1.nmconnection" and
// sent the seed copy to a file that does not exist. A name is never
// trimmed: a trailing space is part of it.
func listingEntries(output string) []string {
	var entries []string
	for _, line := range strings.Split(output, "\n") {
		if line != "" {
			entries = append(entries, line)
		}
	}
	return entries
}

// safeEntryName reports whether a directory entry's name can be joined to its
// directory and handed to guestfish as one argument. Spaces, tabs, a leading
// dash and non-ASCII letters are ordinary file names and are kept; what
// cannot be kept is a name the line-oriented listing cannot carry or that is
// not one path component: an empty name, "." or "..", a "/", a NUL or other
// control character (a newline or carriage return would also have split the
// listing into entries that never existed), and bytes that are not UTF-8.
func safeEntryName(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r == '/' || r == 0x7f || (r < 0x20 && r != '\t') {
			return false
		}
	}
	return true
}
