// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// quoteForShell is word as one shell word: unchanged when it holds only
// characters a shell leaves alone, else in single quotes. It is for commands
// printed in advice, which a newcomer copies.
func quoteForShell(word string) string {
	if word != "" && !strings.ContainsFunc(word, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_-./:@%+=,", r))
	}) {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
}

// mkdirCommand is the command that creates dir and the directories above it.
func mkdirCommand(dir string) string {
	if runtime.GOOS == "windows" {
		if strings.ContainsAny(dir, " \t") {
			return `mkdir "` + dir + `"`
		}
		return "mkdir " + dir
	}
	return "mkdir -p " + quoteForShell(dir)
}

// missingOutputDirectory says which directory the plan was to go into is not
// there, and the command that makes it.
func missingOutputDirectory(dir string) error {
	return fmt.Errorf("the directory %s for --output does not exist; create it with: %s (or choose another --output)", dir, mkdirCommand(dir))
}

// outputDirectoryError turns a failure to create a file in dir into a one-line
// cause.
func outputDirectoryError(dir string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return missingOutputDirectory(dir)
	}
	reason := err
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		reason = pathErr.Err
	}
	return fmt.Errorf("cannot write to %s for --output (%v); make it writable for this user, or choose another --output", describeDirectory(dir), reason)
}

// describeDirectory is "the directory dir", and for the current directory, which
// is what a relative output without a directory means, its full name.
func describeDirectory(dir string) string {
	if dir == "." {
		if abs, err := filepath.Abs(dir); err == nil {
			return "the current directory " + abs
		}
		return "the current directory"
	}
	return "the directory " + dir
}

// checkPlanOutputDirectory refuses, before init reads anything, an output whose
// directory is not there or cannot be written, so a newcomer does not wait for
// the node to find out. It creates a file in the directory and removes it again,
// which is the only test that agrees with what writing the plan will find.
func checkPlanOutputDirectory(output string) error {
	dir := filepath.Dir(output)
	switch info, err := os.Stat(dir); {
	case errors.Is(err, fs.ErrNotExist):
		return missingOutputDirectory(dir)
	case err == nil && !info.IsDir():
		return fmt.Errorf("the directory of %s is not a directory", output)
	}
	probe, err := os.CreateTemp(dir, ".certistack-write-check.*")
	if err != nil {
		return outputDirectoryError(dir, err)
	}
	name := probe.Name()
	probe.Close()
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("cannot remove the file init created in %s to test it (%v); remove %s and choose another --output", dir, err, name)
	}
	return nil
}

// missingDirectoryNote is what to add to the error of a file that is not there
// when its directory is not there either: the first run has not happened yet,
// and certistack setup makes the directory.
func missingDirectoryNote(path string, err error) string {
	if !errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	dir := filepath.Dir(path)
	if _, statErr := os.Stat(dir); !errors.Is(statErr, fs.ErrNotExist) {
		return ""
	}
	return fmt.Sprintf(" (the directory %s does not exist either)", dir)
}
