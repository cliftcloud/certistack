// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IsMountPoint reports whether path, with symbolic links resolved, is where a
// file system is mounted according to the kernel's mount table
// (/proc/self/mountinfo). A directory that exists beneath an absent mount is
// not one: it is an ordinary directory of the file system underneath.
func IsMountPoint(path string) (bool, error) {
	return isMountPoint(mountInfoPath, path)
}

func isMountPoint(mountInfo, path string) (bool, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, err
	}
	file, err := os.Open(mountInfo)
	if err != nil {
		return false, fmt.Errorf("read the mount table: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		// id parent major:minor root mount-point options ...
		fields := strings.Fields(scanner.Text())
		if len(fields) > 4 && unescapeMountPath(fields[4]) == real {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("read the mount table: %w", err)
	}
	return false, nil
}
