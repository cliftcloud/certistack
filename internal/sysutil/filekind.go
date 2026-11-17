// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import "os"

// FileKind names what a file of mode is, for a message that refuses it as not
// a regular file: "a directory", "a named pipe", "a socket", "a device", or
// "not a regular file".
func FileKind(mode os.FileMode) string {
	switch {
	case mode.IsRegular():
		return "a regular file"
	case mode.IsDir():
		return "a directory"
	case mode&os.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&os.ModeSocket != 0:
		return "a socket"
	case mode&os.ModeDevice != 0:
		return "a device"
	}
	return "not a regular file"
}
