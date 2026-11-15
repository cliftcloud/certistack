// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import "strings"

// unescapeMountPath undoes the octal escapes (\040 for a space, \011,
// \012, \134) the kernel writes into mountinfo paths.
func unescapeMountPath(field string) string {
	if !strings.Contains(field, `\`) {
		return field
	}
	var b strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+3 < len(field) && isOctal(field[i+1]) && isOctal(field[i+2]) && isOctal(field[i+3]) {
			b.WriteByte(byte(int(field[i+1]-'0')<<6 | int(field[i+2]-'0')<<3 | int(field[i+3]-'0')))
			i += 3
			continue
		}
		b.WriteByte(field[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }
