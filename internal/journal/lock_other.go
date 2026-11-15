//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

import (
	"errors"
	"os"
)

// Lock fails closed because this package has no portable host-wide lock implementation.
func Lock() (*os.File, error) {
	return nil, errors.New("host lock is unsupported on this platform")
}
