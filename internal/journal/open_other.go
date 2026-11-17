//go:build !unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

// openNonBlocking is unneeded where a file cannot be a named pipe.
const openNonBlocking = 0
