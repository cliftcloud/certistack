//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

import "syscall"

// openNonBlocking opens without waiting for a writer when a named pipe is in
// place of a regular file; the opened file is then refused.
const openNonBlocking = syscall.O_NONBLOCK
