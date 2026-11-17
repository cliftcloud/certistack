//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import "os"

// dropDevicePages is a no-op: PBS maps exist only on Linux nodes.
func dropDevicePages(*os.File, int64, int64) {}

// flushCopyRange writes f to disk.
func flushCopyRange(f *os.File, _, _ int64) error { return f.Sync() }
