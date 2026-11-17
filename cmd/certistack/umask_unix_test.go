// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build unix

package main

import "syscall"

// The tests make report directories with t.TempDir, whose mode follows the
// umask. Ubuntu gives a normal user umask 002, which makes them group-writable,
// and a run refuses a report directory that group or other users can write
// (each test of that refusal sets the mode it means). So the tests fix the
// umask to the common 022, wherever they run.
func init() { syscall.Umask(0o022) }
