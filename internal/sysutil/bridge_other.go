//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

// ifupdownRunning: ifupdown2 runs only on a Linux PVE node.
func ifupdownRunning() bool { return false }

// ifupdownState: nothing runs, and nothing is unknown.
func ifupdownState() (busy bool, unknown string) { return false, "" }
