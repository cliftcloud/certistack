//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import "context"

// StaleFUSELoopDevices has nothing to list: PBS maps exist only on Linux nodes.
func StaleFUSELoopDevices() []string { return nil }

// ReleaseStaleFUSELoopsSince releases nothing: PBS maps exist only on Linux nodes.
func ReleaseStaleFUSELoopsSince(context.Context, []string, int) ([]string, []error) { return nil, nil }
