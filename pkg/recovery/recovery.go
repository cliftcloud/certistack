// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package recovery exposes safe crash recovery for programs built on the
// CertiStack Community engine.
package recovery

import internal "github.com/cliftcloud/certistack/internal/recovery"

// Recover reconciles the resources recorded for an interrupted run.
func Recover(stateDir string) error {
	return internal.Recover(stateDir)
}
