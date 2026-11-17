// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package telemetry

import "os"

// tryLock is a no-op where this build has no flock (Windows and the rest): the
// state file's changes are not serialized there, and the opt-out still works.
func tryLock(*os.File) (bool, error) { return true, nil }

// stateLockSerializes is false here: tryLock excludes no one.
const stateLockSerializes = false

func releaseLock(*os.File) {}
