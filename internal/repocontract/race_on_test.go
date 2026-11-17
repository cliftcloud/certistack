// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build race

package repocontract

// raceEnabled lets a test that compiles the whole controller run once, in the
// plain run, instead of again under the race detector.
const raceEnabled = true
