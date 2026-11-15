// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import "strings"

// EffectiveScratchDir is the scratch directory a run of plan uses: a value
// given explicitly (a flag, or CERTISTACK_SCRATCH_DIR) first, then the plan's
// own storage.scratch_dir, then fallback. Run, plan and doctor resolve it here
// so that they look at the same directory; doctor and node-local plan used to
// take their flag's default without asking the plan, and diagnosed a different
// filesystem than the run would use. It only decides: whether the
// directory is private, safe and roomy is the caller's check. plan may be nil.
func EffectiveScratchDir(explicit string, plan *Plan, fallback string) string {
	if explicit != "" {
		return explicit
	}
	if plan != nil {
		if dir := strings.TrimSpace(plan.Storage.ScratchDir); dir != "" {
			return dir
		}
	}
	return fallback
}
