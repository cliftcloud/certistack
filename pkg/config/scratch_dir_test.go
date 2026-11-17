// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"strings"
	"testing"
)

// validate refuses the storage.scratch_dir values run refuses ("/tmp", "/", a
// relative path or "/a/../tmp"), at the key, so they do not pass validate and
// plan only to stop the run when it reads the plan.
func TestValidateRefusesTheScratchDirectoryARunRefuses(t *testing.T) {
	for dir, refused := range map[string]bool{
		"/var/lib/certistack/scratch":   false,
		" /var/lib/certistack/scratch ": false, // a run trims it
		"/srv/certistack-scratch":       false,
		"/tmp":                          true,
		"/var/tmp":                      true,
		"/dev/shm":                      true,
		"/":                             true,
		"scratch":                       true,
		"./scratch":                     true,
		"/var/lib/../tmp":               true,
		"/var/lib/certistack/scratch/":  true,
		"/var//lib":                     true,
		"/var/lib\\scratch":             true,
	} {
		plan := validPlan()
		plan.Storage.ScratchDir = dir
		var problems []string
		for _, problem := range Validate(plan) {
			if problem.Field == "storage.scratch_dir" {
				problems = append(problems, problem.Message)
			}
		}
		if (len(problems) > 0) != refused {
			t.Errorf("scratch_dir %q: refused = %v (%s), want %v", dir, len(problems) > 0, strings.Join(problems, "; "), refused)
		}
	}
}
