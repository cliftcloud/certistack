// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import "errors"

// onePlanPath refuses a plan named both as the argument and with --plan, as
// validate does: one of the two would be discarded, and the operator would
// believe the other constrained the command. It runs first, before
// any file is read.
func onePlanPath(args []string, flag string) error {
	if len(args) > 0 && flag != "" {
		return errors.New("pass the plan path either as an argument or via --plan, not both")
	}
	return nil
}
