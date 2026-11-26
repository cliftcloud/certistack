// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package nodeapi defines the result a CertiStack node worker returns to its
// controller.
package nodeapi

import "github.com/cliftcloud/certistack/pkg/attest"

// RunResult is written as one JSON document to the worker's standard output.
// A completed run may contain a report and an Error at the same time: a failed
// run still produces evidence. Transport failures are reported by the
// controller separately and never use this structure.
type RunResult struct {
	Report *attest.Report `json:"report,omitempty"`
	Error  string         `json:"error,omitempty"`
}
