// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package nodeapi defines the narrow, versioned response contract between a
// CertiStack controller and its short-lived node worker.
package nodeapi

import "github.com/cliftcloud/certistack/pkg/attest"

// RunResult is written as one JSON document to the worker's standard output.
// A completed validation may contain a report and an Error at the same time:
// failed validations still produce evidence. Transport failures are reported
// by the controller separately and never use this structure.
type RunResult struct {
	Report *attest.Report `json:"report,omitempty"`
	Error  string         `json:"error,omitempty"`
}
