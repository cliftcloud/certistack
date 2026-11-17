// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"fmt"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// refusedReportError is the controller refusing the report a worker returned:
// it is one the controller will not sign, as opposed to one it failed to sign
// or to save. Its message is the wrapped error's.
type refusedReportError struct{ error }

func (e refusedReportError) Unwrap() error { return e.error }

// keepUnsignedResult keeps the raw result of a worker whose report the
// controller checked and found fine, and could not sign (the signer failed): the
// same file in the same place as a refused one, under a first line that says the
// result passed the checks and the signing is what failed.
func keepUnsignedResult(outputDir, runID string, signingErr error, raw []byte) string {
	path, err := attest.SaveUnsignedResult(outputDir, runID, signingErr.Error(), raw)
	if err != nil {
		return fmt.Sprintf("The worker's raw result could not be kept: %v.", err)
	}
	return fmt.Sprintf("The worker's result passed the controller's checks and is kept at %s for diagnosis; it was never signed, it is not evidence, and no report check or evidence store reads it.", path)
}

// keepRefusedResult keeps the raw result of a worker whose report the
// controller refused, as <output>/refused/<run-id>.refused.txt (see
// attest.SaveRefusedResult), and says where, in a sentence for the operator.
// The result would otherwise be lost with the node workspace, and with it
// what the worker said about a run that may have restored a customer's
// backup. Keeping it is never an error of the run: the run is refused either
// way, and a result that cannot be kept is said.
func keepRefusedResult(outputDir, runID string, refusal error, raw []byte) string {
	path, err := attest.SaveRefusedResult(outputDir, runID, refusal.Error(), raw)
	if err != nil {
		return fmt.Sprintf("The worker's raw result could not be kept: %v.", err)
	}
	return fmt.Sprintf("The worker's raw result is kept at %s for diagnosis; it is not evidence, was never signed, and no report check or evidence store reads it.", path)
}
