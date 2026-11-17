// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package acceptance

import (
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// sharedTargets refuses a report in which passing wire probes of two VM
// records name one address (attest.SharedWireTargetProblems): a probe shows
// that its target answered, not which guest answered, so the pass of each VM
// would rest on one answer. It needs no plan, and applies to every report
// the verdict accepts as a pass or as a fault drill.
func (c *acceptanceCheck) sharedTargets(records []probe.VMValidationRecord) {
	for _, problem := range attest.SharedWireTargetProblems(records) {
		c.reject("%s", problem)
	}
}
