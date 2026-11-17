// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"bytes"
	"testing"
)

// The YAML encoder writes some texts in a form it does not read back as the
// same text: "\n" is read as "", "\na" as "a", and "\t\n" or "\ta\nb" is not
// read at all ("found a tab character where an indentation space is
// expected"). The worker plan carries every text unchanged, so the worker a
// plan with such a description or expected output is sent to neither refuses
// it nor runs with another description, and the report's
// validated_plan_sha256 matches the plan (verify-report --expect-plan).
func TestTheWorkerGetsEveryTextOfThePlanUnchanged(t *testing.T) {
	for _, text := range []string{"\n", "\n\n", "\t\n", "\ta\nb", "\na", "\n\na", "\n\ta", " \n", "a\n\t\n"} {
		built := validPlan()
		built.Tiers[0].VMs[0].Probes[0].Description = text
		data, err := MarshalWorkerPlan(built)
		if err != nil {
			t.Fatal(err)
		}
		// The plan as the controller loads it, and as the worker loads what
		// the controller sends it.
		plan, err := LoadFromReader(bytes.NewReader(data))
		if err != nil {
			t.Errorf("%q: the controller refuses the plan: %v\n%s", text, err, data)
			continue
		}
		worker, err := CopyWorkerPlan(plan)
		if err != nil {
			t.Errorf("%q: the worker refuses the plan it is sent: %v", text, err)
			continue
		}
		if got := worker.Tiers[0].VMs[0].Probes[0].Description; got != text {
			t.Errorf("%q: the worker reads the description as %q", text, got)
		}
		sent, _ := CanonicalWorkerPlanSHA256(plan)
		seen, _ := CanonicalWorkerPlanSHA256(worker)
		if sent != seen {
			t.Errorf("%q: the worker's plan digest differs from the controller's", text)
		}
	}
}
