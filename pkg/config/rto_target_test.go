// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// rtoTargetPlanYAML is the reported plan: complete and valid apart from the
// line that gives compliance.rto_target_seconds, which is left out when target
// is empty.
func rtoTargetPlanYAML(target string) []byte {
	targetLine := ""
	if target != "" {
		targetLine = "  rto_target_seconds: " + target + "\n"
	}
	return []byte(fmt.Sprintf(`version: "v1"
plan_id: "audit-rto-target"
name: "Audit RTO Target"

compliance:
  frameworks:
    - "DORA-Article-12"
  retention_days: 90
  sign_key_path: "/synthetic/controller-signing.ed25519"
%s
admission_control:
  max_host_ram_percent: 85.0
  max_host_iowait_percent: 12.0
  defer_retry_interval_sec: 30
  max_defer_retries: 10

network:
  mode: "simple"
  zone_id: "csSb01"
  vnet_id: "csVn01"
  ip_range: "10.100.0.0/24"
  probe_ip: "10.100.0.1"

tiers:
  - level: 1
    name: "Audit tier"
    startup_grace_period_sec: 1
    vms:
      - vmid: 9001
        name: "audit-vm"
        source_pbs:
          storage_id: "pbs"
          snapshot: "vm/100/2026-03-30T02:00:00Z"
          drive: "drive-scsi0"
        probes:
          - type: "tcp"
            target_ip: "10.100.0.10"
            port: 443
            timeout_sec: 1
            description: "Audit TCP probe"
`, targetLine))
}

// The reference said a set rto_target_seconds fails a run whose
// measured RTO exceeds it, and accepted zero, which every enforcement then read
// as "not set": a 42-second run passed an objective of zero seconds, exactly
// like a plan with no objective. Only omission disables the objective now; a
// zero or a negative number is refused by both loaders, naming
// the field and what to do instead.
func TestRTOTargetMustBePositiveOrLeftOut(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		want   float64 // the loaded target when the plan is accepted
		refuse bool
	}{
		{name: "omitted", target: "", want: 0},
		{name: "positive integer", target: "30", want: 30},
		{name: "positive fraction", target: "0.5", want: 0.5},
		{name: "a very small fraction", target: "0.000001", want: 0.000001},
		{name: "explicit zero", target: "0", refuse: true},
		{name: "explicit zero as a float", target: "0.0", refuse: true},
		{name: "negative zero", target: "-0.0", refuse: true},
		{name: "negative", target: "-1", refuse: true},
		{name: "negative fraction", target: "-0.5", refuse: true},
		// A key written with no value is a key left out everywhere in a plan.
		{name: "null is the key left out", target: "null", want: 0},
		{name: "not a number", target: ".nan", refuse: true},
		{name: "infinite", target: ".inf", refuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := rtoTargetPlanYAML(tc.target)
			for loader, load := range map[string]func() (*Plan, error){
				"controller": func() (*Plan, error) { return LoadFromReader(bytes.NewReader(data)) },
				"worker":     func() (*Plan, error) { return LoadFromReaderForWorker(bytes.NewReader(data)) },
			} {
				plan, err := load()
				if tc.refuse {
					if err == nil || !strings.Contains(err.Error(), "compliance.rto_target_seconds") {
						t.Errorf("%s loader: an rto_target_seconds of %q was accepted (err %v), and every run would pass it as if none were set", loader, tc.target, err)
					}
					continue
				}
				if err != nil {
					t.Errorf("%s loader refused rto_target_seconds %q: %v", loader, tc.target, err)
					continue
				}
				if plan.Compliance.RTOTargetSeconds != tc.want {
					t.Errorf("%s loader: rto_target_seconds %q loaded as %v, want %v", loader, tc.target, plan.Compliance.RTOTargetSeconds, tc.want)
				}
				if errs := Validate(plan); len(errs) != 0 {
					t.Errorf("%s loader: Validate refused rto_target_seconds %q: %v", loader, tc.target, errs)
				}
			}
		})
	}
}

// The refusal says what to do. A plan built in code has no record of which
// keys it gave, so zero there is a field left unset and stays accepted;
// negative is refused whichever way the plan was made.
func TestRTOTargetRefusalMessageAndPlansBuiltInCode(t *testing.T) {
	_, err := LoadFromReader(bytes.NewReader(rtoTargetPlanYAML("0")))
	if err == nil || !strings.Contains(err.Error(), "leave") || !strings.Contains(err.Error(), "out") {
		t.Fatalf("the refusal of an explicit zero does not say to leave the key out: %v", err)
	}

	built := validPlan()
	if errs := Validate(built); len(errs) != 0 {
		t.Fatalf("a plan built in code without an objective is refused: %v", errs)
	}
	built.Compliance.RTOTargetSeconds = 30
	if errs := Validate(built); len(errs) != 0 {
		t.Fatalf("a plan built in code with an objective of 30 is refused: %v", errs)
	}
	built.Compliance.RTOTargetSeconds = -1
	refused := false
	for _, e := range Validate(built) {
		refused = refused || e.Field == "compliance.rto_target_seconds"
	}
	if !refused {
		t.Fatal("a negative objective built in code is accepted")
	}
}
