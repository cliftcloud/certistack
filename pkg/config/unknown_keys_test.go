// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"strings"
	"testing"
)

// An unknown key names its plan section, the key the operator probably
// meant and the keys the section accepts, not a Go type: "grace: 480" in a
// tier must not get "field grace not found in type config.Tier".
func TestUnknownPlanKeysAreExplained(t *testing.T) {
	_, err := LoadFromReader(strings.NewReader(`version: v1
tier: 1
tiers:
  - name: core
    grace: 480
    vms:
      - targetVmid: 9001
        name: web
        probes:
          - type: tcp
            tiemout_sec: 30
          - type: tcp
            zzqx: 1
`))
	if err == nil {
		t.Fatal("plan with unknown keys loaded")
	}
	msg := err.Error()
	for _, want := range []string{
		`line 2: unknown key "tier" at the top level of the plan; did you mean "tiers"?`,
		`line 5: unknown key "grace" in tiers[]; did you mean "startup_grace_period_sec"? Keys there: boot_timeout_sec, level, name, soak_time_sec, startup_grace_period_sec, tier, vms`,
		`line 7: unknown key "targetVmid" in tiers[].vms[]; did you mean "target_vmid"?`,
		`line 11: unknown key "tiemout_sec" in tiers[].vms[].probes[]; did you mean "timeout_sec"?`,
		`line 13: unknown key "zzqx" in tiers[].vms[].probes[]. Keys there: `,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "config.") {
		t.Errorf("error names a Go type:\n%s", msg)
	}
}

func TestPlanDecodeErrorKeepsOtherTypeErrors(t *testing.T) {
	_, err := LoadFromReader(strings.NewReader("version: v1\ntiers:\n  - name: core\n    boot_timeout_sec: soon\n"))
	if err == nil || !strings.Contains(err.Error(), "line 4: cannot unmarshal !!str `soon` into int") {
		t.Fatalf("err = %v, want the decoder's own type mismatch", err)
	}
}

// A key that takes a list, written as one value, says it is a list and how to
// write it, not the decoder's "cannot unmarshal !!str `NONE` into []string",
// which names neither the key nor the way out.
func TestAListKeyWrittenAsOneValueSaysItIsAList(t *testing.T) {
	for name, tc := range map[string]struct{ value, want string }{
		"one label":    {"NONE", "line 2: frameworks is a list: write [NONE]"},
		"two labels":   {"DORA, SOC2", "line 2: frameworks is a list: write [DORA, SOC2]"},
		"a quoted one": {`"HIPAA"`, "line 2: frameworks is a list: write [HIPAA]"},
		"an empty one": {`""`, "line 2: frameworks is a list: write [NONE], or the labels you want in brackets"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFromReader(strings.NewReader("compliance:\n  frameworks: " + tc.value + "\n  retention_days: 90\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "cannot unmarshal") {
				t.Errorf("the decoder's own words are still in it: %v", err)
			}
		})
	}
	// A list written the right way is not touched, and a wrong type elsewhere keeps
	// the decoder's own message.
	if _, err := LoadFromReader(strings.NewReader("compliance:\n  frameworks: [NONE]\n  retention_days: soon\n")); err == nil || !strings.Contains(err.Error(), "cannot unmarshal !!str `soon` into int") {
		t.Errorf("err = %v, want the decoder's own message for retention_days", err)
	}
}

func TestPlanSectionsCoverEveryPlanStruct(t *testing.T) {
	for typ, path := range map[string]string{
		"config.Plan":  "",
		"config.Tier":  "tiers[]",
		"config.VM":    "tiers[].vms[]",
		"config.Probe": "tiers[].vms[].probes[]",
	} {
		section, ok := planSections[typ]
		if !ok || section.path != path || len(section.keys) == 0 {
			t.Errorf("%s: section %+v, want path %q with keys", typ, section, path)
		}
	}
	for _, key := range planSections["config.VM"].keys {
		if key == "-" || key == "" {
			t.Errorf("VM keys include %q", key)
		}
	}
}

func TestNearestKeys(t *testing.T) {
	keys := []string{"boot_timeout_sec", "name", "soak_time_sec", "startup_grace_period_sec", "vms"}
	for unknown, want := range map[string]string{
		"BootTimeoutSec": "boot_timeout_sec",
		"boot-timeout":   "boot_timeout_sec",
		"grace":          "startup_grace_period_sec",
		"nmae":           "name",
		"vm":             "vms",
		"xq":             "",
		"qqqqqq":         "",
	} {
		if got := strings.Join(nearestKeys(unknown, keys), ","); got != want {
			t.Errorf("nearestKeys(%q) = %q, want %q", unknown, got, want)
		}
	}
}
