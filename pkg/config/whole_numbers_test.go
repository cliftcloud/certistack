// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// wholeNumberPlan is the multi-tier fixture, decoded for editing, with the
// int keys the table below needs and the fixture does not have.
func wholeNumberPlan(t *testing.T) any {
	t.Helper()
	doc := readPlanDocument(t, filepath.Join("..", "..", "testdata", "plans", "multi_tier_sandbox.yaml"))
	setPath(doc, "admission_control.max_concurrent_boots", 2)
	ensureMap(t, doc, "storage")
	setPath(doc, "storage.max_copy_gib", 100)
	setPath(doc, "tiers[0].vms[0].probes[0].retries", 3)
	setPath(doc, "tiers[1].boot_timeout_sec", 90)
	setPath(doc, "tiers[1].soak_time_sec", 60)
	return doc
}

// planWith is the fixture with the key at path written as raw, the text of the
// number exactly as an author would type it (a marshalled float would drop the
// ".0").
func planWith(t *testing.T, path, raw string) string {
	t.Helper()
	doc := wholeNumberPlan(t)
	setPath(doc, path, "ZZ-RAW-ZZ")
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "ZZ-RAW-ZZ") {
		t.Fatalf("%s: the marker is not in the plan:\n%s", path, text)
	}
	return strings.Replace(text, "ZZ-RAW-ZZ", raw, 1)
}

// An int key took a decimal and cut it, so "retention_days: 2555.9" ran as 2555
// and "port: 5432.7" probed 5432. Both loaders refuse a number that is not
// whole, in an int key at any depth, naming the line, the key's path and the
// value as written; a number that is whole however it is spelled (45.0, 45.,
// 45e0) is the integer it says, as the decoder has always read it.
func TestAnIntKeyRefusesANumberThatIsNotWhole(t *testing.T) {
	for _, tc := range []struct {
		path  string
		whole int
	}{
		{"compliance.retention_days", 90},
		{"admission_control.defer_retry_interval_sec", 5},
		{"admission_control.max_defer_retries", 2},
		{"admission_control.max_concurrent_boots", 2},
		{"storage.max_copy_gib", 100},
		{"tiers[0].level", 1},
		{"tiers[1].level", 2},
		{"tiers[0].startup_grace_period_sec", 5},
		{"tiers[1].boot_timeout_sec", 90},
		{"tiers[1].soak_time_sec", 60},
		{"tiers[0].vms[0].vmid", 9110},
		{"tiers[1].vms[0].source_vmid", 120},
		{"tiers[0].vms[0].hardware_overrides.cores", 2},
		{"tiers[0].vms[0].hardware_overrides.memory_mb", 2048},
		{"tiers[0].vms[0].hardware_overrides.cpu_weight", 50},
		{"tiers[0].vms[0].probes[0].port", 389},
		{"tiers[0].vms[0].probes[0].retries", 3},
		{"tiers[0].vms[0].probes[1].port", 53},
		{"tiers[0].vms[0].probes[1].timeout_sec", 30},
		{"tiers[1].vms[0].probes[0].timeout_sec", 45},
	} {
		t.Run(tc.path, func(t *testing.T) {
			// The fixture loads with its own value, so only the spelling is tested.
			if _, err := loadText(t, planWith(t, tc.path, fmt.Sprint(tc.whole))); err != nil {
				t.Fatalf("the fixture with %s = %d: %v", tc.path, tc.whole, err)
			}
			for _, notWhole := range []string{
				fmt.Sprintf("%d.9", tc.whole),
				fmt.Sprintf("%d.5", tc.whole),
				fmt.Sprintf("%d.0000000000000001", tc.whole), // not 2555 to the nearest float64, but not 2555
				fmt.Sprintf("%d.25e0", tc.whole),
				"0.5",
				".5",
			} {
				_, err := loadText(t, planWith(t, tc.path, notWhole))
				want := fmt.Sprintf("%s must be a whole number, not %s", tc.path, notWhole)
				if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "line ") {
					t.Errorf("%s = %s: err %v, want one naming a line and %q", tc.path, notWhole, err, want)
				}
			}
			for _, whole := range []string{
				fmt.Sprintf("%d.0", tc.whole),
				fmt.Sprintf("%d.", tc.whole),
				fmt.Sprintf("%de0", tc.whole),
				fmt.Sprintf("+%d.00", tc.whole),
			} {
				plan, err := loadText(t, planWith(t, tc.path, whole))
				if err != nil {
					t.Errorf("%s = %s is the whole number %d: %v", tc.path, whole, tc.whole, err)
					continue
				}
				if got := planDigestOf(t, plan); got != planDigestOf(t, mustLoadText(t, planWith(t, tc.path, fmt.Sprint(tc.whole)))) {
					t.Errorf("%s = %s did not load as %d", tc.path, whole, tc.whole)
				}
			}
		})
	}
}

func mustLoadText(t *testing.T, text string) *Plan {
	t.Helper()
	plan, err := loadText(t, text)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// planDigestOf is the plan as the worker receives it, so two plans with one
// digest hold the same values in every key.
func planDigestOf(t *testing.T, plan *Plan) string {
	t.Helper()
	digest, err := CanonicalWorkerPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// A number the decoder reads as a float and that is not finite is not whole.
// The decoder refuses .inf and .nan for an int key by itself (naming the line
// and the value); it accepts -.inf, as the smallest integer, so that one the
// loader refuses here, by the key's path.
func TestAnIntKeyRefusesInfinityAndNaN(t *testing.T) {
	for _, raw := range []string{".inf", "-.inf", ".Inf", ".NaN", ".nan"} {
		_, err := loadText(t, planWith(t, "compliance.retention_days", raw))
		if err == nil || !strings.Contains(err.Error(), raw) {
			t.Errorf("retention_days = %s: err %v, want a refusal naming it", raw, err)
		}
	}
	_, err := loadText(t, planWith(t, "compliance.retention_days", "-.inf"))
	if want := "compliance.retention_days must be a whole number, not -.inf"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("retention_days = -.inf: err %v, want %q", err, want)
	}
}

// A key that is a float in the plan still takes a decimal, and a string key is
// not an int key: only the int keys are held to whole numbers.
func TestFloatKeysStillTakeDecimals(t *testing.T) {
	for path, raw := range map[string]string{
		"compliance.rto_target_seconds":               "180.5",
		"admission_control.max_host_ram_percent":      "90.5",
		"admission_control.max_host_iowait_percent":   "12.25",
		"tiers[0].vms[0].probes[0].description":       "1.5",
		"tiers[0].vms[0].source_pbs.drives[0].slot":   "scsi0",
		"tiers[0].vms[0].network_recovery.sandbox_ip": "192.0.2.10",
	} {
		if _, err := loadText(t, planWith(t, path, raw)); err != nil {
			t.Errorf("%s = %s: %v", path, raw, err)
		}
	}
}

// Every offender is named, in the order the file gives them, in one refusal,
// whatever the style of the YAML (block, flow or the JSON subset), and the
// older alias keys and keys behind a merge are held to the same rule.
func TestEveryNumberThatIsNotWholeIsNamedInFileOrder(t *testing.T) {
	text := `version: v1
plan_id: handwritten
name: handwritten
compliance: {frameworks: [DORA], retention_days: 2555.9}
admission: {max_host_ram_percent: 85, max_host_iowait_percent: 12, defer_retry_interval_sec: 30.5, max_defer_retries: 10}
network: {mode: simple, zone_id: csSb01, vnet_id: csVn01, ip_range: 10.100.0.0/24, probe_ip: 10.100.0.1}
tiers:
  - tier: 1.5
    name: t
    vms:
      - target_vmid: 9001
        name: dc
        source_pbs: {storage_id: pbs, snapshot: vm/100/latest, drive: drive-scsi0}
        probes:
          - &base {type: tcp, target_ip: 10.100.0.10, port: 389, description: ldap, timeout_sec: 4.5}
          - <<: *base
            port: 636
`
	_, err := loadText(t, text)
	if err == nil {
		t.Fatal("the plan loaded")
	}
	var last int
	for _, want := range []string{
		"line 4: compliance.retention_days must be a whole number, not 2555.9",
		"line 5: admission.defer_retry_interval_sec must be a whole number, not 30.5",
		"line 8: tiers[0].tier must be a whole number, not 1.5",
		"line 15: tiers[0].vms[0].probes[0].timeout_sec must be a whole number, not 4.5",
		"line 15: tiers[0].vms[0].probes[1].timeout_sec must be a whole number, not 4.5",
	} {
		at := strings.Index(err.Error(), want)
		if at < 0 {
			t.Errorf("the error lacks %q:\n%s", want, err)
			continue
		}
		if at < last {
			t.Errorf("%q is out of file order in:\n%s", want, err)
		}
		last = at
	}
	if strings.Count(err.Error(), "must be a whole number") != 5 {
		t.Errorf("the error names other keys than the five that are not whole:\n%s", err)
	}

	// The same plan in JSON, which is YAML, names the same keys.
	_, err = loadText(t, `{"version": "v1", "plan_id": "j", "name": "j", "compliance": {"frameworks": ["DORA"], "retention_days": 2555.9}}`)
	if err == nil || !strings.Contains(err.Error(), "compliance.retention_days must be a whole number, not 2555.9") {
		t.Errorf("a JSON plan: %v", err)
	}
}

// Once every int key holds a whole number the plan is judged as before: a
// number that is whole but out of range is refused for its range, by the rule
// that names the bound.
func TestAWholeNumberOutOfRangeIsStillRefusedForItsRange(t *testing.T) {
	_, err := loadText(t, planWith(t, "compliance.retention_days", "36501.0"))
	if err == nil || strings.Contains(err.Error(), "whole number") || !strings.Contains(validationText(err), "compliance.retention_days") {
		t.Errorf("36501.0: %v", err)
	}
}
