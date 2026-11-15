// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validateFixture validates the repository's valid plan after replacing each
// old text of replacements (pairs) with its new one, and returns the output.
func validateFixture(t *testing.T, replacements ...string) (string, error) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for i := 0; i < len(replacements); i += 2 {
		if !strings.Contains(text, replacements[i]) {
			t.Fatalf("the fixture has no %q", replacements[i])
		}
		text = strings.ReplaceAll(text, replacements[i], replacements[i+1])
	}
	path := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = runRoot(t, &out, "validate", path)
	return out.String(), err
}

// validate prints, under a valid plan's summary, a "!" line for what it cannot
// judge and a reader should check. None of them fails the plan.
func TestValidateNotesWhatItCannotJudge(t *testing.T) {
	clearControllerEnvironment(t)
	const (
		rangeNote = "network.ip_range 10.50.0.0/24 is not one of the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)"
		planCheck = "plan checks the range against the node"
	)
	for _, tc := range []struct {
		name  string
		edits []string
		want  []string
	}{
		{"a range that is not a documentation range",
			[]string{`ip_range: "192.0.2.0/24"`, `ip_range: "10.50.0.0/24"`, `probe_ip: "192.0.2.1"`, `probe_ip: "10.50.0.1"`, `target_ip: "192.0.2.`, `target_ip: "10.50.0.`},
			[]string{"  ! " + rangeNote, planCheck}},
		{"a vnet_id a host bridge has",
			[]string{`vnet_id: "csVn01"`, `vnet_id: "vmbr0"`},
			[]string{"  ! network.vnet_id vmbr0 is a name a host bridge has", "csVnet01"}},
		{"a zone_id a host bridge has",
			[]string{`zone_id: "csSb01"`, `zone_id: "vmbr1"`},
			[]string{"  ! network.zone_id vmbr1 is a name a host bridge has", "csZone01"}},
		{"overlay storage local",
			[]string{"\ntiers:\n", "\nstorage:\n  overlay_storage: \"local\"\n\ntiers:\n"},
			[]string{"  ! storage.overlay_storage local is Proxmox VE's default storage, on the node's system disk"}},
		{"overlay storage local-lvm",
			[]string{"\ntiers:\n", "\nstorage:\n  overlay_storage: \"local-lvm\"\n\ntiers:\n"},
			[]string{"  ! storage.overlay_storage local-lvm is Proxmox VE's default LVM-thin storage", "not file-based"}},
		{"memory above 95 percent",
			[]string{"max_host_ram_percent: 85.0", "max_host_ram_percent: 98.0"},
			[]string{"  ! admission_control.max_host_ram_percent 98 lets a run fill the node's memory", "init writes 85.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := validateFixture(t, tc.edits...)
			if err != nil {
				t.Fatalf("a note must not fail the plan: %v\n%s", err, out)
			}
			if !strings.Contains(out, "✓ Plan is valid") {
				t.Fatalf("the plan is not reported valid:\n%s", out)
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("the output lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

// A plan that does none of those gets no note, and a range inside a
// documentation range, or equal to one, needs none.
func TestValidateNotesNothingForAnOrdinaryPlan(t *testing.T) {
	clearControllerEnvironment(t)
	for name, edits := range map[string][]string{
		"the fixture as it is":            nil,
		"the second documentation range":  {`ip_range: "192.0.2.0/24"`, `ip_range: "198.51.100.0/24"`, `probe_ip: "192.0.2.1"`, `probe_ip: "198.51.100.1"`, `target_ip: "192.0.2.`, `target_ip: "198.51.100.`},
		"a range inside the third":        {`ip_range: "192.0.2.0/24"`, `ip_range: "203.0.113.0/25"`, `probe_ip: "192.0.2.1"`, `probe_ip: "203.0.113.1"`, `target_ip: "192.0.2.`, `target_ip: "203.0.113.`},
		"memory at 95 percent":            {"max_host_ram_percent: 85.0", "max_host_ram_percent: 95.0"},
		"a storage that is not default":   {"\ntiers:\n", "\nstorage:\n  overlay_storage: \"certistack-scratch\"\n\ntiers:\n"},
		"a vnet that only starts like it": {`vnet_id: "csVn01"`, `vnet_id: "vmbrx1"`},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := validateFixture(t, edits...)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(line, "  ! ") && !strings.Contains(line, "sign_key_path") {
					t.Errorf("an ordinary plan got a note: %q", line)
				}
			}
		})
	}
}
