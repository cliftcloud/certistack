// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/support"
)

func statusOf(pve, pbs, client string) support.Status {
	return support.Classify(support.ParseVersion(pve), support.ParseVersion(pbs), support.ParseVersion(client))
}

// The version line: passed for a tested pair, a warning for an untested one
// or a version that could not be read, a failure for an unsupported pair; and
// only the failure makes the host not ready.
func TestVersionCheckLine(t *testing.T) {
	for _, tc := range []struct {
		name, pve, pbs, client string
		status                 string
		ready                  bool
		detail                 []string
		support                string
	}{
		{"tested", "9.1.1", "4.2.7", "4.2.5", "passed", true, []string{"PVE 9.1.1", "PBS 4.2.7", "proxmox-backup-client 4.2.5", "tested"}, "tested"},
		{"untested", "8.3.0", "3.4.0", "3.3.7", "warning", true, []string{"PVE 8.3.0", "PBS 3.4.0", "proxmox-backup-client 3.3.7", "untested", "not covered by the release evidence"}, "untested"},
		{"unknown", "9.1.1", "", "4.2.5", "warning", true, []string{"PVE 9.1.1", "PBS unknown", "could not be read", "not covered by the release evidence"}, "unknown"},
		{"nothing read", "", "", "", "warning", true, []string{"PVE unknown", "PBS unknown", "proxmox-backup-client unknown"}, "unknown"},
		{"unsupported PVE", "7.4-20", "4.2.7", "4.2.5", "failed", false, []string{"PVE 7.4-20", "PBS 4.2.7", "unsupported", "older than PVE 8"}, "unsupported"},
		{"unsupported PBS", "9.1.1", "2.4.7", "2.4.7", "failed", false, []string{"PBS 2.4.7", "unsupported", "older than PBS 3"}, "unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := statusOf(tc.pve, tc.pbs, tc.client)
			result := Result{Ready: true}
			applyVersionStatus(&result, status)

			if len(result.Checks) != 1 || result.Checks[0].Name != "version_support" {
				t.Fatalf("checks = %+v, want the one version_support line", result.Checks)
			}
			item := result.Checks[0]
			if item.Status != tc.status {
				t.Errorf("status = %q, want %q (%s)", item.Status, tc.status, item.Detail)
			}
			if result.Ready != tc.ready {
				t.Errorf("Ready = %v, want %v", result.Ready, tc.ready)
			}
			for _, want := range tc.detail {
				if !strings.Contains(item.Detail, want) {
					t.Errorf("detail %q lacks %q", item.Detail, want)
				}
			}
			if result.Versions == nil || result.Versions.Support != tc.support {
				t.Fatalf("versions = %+v, want support %q", result.Versions, tc.support)
			}
			if status.Level == support.Unsupported && item.Detail != status.Refusal().Error() {
				t.Errorf("the failing check says %q, but run and plan refuse with %q", item.Detail, status.Refusal())
			}
		})
	}
}

// The JSON of doctor gains a versions member; the members it had keep their
// names.
func TestVersionsJSONMember(t *testing.T) {
	result := Result{Ready: true, Checks: []CheckItem{{Name: "kvm", Status: "passed", Detail: "ok"}}}
	applyVersionStatus(&result, statusOf("9.1.1", "4.2.7", ""))
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{"ready", "checks", "versions"} {
		if _, ok := decoded[member]; !ok {
			t.Errorf("doctor's JSON lacks %q: %s", member, data)
		}
	}
	var versions map[string]string
	if err := json.Unmarshal(decoded["versions"], &versions); err != nil {
		t.Fatal(err)
	}
	for member, want := range map[string]string{"pve": "9.1.1", "pbs": "4.2.7", "pbs_client": "unknown", "support": "unknown"} {
		if versions[member] != want {
			t.Errorf("versions.%s = %q, want %q (%v)", member, versions[member], want, versions)
		}
	}
	if versions["reason"] == "" {
		t.Error("versions.reason is empty")
	}

	// A preflight that did not run the check leaves the member out.
	bare, _ := json.Marshal(Result{Ready: true})
	if strings.Contains(string(bare), "versions") {
		t.Errorf("a result without versions carries the member: %s", bare)
	}
}
