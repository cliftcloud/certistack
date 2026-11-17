// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// The Proxmox versions a run read, and whether that pair is tested, are
// signed members of the report: changing one after signing breaks the
// signature, and a report that records none of them omits the members rather
// than carry empty ones.
func TestReportSignsTheProxmoxVersionsItRecorded(t *testing.T) {
	_, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plan := &config.Plan{PlanID: "versions", Name: "Versions", Compliance: config.Compliance{Frameworks: []string{"SOC2-Type2-CC7.4"}}}

	report := BuildReport(plan, "pve1", 10*time.Second, true, nil, "")
	report.PVEVersion, report.PBSVersion, report.PBSClientVersion, report.VersionSupport = "9.1.1", "4.2.7", "4.2.5", "tested"
	if err := report.SignReport(privKey); err != nil {
		t.Fatal(err)
	}
	signed, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"pve_version":"9.1.1"`, `"pbs_version":"4.2.7"`, `"pbs_client_version":"4.2.5"`, `"version_support":"tested"`} {
		if !strings.Contains(string(signed), want) {
			t.Errorf("signed report lacks %s: %s", want, signed)
		}
	}
	back, valid, err := VerifyReportSignatureOnly(signed)
	if err != nil || !valid {
		t.Fatalf("report with versions did not verify: %v %v", valid, err)
	}
	if back.PVEVersion != "9.1.1" || back.PBSVersion != "4.2.7" || back.PBSClientVersion != "4.2.5" || back.VersionSupport != "tested" {
		t.Errorf("round trip lost a version member: %+v", back)
	}

	for _, member := range []string{"version_support", "pve_version", "pbs_version", "pbs_client_version"} {
		tampered := strings.Replace(string(signed), `"`+member+`":"`, `"`+member+`":"x`, 1)
		if _, valid, _ := VerifyReportSignatureOnly([]byte(tampered)); valid {
			t.Errorf("changing %s after signing left the signature valid", member)
		}
	}

	// A report that read no version carries no member for it, and verifies.
	bare := BuildReport(plan, "pve1", 10*time.Second, true, nil, "")
	if err := bare.SignReport(privKey); err != nil {
		t.Fatal(err)
	}
	bareJSON, _ := json.Marshal(bare)
	for _, member := range []string{"pve_version", "pbs_version", "pbs_client_version", "version_support"} {
		if strings.Contains(string(bareJSON), member) {
			t.Errorf("a report that read no version carries %s: %s", member, bareJSON)
		}
	}
	if _, valid, err := VerifyReportSignatureOnly(bareJSON); err != nil || !valid {
		t.Fatalf("report without versions did not verify: %v %v", valid, err)
	}
}
