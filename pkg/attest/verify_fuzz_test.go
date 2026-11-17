// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// fuzzSignedReport is a signed report with the members a real pass carries:
// VM records with probes and disk evidence, phase timings, teardown evidence,
// an objective and the admission policy. It returns the indented file as the
// controller saves it, the trusted key, and the report as verified.
func fuzzSignedReport(f *testing.F) ([]byte, ed25519.PublicKey, *Report) {
	f.Helper()
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	objective := 900.0
	report := &Report{
		ReportSchemaVersion: CurrentReportSchemaVersion,
		ReportID:            "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b",
		RunID:               "run-1763200000000000000",
		Timestamp:           "2026-11-15T03:12:59Z",
		PlanID:              "nightly-web",
		PlanName:            "Nightly web tier",
		PlanSHA256:          strings.Repeat("ab", 32),
		ValidationMode:      ValidationModeFullIntegrity,
		NodeFQDN:            "pve-node-01",
		EngineVersion:       "v0.1.0",
		WorkerSHA256:        strings.Repeat("cd", 32),
		Frameworks:          []string{"SOC2"},
		RetentionDays:       365,
		RTOSeconds:          312.25,
		RTOTargetSeconds:    &objective,
		AllPassed:           true,
		PhaseTimings:        &PhaseTimings{PBSMappingSec: 1.5, VMStartSec: 20, ProbesExecutionSec: 3.25, TotalRTOSec: 312.25},
		TeardownEvidence: &TeardownEvidence{
			VMStoppedAndDestroyed: true, OverlayFilesRemoved: []string{"certistack-delta-vm9100-scsi0-1-0.qcow2"},
			LoopDevicesUnmapped: []string{"/dev/loop7"}, SDNVNetRemoved: "csVn01", SDNZoneRemoved: "csSb01",
			OrphanSweepClean: true, AllCleaned: true, JournalRecoveryVerified: true, VerifiedAt: "2026-11-15T03:18:11Z",
		},
		VMRecords: []probe.VMValidationRecord{{
			VMID: 9100, SourceVMID: 100, Name: "web-01", BootDuration: 20 * time.Second, BootDurationSeconds: 20,
			SourceSnapshot: "vm/100/2026-11-15T01:00:00Z", VerificationStatus: "verified", AllPassed: true,
			SourceDisks: []probe.SourceDiskEvidence{{Slot: "scsi0", IntegrityStatus: "verified", ImageDigest: strings.Repeat("ef", 32), ManifestReference: "drive-scsi0.img.fidx"}},
			ProbeResults: []probe.Result{
				{Type: "tcp", Target: "10.100.0.10:443", Description: "HTTPS answers", Passed: true},
				{Type: "http", Target: "http://10.100.0.10/", Description: "home page", Passed: true, Detail: "200 OK"},
			},
		}},
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	if err := report.SignReport(key); err != nil {
		f.Fatal(err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		f.Fatal(err)
	}
	verified, _, err := VerifyReport(data, []ed25519.PublicKey{pub.Public().(ed25519.PublicKey)})
	if err != nil {
		f.Fatalf("the seed report does not verify: %v", err)
	}
	return data, pub.Public().(ed25519.PublicKey), verified
}

// FuzzVerifyReportChanged: a signed report changed in any way either is refused
// by VerifyReport, or verifies to exactly the report that was signed. The
// members outside the signature (the signature, key and fingerprint, which
// only verify in one spelling of their value, and the timestamp, judged
// separately) are compared as the verifier returns them. Whatever the bytes,
// verifying and the unverified decoders never panic.
func FuzzVerifyReportChanged(f *testing.F) {
	data, trusted, original := fuzzSignedReport(f)
	f.Add(data)
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		f.Fatal(err)
	}
	f.Add(compact.Bytes())
	for _, change := range [][2]string{
		{`"all_passed": true`, `"all_passed": false`},
		{`"passed": true`, `"passed": false`},
		{`"rto_seconds": 312.25`, `"rto_seconds": 3.1225e2`},
		{`"rto_seconds": 312.25`, `"rto_seconds": 312.250`},
		{`"retention_days": 365`, `"retention_days": 365.0`},
		{`"vmid": 9100`, `"vmid": 9100, "vmid": 9101`},
		{`"plan_id": "nightly-web"`, `"plan_id": "nightly-web", "Plan_ID": "other"`},
		{`"node_fqdn": "pve-node-01"`, `"node_fqdn": "pve-node-01"`},
		{`"node_fqdn": "pve-node-01"`, `"node_fqdn": "pve-node-01", "x_future": 1`},
		{`"signature": "`, `"signature_timestamp": {"authority": "stub"}, "signature": "`},
		{`"signature": "`, `"Signature": "`},
	} {
		f.Add(bytes.Replace(data, []byte(change[0]), []byte(change[1]), 1))
	}
	f.Add(data[:len(data)/2])

	want, err := original.CanonicalForm()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, changed []byte) {
		_, _ = DecodeReportUnverified(changed)
		_, _ = DecodeUnsignedReport(changed)
		_, _ = CarriedSignatureMembers(changed)
		report, valid, err := VerifyReport(changed, []ed25519.PublicKey{trusted})
		if err != nil || !valid {
			return
		}
		got, err := report.CanonicalForm()
		if err != nil {
			t.Fatalf("a verified report has no canonical form: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("a changed report verified with other contents:\n got %s\nwant %s", got, want)
		}
		signed, compared := *original, *report
		signed.Signature, signed.PublicKey, signed.SignerFingerprint, signed.SignatureTimestamp = "", "", "", nil
		compared.Signature, compared.PublicKey, compared.SignerFingerprint, compared.SignatureTimestamp = "", "", "", nil
		if !reflect.DeepEqual(signed, compared) {
			t.Fatalf("a changed report verified to other values:\n got %+v\nwant %+v", compared, signed)
		}
	})
}
