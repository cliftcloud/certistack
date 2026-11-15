// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// The fixtures of the report viewer (report show). They are
// synthetic: nothing here was read from a real environment, and every report
// is signed with a key derived from a fixed seed, so the golden outputs are
// byte for byte reproducible. The "twin" reports have the shape and the values
// of a first run on a one-VM lab (a passing run, and a run whose guest-agent
// probe failed), under neutral names.

// goldenUpdateEnvironment rewrites the golden files instead of comparing them:
// CERTISTACK_UPDATE_GOLDEN=1 go test ./cmd/certistack/ -run Golden
const goldenUpdateEnvironment = "CERTISTACK_UPDATE_GOLDEN"

// fixtureKeyPair is the signer of every viewer fixture.
func fixtureKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	return private.Public().(ed25519.PublicKey), private
}

// writeFixtureKeyring writes a keyring that trusts the fixture signer.
func writeFixtureKeyring(t *testing.T, dir string) string {
	t.Helper()
	public, _ := fixtureKeyPair()
	data, err := json.Marshal(attest.Keyring{TrustedSigners: []attest.TrustedSigner{{
		Name: "Fixture signer", PublicKey: hex.EncodeToString(public), Node: "ctl-fixture",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "trusted-signers.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeFixtureReport signs the report with the fixture key (or another, when
// signer is not nil) and writes it the way Save does, under dir/name.
func writeFixtureReport(t *testing.T, dir, name string, report *attest.Report, signer ed25519.PrivateKey) string {
	t.Helper()
	if signer == nil {
		_, signer = fixtureKeyPair()
	}
	if err := attesttest.SignReport(report, signer); err != nil {
		t.Fatal(err)
	}
	return writeFixtureBytes(t, dir, name, report)
}

// writeFixtureBytes writes the report as it is, signed or not.
func writeFixtureBytes(t *testing.T, dir, name string, report *attest.Report) string {
	t.Helper()
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// twinReport is an unsigned, schema 1.7 report of a one-VM run on node
// pve-node-01: the passing run when passed, else the run whose second probe (a
// guest-agent check of the nginx unit) failed. when is the report's timestamp
// and rto its recovery time in seconds.
func twinReport(id string, when time.Time, passed bool, rto float64) *attest.Report {
	disk := probe.SourceDiskEvidence{
		Slot: "scsi0", Archive: "drive-scsi0", ManifestReference: "drive-scsi0.img.fidx", IntegrityStatus: "verified",
		ImageDigest: "7f59c0196f93550731835832470b516a6f0662f6b7b90d3e42666c359db62be5",
	}
	record := probe.VMValidationRecord{
		VMID: 9100, SourceVMID: 100, Name: "cs-rocky-web",
		BootDuration: 3657424213, BootDurationSeconds: 3.657424213,
		SourceSnapshot: "vm/100/2026-10-05T13:32:03Z", SourceCryptMode: "none",
		SourceConsistency: "quiesced", SourceConsistencyDetail: "the guest agent froze the file systems for the snapshot",
		SourceDrive: "drive-scsi0", SourceManifestReference: "drive-scsi0.img.fidx", SourceImageDigest: disk.ImageDigest,
		SourceDisks:             []probe.SourceDiskEvidence{disk},
		PBSVerifyStatus:         "full mapped image read (12884901888 bytes; the size the snapshot's manifest records); SHA-256 " + disk.ImageDigest,
		NetworkRecoveryStrategy: "ifcfg", NetworkRecoveryAddress: "192.0.2.10", NetworkRecoverySeconds: 213.698976461,
		NetworkRecoveryFiles: []string{"/etc/sysconfig/network-scripts/ifcfg-eth0", "/etc/systemd/network/00-certistack-recovery.link"},
		VerificationStatus:   "verified", AllPassed: true,
		RestoredHardware: &probe.RestoredHardware{
			FromBackupConfig: true, Cores: 1, Sockets: 1, MemoryMB: 1024, CPU: "host", CPUWeight: 50, Machine: "q35",
			SCSIHW: "virtio-scsi-single", OSType: "l26", NICModel: "virtio", BootDisk: "scsi0", BootOrder: []string{"scsi0"},
		},
		ProbeResults: []probe.Result{{
			Type: "http", Target: "http://192.0.2.10:80/", Description: "nginx answers 200 on the sandbox address",
			Origin: "worker_host", SourceInterface: "csVnet1", SourceAddress: "192.0.2.1", TimeoutSec: 300, Attempts: 1,
			Passed: true, Duration: 33118674869, Detail: "HTTP 200 OK (200 OK) in 33.118674869s",
		}},
	}
	timings := &attest.PhaseTimings{
		AdmissionCheckSec: 0.501762837, SDNProvisioningSec: 4.436, PBSMappingSec: 0.219084759, OverlayCreationSec: 0.118788744,
		COWGuestNetworkRecoverySec: 213.698976461, VMRegistrationSec: 1.138575331, VMStartSec: 3.075476924, QMPRunningWaitSec: 0.50507549,
		IntegrityVerificationSec: 84.315576099, ProbesExecutionSec: 33.119525027, TeardownSec: 10.292224012, TotalRTOSec: rto,
	}
	report := &attest.Report{
		ReportSchemaVersion: "1.7", ReportID: id, RunID: "run-" + id, Timestamp: when.UTC().Format(time.RFC3339),
		PlanID: "recovery-pve-node-01", PlanName: "Recovery check of 1 VM(s) on pve-node-01",
		PlanSHA256:     strings.Repeat("a1", 32),
		PBSNamespace:   "nightly",
		ValidationMode: attest.ValidationModeFullIntegrity, NodeFQDN: "pve-node-01",
		EngineVersion: "v0.1.0", GitCommit: "0123456789ab", BuildDate: "2026-10-04T11:46:58Z",
		PVEVersion: "9.2.2", PBSVersion: "4.2.0", PBSClientVersion: "4.2.0", VersionSupport: "tested",
		WorkerSHA256: strings.Repeat("b0", 32),
		Frameworks:   []string{"SOC2"}, RetentionDays: 90,
		VMRecords: []probe.VMValidationRecord{record}, PhaseTimings: timings, RTOSeconds: rto, AllPassed: passed,
		TeardownEvidence: &attest.TeardownEvidence{
			VMStoppedAndDestroyed: true, OverlayFilesRemoved: []string{"certistack-delta-vm9100-scsi0-1.qcow2"},
			LoopDevicesUnmapped: []string{"/dev/loop0"}, SDNProvisioning: "ephemeral", SDNVNetRemoved: "csVnet1", SDNZoneRemoved: "csZone1",
			SDNClusterReloaded: true, OrphanSweepClean: true, AllCleaned: true, JournalRecoveryVerified: true,
			VerifiedAt: when.UTC().Add(2 * time.Second).Format(time.RFC3339),
		},
		Admission: &attest.AdmissionEvidence{
			MaxHostRAMPercent: 85, MaxHostIOWaitPercent: 12, DeferRetryIntervalSec: 30, MaxDeferRetries: 10,
			RecoveryReservationMiB: 1280, RecoveryReservationVMs: 1, RecoveryReservationTier: 1,
			Evaluation: &attest.AdmissionEvaluation{
				Checks: 1, Decision: "granted", HostTotalMiB: 32094.3828125, HostAvailableMiB: 28672.98828125,
				HostRAMPercent: 10.660257185776036, HostIOWaitPercent: 0, ProjectedRAMPercent: 14.648652253935596,
			},
		},
	}
	if !passed {
		failing := &report.VMRecords[0]
		failing.VerificationStatus, failing.AllPassed = "failed", false
		failing.ProbeResults = append(failing.ProbeResults, probe.Result{
			Type: "qga", Target: "systemctl is-active nginx", Description: "nginx unit is active (guest-exec)",
			Origin: "guest_qga", RequireQGA: true, TimeoutSec: 120, Attempts: 64, Duration: 9798644,
			Error: "QGA execution failed: QGA guest-exec error: Command guest-exec has been disabled: the command is not allowed (last completed attempt; the final attempt was cut off by the probe timeout)",
		})
		report.FailureReason = `recovery tier 1 (Recovery check) failed: VM 9100 (cs-rocky-web) probes: probe "nginx unit is active (guest-exec)" failed: QGA execution failed: QGA guest-exec error: Command guest-exec has been disabled: the command is not allowed (last completed attempt; the final attempt was cut off by the probe timeout)`
		report.PhaseTimings.ProbesExecutionSec = 152.06
	}
	return report
}

// compareGolden compares got with the golden file testdata/<dir>/<name>, or
// rewrites the file when CERTISTACK_UPDATE_GOLDEN is set.
func compareGolden(t *testing.T, dir, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", dir, name)
	if os.Getenv(goldenUpdateEnvironment) != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (create it with %s=1)", err, goldenUpdateEnvironment)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != got {
		t.Errorf("%s differs from the golden file %s (rewrite it with %s=1 if the change is intended):\n--- got ---\n%s", name, path, goldenUpdateEnvironment, got)
	}
}
