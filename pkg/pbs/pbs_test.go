// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCommandFailureWithholdsPBSClientOutput(t *testing.T) {
	secretOutput := []byte("repository=backup@pbs!ci-token@host password=do-not-log")
	err := commandFailure("map PBS backup image", errors.New("exit status 1"), secretOutput)
	if strings.Contains(err.Error(), string(secretOutput)) || strings.Contains(err.Error(), "ci-token") || strings.Contains(err.Error(), "do-not-log") {
		t.Fatalf("PBS command failure exposed client output: %v", err)
	}
	if !strings.Contains(err.Error(), "client output withheld; 55 bytes") {
		t.Fatalf("PBS command failure lacks redaction evidence: %v", err)
	}
}

func TestBuildEnvScopesPBSCredentials(t *testing.T) {
	t.Setenv("PVE_TOKEN_SECRET", "pve-secret")
	t.Setenv("PBS_PASSWORD", "inherited-pbs-secret")

	env := (&Client{cfg: Config{
		Repository:  "backup@pbs.example:8007:datastore",
		Password:    "configured-pbs-secret",
		Fingerprint: "aa:bb",
		Namespace:   "tenant",
	}}).buildEnv()
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "PVE_TOKEN_SECRET") || strings.Contains(joined, "pve-secret") {
		t.Fatalf("PBS environment contains PVE credentials: %q", joined)
	}
	for _, expected := range []string{
		"PBS_REPOSITORY=backup@pbs.example:8007:datastore",
		"PBS_PASSWORD=configured-pbs-secret",
		"PBS_FINGERPRINT=aa:bb",
		"PBS_NAMESPACE=tenant",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("PBS environment is missing %q: %q", expected, joined)
		}
	}
}

func TestReportVerificationProgressIsBoundedToGiBIntervals(t *testing.T) {
	next := verificationProgressInterval
	var reported []int64
	report := func(bytes int64) { reported = append(reported, bytes) }

	reportVerificationProgress(verificationProgressInterval-1, &next, report)
	reportVerificationProgress(verificationProgressInterval, &next, report)
	reportVerificationProgress(verificationProgressInterval+7, &next, report)
	reportVerificationProgress(3*verificationProgressInterval+9, &next, report)

	if got, want := reported, []int64{verificationProgressInterval, 3*verificationProgressInterval + 9}; !slices.Equal(got, want) {
		t.Fatalf("reported verification progress = %v, want %v", got, want)
	}
	if next != 4*verificationProgressInterval {
		t.Fatalf("next progress threshold = %d, want %d", next, 4*verificationProgressInterval)
	}
}

func TestNormalizeDriveArchive(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"drive-scsi0.img.fidx", "drive-scsi0.img"},
		{"drive-scsi0.fidx", "drive-scsi0.img"},
		{"drive-scsi0.img", "drive-scsi0.img"},
		{"drive-scsi0", "drive-scsi0.img"},
		{"drive-virtio0", "drive-virtio0.img"},
		{"drive-virtio0.img.fidx", "drive-virtio0.img"},
	}

	for _, tt := range tests {
		normalized, err := normalizeDriveArchive(tt.input)
		if err != nil {
			t.Fatalf("normalizeDriveArchive(%q): %v", tt.input, err)
		}
		if normalized != tt.expected {
			t.Errorf("input %s: got %s, expected %s", tt.input, normalized, tt.expected)
		}
	}
}

// A VM ID is spelled canonically: Atoi reads "+7001" and "07001" as 7001, and
// the report-side rules (attest.snapshotGroup) refuse both, so the client
// refuses them too instead of listing or pinning a group the report cannot
// name.
func TestPBSRefusesNonCanonicalVMIDsInGroupsAndSnapshots(t *testing.T) {
	const when = "2026-09-16T02:00:00Z"
	for group, ok := range map[string]bool{"vm/7001": true, "vm/+7001": false, "vm/07001": false, "vm/0": false, "vm/-7001": false, "vm/7001/x": false, "ct/7001": false} {
		if got := validBackupGroup(group); got != ok {
			t.Errorf("validBackupGroup(%q) = %v, want %v", group, got, ok)
		}
	}
	for snapshot, want := range map[string]int{"vm/7001/" + when: 7001, "vm/+7001/" + when: 0, "vm/07001/" + when: 0, "vm/7001/latest": 0} {
		if got, ok := SnapshotVMID(snapshot); got != want || ok != (want > 0) {
			t.Errorf("SnapshotVMID(%q) = %d, %v; want %d", snapshot, got, ok, want)
		}
	}
	client := New(Config{})
	for _, group := range []string{"vm/+7001", "vm/07001"} {
		if _, err := client.LatestSnapshot(context.Background(), group); err == nil || !strings.Contains(err.Error(), "invalid PBS backup group") {
			t.Errorf("LatestSnapshot(%q) = %v, want the group refused before any client runs", group, err)
		}
		if _, _, err := latestCompleteSnapshot([]byte("[]"), group); err == nil || !strings.Contains(err.Error(), "invalid PBS backup group") {
			t.Errorf("latestCompleteSnapshot(%q) = %v, want the group refused", group, err)
		}
	}
}

func TestPBSRejectsUntrustedSnapshotAndArchiveArgumentsBeforeExecution(t *testing.T) {
	client := New(Config{})
	ctx := context.Background()
	for _, snapshot := range []string{"", "latest", "vm/100/latest", "vm/100/2026-09-16T02:00:00Z/extra", "vm/100/not-a-time", "--repository"} {
		if _, err := client.Map(ctx, snapshot, "drive-scsi0"); err == nil {
			t.Errorf("Map accepted invalid snapshot %q", snapshot)
		}
	}
	for _, archive := range []string{"", "--repository", "drive-scsi0/other", "drive scsi0", "drive-scsi0.img.fidx.fidx"} {
		if _, err := client.Map(ctx, "vm/100/2026-09-16T02:00:00Z", archive); err == nil {
			t.Errorf("Map accepted invalid archive %q", archive)
		}
	}
	if _, err := client.ResolveSnapshot(ctx, "vm/100/not-a-time", 100); err == nil {
		t.Fatal("ResolveSnapshot accepted an invalid pinned snapshot")
	}
	if _, err := client.LoadVMProfile(ctx, "vm/100/not-a-time", t.TempDir()); err == nil {
		t.Fatal("LoadVMProfile accepted an invalid pinned snapshot")
	}
}

func TestParseLatestSnapshotJSON(t *testing.T) {
	entries := []map[string]any{
		{"backup-type": "vm", "backup-id": "100", "backup-time": int64(1_700_000_000)},
		{"backup-type": "vm", "backup-id": "100", "backup-time": int64(1_710_000_000)},
		{"backup-type": "vm", "backup-id": "101", "backup-time": int64(1_720_000_000)},
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ParseLatestSnapshotJSON(data, "vm/100")
	if err != nil {
		t.Fatal(err)
	}
	want := "vm/100/" + time.Unix(1_710_000_000, 0).UTC().Format(time.RFC3339)
	if got != want {
		t.Fatalf("latest snapshot = %q, want %q", got, want)
	}
}

// Shape of `proxmox-backup-client snapshot list --output-format json` (4.2)
// for a group whose newest backup aborted: it kept only the VM config and
// has no index.json.blob manifest.
const abortedNewestSnapshotList = `[
 {"backup-id":"7144","backup-time":1790273656,"backup-type":"vm","files":[
  {"filename":"qemu-server.conf.blob","size":767},{"filename":"drive-scsi0.img.fidx","size":34359738368},
  {"filename":"index.json.blob","size":488},{"filename":"client.log.blob"}]},
 {"backup-id":"7144","backup-time":1790274000,"backup-type":"vm","files":[{"filename":"qemu-server.conf.blob"}]}
]`

func TestLatestSnapshotSkipsAbortedBackup(t *testing.T) {
	got, skipped, err := latestCompleteSnapshot([]byte(abortedNewestSnapshotList), "vm/7144")
	if err != nil {
		t.Fatal(err)
	}
	want := "vm/7144/" + time.Unix(1790273656, 0).UTC().Format(time.RFC3339)
	if got != want {
		t.Fatalf("latest = %q, want the newest complete snapshot %q", got, want)
	}
	if len(skipped) != 1 || skipped[0] != "vm/7144/"+time.Unix(1790274000, 0).UTC().Format(time.RFC3339) {
		t.Fatalf("skipped = %v, want the newer aborted snapshot", skipped)
	}
}

func TestLatestSnapshotRejectsGroupWithOnlyAbortedBackups(t *testing.T) {
	data := []byte(`[{"backup-id":"7144","backup-time":1790274000,"backup-type":"vm","files":[{"filename":"qemu-server.conf.blob"}]}]`)
	_, err := ParseLatestSnapshotJSON(data, "vm/7144")
	if err == nil || !strings.Contains(err.Error(), "no complete snapshot") {
		t.Fatalf("error = %v, want an explicit no-complete-snapshot failure", err)
	}
}

func TestParseLatestSnapshotJSONRejectsMissingGroup(t *testing.T) {
	_, err := ParseLatestSnapshotJSON([]byte(`[]`), "vm/100")
	if err == nil {
		t.Fatal("expected no-snapshots error")
	}
}

func TestParseLatestSnapshotJSONAcceptsRFC3339Time(t *testing.T) {
	data := []byte(`[{"backup-type":"vm","backup-id":"100","backup-time":"2026-09-16T02:00:00Z"}]`)
	got, err := ParseLatestSnapshotJSON(data, "vm/100")
	if err != nil {
		t.Fatal(err)
	}
	if got != "vm/100/2026-09-16T02:00:00Z" {
		t.Fatalf("snapshot = %q", got)
	}
}
