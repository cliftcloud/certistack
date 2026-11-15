// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/cleanup"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// A VM record is signed whatever way its restore ends, and an early
// failure used to sign a record without the backup it was refused for: the
// snapshot, the disks, the protection and the tags were set only after the map,
// the overlay, the firmware and the network step. The reports of two failures
// of different backups were then byte for byte the same.

var sourceEvidenceKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))

// signedFailure marks a record failed as Run does, builds the report from it,
// signs it with a fixed key and verifies it, and returns the signed bytes and
// the VM record read back from them.
func signedFailure(t *testing.T, vm config.VM, record probe.VMValidationRecord, runErr error) ([]byte, probe.VMValidationRecord) {
	t.Helper()
	plan := &config.Plan{
		Version: "v1", PlanID: "early-source-evidence", Name: "Early source evidence",
		Tiers: []config.Tier{{Level: 1, Name: "restore", VMs: []config.VM{vm}}},
	}
	markVMRecordFailed(&record, runErr)
	report := attest.BuildReport(plan, "node-a.example", time.Second, false, []probe.VMValidationRecord{record}, "")
	report.ReportID = "00000000-0000-4000-8000-000000000141"
	report.Timestamp = "2026-09-30T18:00:00Z"
	report.FailureReason = runErr.Error()
	if err := attesttest.SignReport(report, sourceEvidenceKey); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	verified, valid, err := attest.VerifyReport(data, []ed25519.PublicKey{sourceEvidenceKey.Public().(ed25519.PublicKey)})
	if err != nil || !valid || verified == nil || len(verified.VMRecords) != 1 {
		t.Fatalf("verify the signed failure report: valid=%v report=%v err=%v", valid, verified != nil, err)
	}
	return data, verified.VMRecords[0]
}

// wantSourceIdentity fails unless the record says what vm says of its backup,
// and lists the disks vm is to restore, with the statuses in want (by slot).
func wantSourceIdentity(t *testing.T, got probe.VMValidationRecord, vm config.VM, want map[string]string) {
	t.Helper()
	if got.SourceVMID != vm.SourceVMID || got.SourceSnapshot != vm.SourcePBS.Snapshot ||
		got.SourceCryptMode != vm.SourceCryptMode || got.SourceSignatureVerified != vm.SourceSignatureVerified ||
		!reflect.DeepEqual(got.SourceTags, vm.SourceTags) || !reflect.DeepEqual(got.ExcludedSourceDisks, vm.ExcludedDisks) ||
		!reflect.DeepEqual(got.OmittedSourceDisks, vm.OmittedDisks) {
		t.Errorf("the record names source VM %d snapshot %q crypt %q signature %v tags %v excluded %v omitted %v;\nthe VM is source VM %d snapshot %q crypt %q signature %v tags %v excluded %v omitted %v",
			got.SourceVMID, got.SourceSnapshot, got.SourceCryptMode, got.SourceSignatureVerified, got.SourceTags, got.ExcludedSourceDisks, got.OmittedSourceDisks,
			vm.SourceVMID, vm.SourcePBS.Snapshot, vm.SourceCryptMode, vm.SourceSignatureVerified, vm.SourceTags, vm.ExcludedDisks, vm.OmittedDisks)
	}
	var wantDisks []string
	for _, drive := range vm.SourcePBS.RestoreDrives() {
		wantDisks = append(wantDisks, drive.Slot+" "+drive.Archive+" "+want[drive.Slot])
	}
	for _, disk := range vm.FirmwareDisks {
		wantDisks = append(wantDisks, disk.Slot+" "+disk.Archive+" "+want[disk.Slot])
	}
	var gotDisks []string
	for _, disk := range got.SourceDisks {
		gotDisks = append(gotDisks, disk.Slot+" "+disk.Archive+" "+disk.IntegrityStatus)
		if disk.ManifestReference != manifestReference(disk.Archive) {
			t.Errorf("disk %s names manifest %q, want %q", disk.Slot, disk.ManifestReference, manifestReference(disk.Archive))
		}
	}
	if !reflect.DeepEqual(gotDisks, wantDisks) {
		t.Errorf("the record lists disks\n  %s\nwant\n  %s", strings.Join(gotDisks, "\n  "), strings.Join(wantDisks, "\n  "))
	}
}

// The first reported case: the cluster-wide preexisting-VM guard refuses two
// VMs that differ in everything the backup is (snapshot, disk layout,
// protection, tags, excluded and omitted disks), before any restore, and the
// two signed reports were identical.
func TestFailuresBeforeAnyRestoreSignWhichBackupWasRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/cluster/resources" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[{"type":"qemu","vmid":9101,"node":"other-node"}]`)})
	}))
	defer server.Close()
	client := pve.NewClient(pve.Config{BaseURL: server.URL})

	vmA := config.VM{
		VMID: 9101, SourceVMID: 7101, Name: "database",
		SourcePBS: config.SourcePBS{StorageID: "pbs", Snapshot: "vm/7101/2026-09-28T01:00:00Z",
			Drives: []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0.img.fidx"}}},
		SourceCryptMode: pbs.CryptModeNone, SourceSignatureVerified: false,
		SourceTags: []string{"source-a"}, ExcludedDisks: []string{"local-a"}, OmittedDisks: []string{"scsi1"},
		SourceConsistency: pbs.ConsistencyQuiesced, SourceConsistencyDetail: "guest agent freeze confirmed",
	}
	vmB := vmA
	vmB.SourcePBS = config.SourcePBS{StorageID: "pbs", Snapshot: "vm/7101/2026-09-29T02:00:00Z",
		Drives: []config.SourceDrive{{Slot: "virtio0", Archive: "drive-virtio0.img.fidx"}}}
	vmB.SourceCryptMode = pbs.CryptModeEncrypt
	vmB.SourceSignatureVerified = true
	vmB.SourceTags = []string{"source-b"}
	vmB.ExcludedDisks = []string{"local-b"}
	vmB.OmittedDisks = []string{"virtio1"}

	refuse := func(vm config.VM) ([]byte, probe.VMValidationRecord) {
		t.Helper()
		o := &Orchestrator{opts: Options{NodeName: "node-a"}, pveClient: client}
		record, err := o.bootAndVerifyVM(context.Background(), vm, 60, nil)
		if err == nil || !strings.Contains(err.Error(), "preexisting VM guard triggered") {
			t.Fatalf("bootAndVerifyVM = %v, want the preexisting-VM guard", err)
		}
		return signedFailure(t, vm, *record, err)
	}
	reportA, recordA := refuse(vmA)
	reportB, recordB := refuse(vmB)

	if bytes.Equal(reportA, reportB) {
		t.Fatal("two failures of different backups signed byte for byte the same report: the early failure evidence omits the backup it was refused for")
	}
	wantSourceIdentity(t, recordA, vmA, map[string]string{"scsi0": probe.DiskNotAttempted})
	wantSourceIdentity(t, recordB, vmB, map[string]string{"virtio0": probe.DiskNotAttempted})
	for name, report := range map[string][]byte{"A": reportA, "B": reportB} {
		for _, needle := range []string{"2026-09-28T01:00:00Z", "2026-09-29T02:00:00Z"} {
			wantIt := (name == "A") == strings.Contains(needle, "09-28")
			if bytes.Contains(report, []byte(needle)) != wantIt {
				t.Errorf("signed report %s: contains %s = %v, want %v", name, needle, !wantIt, wantIt)
			}
		}
	}
}

// The second reported case: the real map command is refused after the run has
// journaled the snapshot and archive it was to map, and the signed report said
// nothing of either.
func TestAMapFailureSignsTheSnapshotAndArchiveItWasGiven(t *testing.T) {
	run := newEvidenceRun(t, evidenceSpec{mapExit: map[string]int{"scsi0": 37}})
	record, err := run.o.bootAndVerifyVM(context.Background(), run.vm, 60, nil)
	if err == nil || !strings.Contains(err.Error(), "PBS map error for scsi0") {
		t.Fatalf("bootAndVerifyVM = %v, want the map failure", err)
	}
	args, readErr := os.ReadFile(run.mapLog)
	if readErr != nil || !strings.Contains(string(args), run.vm.SourcePBS.Snapshot+" drive-scsi0.img") {
		t.Fatalf("the client was run with %q (%v), want the map of the VM's snapshot and archive", args, readErr)
	}
	intents, loadErr := journal.Load(filepath.Join(run.stateDir, "active.json"))
	if loadErr != nil || len(intents.MapIntents) != 1 || intents.MapIntents[0].Snapshot != run.vm.SourcePBS.Snapshot {
		t.Fatalf("map journal = %+v, %v; want the intent the reporter saw", intents, loadErr)
	}

	data, signed := signedFailure(t, run.vm, *record, err)
	wantSourceIdentity(t, signed, run.vm, map[string]string{"scsi0": probe.DiskMapFailed, "scsi1": probe.DiskNotAttempted, "scsi2": probe.DiskNotAttempted})
	for _, needle := range []string{run.vm.SourcePBS.Snapshot, "drive-scsi0.img", "drive-scsi1.img"} {
		if !bytes.Contains(data, []byte(needle)) {
			t.Errorf("the signed report does not name %q", needle)
		}
	}
}

// Failure injection at each point the restore can end, with the backup the VM
// was given and how far each disk got. Every case runs the real
// bootAndVerifyVM against fakes of PVE, the PBS client, losetup and qemu-img.
func TestEveryBoundaryOfTheRestoreKeepsTheBackupItWasGiven(t *testing.T) {
	const (
		na   = probe.DiskNotAttempted
		maps = probe.DiskMapped
	)
	cases := []struct {
		name    string
		spec    evidenceSpec
		mutate  func(*evidenceRun)
		wantErr string
		disks   map[string]string
	}{
		{name: "quiesced backup required", mutate: func(r *evidenceRun) {
			r.vm.RequireQuiescedBackup, r.vm.SourceConsistency, r.vm.SourceConsistencyDetail = true, pbs.ConsistencyCrash, "fsfreeze failed"
		}, wantErr: "the plan requires a quiesced backup", disks: map[string]string{"scsi0": na, "scsi1": na, "scsi2": na}},
		{name: "cluster lookup fails", spec: evidenceSpec{clusterStatus: 500}, wantErr: "cannot establish whether VM 9001 is already used in the cluster",
			disks: map[string]string{"scsi0": na, "scsi1": na, "scsi2": na}},
		{name: "VM id used in the cluster", spec: evidenceSpec{clusterBody: `[{"type":"qemu","vmid":9001,"node":"other"}]`}, wantErr: "already exists in the PVE cluster",
			disks: map[string]string{"scsi0": na, "scsi1": na, "scsi2": na}},
		{name: "node status lookup fails", spec: evidenceSpec{nodeStatus: 500}, wantErr: "cannot establish whether VM 9001 already exists",
			disks: map[string]string{"scsi0": na, "scsi1": na, "scsi2": na}},
		{name: "VM exists on the node", spec: evidenceSpec{nodeStatus: 200}, wantErr: "already exists on node localhost",
			disks: map[string]string{"scsi0": na, "scsi1": na, "scsi2": na}},
		{name: "no backed-up disk", mutate: func(r *evidenceRun) { r.vm.SourcePBS.Drives = nil }, wantErr: "has no backed-up source disks", disks: nil},
		{name: "journal cannot be written", mutate: func(r *evidenceRun) {
			// A state directory that is a file: the intent cannot be flushed.
			if err := os.RemoveAll(r.stateDir); err != nil {
				r.t.Fatal(err)
			}
			if err := os.WriteFile(r.stateDir, []byte("not a directory"), 0o600); err != nil {
				r.t.Fatal(err)
			}
		}, wantErr: "", disks: map[string]string{"scsi0": na, "scsi1": na, "scsi2": na}},
		{name: "first map refused", spec: evidenceSpec{mapExit: map[string]int{"scsi0": 37}}, wantErr: "PBS map error for scsi0",
			disks: map[string]string{"scsi0": probe.DiskMapFailed, "scsi1": na, "scsi2": na}},
		{name: "second map refused after the first disk's overlay", spec: evidenceSpec{mapExit: map[string]int{"scsi1": 37}}, wantErr: "PBS map error for scsi1",
			disks: map[string]string{"scsi0": maps, "scsi1": probe.DiskMapFailed, "scsi2": na}},
		{name: "loop identity unreadable", spec: evidenceSpec{noLoopIdentity: "scsi1"}, wantErr: "verify mapped PBS loop identity for scsi1",
			disks: map[string]string{"scsi0": maps, "scsi1": maps, "scsi2": na}},
		{name: "overlay refused", spec: evidenceSpec{qemuImgExit: 1}, wantErr: "delta overlay error for scsi0",
			disks: map[string]string{"scsi0": maps, "scsi1": na, "scsi2": na}},
		{name: "network recovery cannot be resolved", mutate: func(r *evidenceRun) { r.vm.NetworkRecovery.Mode = "" },
			wantErr: "resolve overlay network recovery for VM 9001", disks: map[string]string{"scsi0": maps, "scsi1": maps, "scsi2": maps}},
		{name: "network adaptation fails", mutate: func(r *evidenceRun) {
			r.vm.NetworkRecovery.Mode = ""
			r.vm.Probes = []config.Probe{{Type: "tcp", Description: "web", TargetIP: "10.70.0.5", Port: 80}}
			r.o.plan.Network.IPRange, r.o.plan.Network.ProbeIP = "10.70.0.0/24", "10.70.0.1"
		}, wantErr: "apply COW-only network recovery for VM 9001", disks: map[string]string{"scsi0": maps, "scsi1": maps, "scsi2": maps}},
		// The boot disk is scanned last, so the others keep what they established.
		{name: "scan of a later disk fails", spec: evidenceSpec{scanFails: "scsi2"}, wantErr: "integrity verification failed for scsi2",
			disks: map[string]string{"scsi0": maps, "scsi1": probe.DiskVerified, "scsi2": probe.DiskVerificationFailed}},
		{name: "scan of the boot disk fails last", spec: evidenceSpec{scanFails: "scsi0"}, wantErr: "integrity verification failed for scsi0",
			disks: map[string]string{"scsi0": probe.DiskVerificationFailed, "scsi1": probe.DiskVerified, "scsi2": probe.DiskVerified}},
		{name: "copy before boot fails", spec: evidenceSpec{scanFails: "scsi2"}, mutate: func(r *evidenceRun) {
			r.vm.CopyBeforeBoot = config.CopyBeforeBootAlways
			r.o.deviceBytesFn = func(string) (int64, error) { return 1 << 20, nil }
			r.o.freeBytesFn = func(string) (int64, error) { return 1 << 40, nil }
			r.o.sharedDisksFn = func(context.Context, string, string) ([]string, error) { return nil, nil }
		}, wantErr: "integrity verification and copy failed for scsi2",
			disks: map[string]string{"scsi0": maps, "scsi1": probe.DiskVerified, "scsi2": probe.DiskVerificationFailed}},
		{name: "VM start refused", spec: evidenceSpec{createOK: true, startStatus: 500}, wantErr: "PVE StartVM error: failed to start VM 9001",
			disks: map[string]string{"scsi0": probe.DiskVerified, "scsi1": probe.DiskVerified, "scsi2": probe.DiskVerified}},
		{name: "VM registration refused", spec: evidenceSpec{createStatus: 500}, wantErr: "PVE CreateVM error: failed to create VM 9001 on node localhost",
			disks: map[string]string{"scsi0": probe.DiskVerified, "scsi1": probe.DiskVerified, "scsi2": probe.DiskVerified}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := newEvidenceRun(t, tc.spec)
			if tc.mutate != nil {
				tc.mutate(run)
			}
			record, err := run.o.bootAndVerifyVM(context.Background(), run.vm, 60, nil)
			if err == nil || (tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("bootAndVerifyVM = %v, want it to fail with %q", err, tc.wantErr)
			}
			run.o.cleanup.Unwind()
			_, signed := signedFailure(t, run.vm, *record, err)
			if tc.name == "no backed-up disk" {
				if len(signed.SourceDisks) != 0 || signed.SourceSnapshot != run.vm.SourcePBS.Snapshot || signed.SourceCryptMode != run.vm.SourceCryptMode {
					t.Fatalf("record = %+v, want the snapshot and protection and no disk", signed)
				}
				return
			}
			wantSourceIdentity(t, signed, run.vm, tc.disks)
		})
	}
}

// The firmware state of a UEFI VM is part of the backup: a restore that stops
// with its variable store restored and its TPM state not says so, and a
// failed firmware restore keeps what the data disks established.
func TestAFirmwareRestoreFailureKeepsWhatEarlierDisksEstablished(t *testing.T) {
	orch, vm, _ := firmwareFixture(t, map[string][]byte{"drive-efidisk0": []byte("vars")})
	vm.SourcePBS = config.SourcePBS{Snapshot: "vm/7214/2026-09-27T03:12:59Z", Drives: []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}}
	record := newVMRecord(vm)
	setSourceDisk(record, probe.SourceDiskEvidence{Slot: "scsi0", Archive: "drive-scsi0", ManifestReference: "drive-scsi0.img.fidx", IntegrityStatus: probe.DiskMapped})

	_, _, err := orch.restoreFirmwareDisks(context.Background(), vm, 1, nil, record)
	if err == nil || !strings.Contains(err.Error(), "tpmstate0") {
		t.Fatalf("restoreFirmwareDisks = %v, want the TPM restore failure", err)
	}
	statuses := map[string]string{}
	for _, disk := range record.SourceDisks {
		statuses[disk.Slot] = disk.IntegrityStatus
	}
	want := map[string]string{"scsi0": probe.DiskMapped, "efidisk0": probe.DiskVerified, "tpmstate0": probe.DiskRestoreFailed}
	if !reflect.DeepEqual(statuses, want) {
		t.Fatalf("statuses = %v, want %v", statuses, want)
	}
	for _, disk := range record.SourceDisks {
		if disk.Slot == "efidisk0" && (disk.ImageDigest == "" || disk.ManifestReference == "") {
			t.Fatalf("the restored variable store records no digest: %+v", disk)
		}
	}
}

// A disk's status only moves forward, and an outcome is final: a later failure
// never turns a verified disk back into a failed or a waiting one.
func TestADisksStatusOnlyMovesForward(t *testing.T) {
	order := []string{probe.DiskNotAttempted, probe.DiskMapped, probe.DiskVerified}
	record := &probe.VMValidationRecord{SourceDisks: []probe.SourceDiskEvidence{{Slot: "scsi0", IntegrityStatus: probe.DiskNotAttempted}}}
	for _, status := range order {
		setSourceDiskStatus(record, "scsi0", status)
	}
	if record.SourceDisks[0].IntegrityStatus != probe.DiskVerified {
		t.Fatalf("status = %q, want verified", record.SourceDisks[0].IntegrityStatus)
	}
	for _, back := range []string{probe.DiskNotAttempted, probe.DiskMapped, probe.DiskMapFailed, probe.DiskVerificationFailed, probe.DiskRestoreFailed} {
		setSourceDiskStatus(record, "scsi0", back)
		setSourceDisk(record, probe.SourceDiskEvidence{Slot: "scsi0", IntegrityStatus: back, ImageDigest: "changed"})
		if got := record.SourceDisks[0]; got.IntegrityStatus != probe.DiskVerified || got.ImageDigest != "" {
			t.Fatalf("a verified disk was moved to %q: %+v", back, got)
		}
	}
	failed := &probe.VMValidationRecord{SourceDisks: []probe.SourceDiskEvidence{{Slot: "scsi0", IntegrityStatus: probe.DiskMapFailed}}}
	setSourceDiskStatus(failed, "scsi0", probe.DiskVerificationFailed)
	setSourceDisk(failed, probe.SourceDiskEvidence{Slot: "scsi0", IntegrityStatus: probe.DiskVerified})
	if failed.SourceDisks[0].IntegrityStatus != probe.DiskMapFailed {
		t.Fatalf("a failed disk was moved to %q", failed.SourceDisks[0].IntegrityStatus)
	}
	// A slot nobody asked for is added, a nil record is ignored.
	setSourceDisk(failed, probe.SourceDiskEvidence{Slot: "efidisk0", IntegrityStatus: probe.DiskVerified})
	if len(failed.SourceDisks) != 2 || failed.SourceDisks[1].Slot != "efidisk0" {
		t.Fatalf("disks = %+v", failed.SourceDisks)
	}
	setSourceDisk(nil, probe.SourceDiskEvidence{Slot: "scsi0"})
	setSourceDiskStatus(nil, "scsi0", probe.DiskMapped)
}

// Every status a worker of this build writes is one the controller and the
// verifier know, and the statuses that are not a pass are every one of the rest.
func TestTheDiskStatusesAreTheOnesTheRecordsCanHold(t *testing.T) {
	for _, status := range []string{probe.DiskNotAttempted, probe.DiskMapped, probe.DiskMapFailed, probe.DiskVerificationFailed, probe.DiskRestoreFailed, probe.DiskVerified, probe.DiskSkippedTestMode} {
		if !probe.KnownDiskStatus(status) {
			t.Errorf("%q is not a known disk status", status)
		}
	}
	for _, status := range []string{"", "Verified", "verified ", "passed", "map-failed"} {
		if probe.KnownDiskStatus(status) {
			t.Errorf("%q is a known disk status", status)
		}
	}
}

// The seed is the only thing that sets the backup's identity: the function that
// restores a VM creates its record once, from the VM it was given, returns that
// record at every exit, and never assigns the seeded fields afterwards. The
// failure-injection cases above prove the exits they reach; this proves there
// is no exit they do not (a new return of another record, a field set late).
func TestTheSourceIdentityIsSeededOnceAtTheStart(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "orchestrator.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if candidate, ok := decl.(*ast.FuncDecl); ok && candidate.Name.Name == "bootAndVerifyVM" {
			fn = candidate
		}
	}
	if fn == nil {
		t.Fatal("bootAndVerifyVM was not found")
	}
	first, ok := fn.Body.List[0].(*ast.AssignStmt)
	if !ok || first.Tok != token.DEFINE || len(first.Lhs) != 1 || first.Lhs[0].(*ast.Ident).Name != "record" ||
		len(first.Rhs) != 1 || !isCallTo(first.Rhs[0], "newVMRecord") {
		t.Fatal("bootAndVerifyVM must begin with `record := newVMRecord(vmCfg)`")
	}
	seeded := map[string]bool{"SourceSnapshot": true, "SourceCryptMode": true, "SourceSignatureVerified": true,
		"ExcludedSourceDisks": true, "OmittedSourceDisks": true, "SourceTags": true, "SourceDisks": true, "SourceVMID": true}
	returns := 0
	var walk func(node ast.Node) bool
	walk = func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.FuncLit:
			return false // a closure's returns are its own
		case *ast.ReturnStmt:
			returns++
			if len(n.Results) != 2 {
				t.Errorf("%s: a return that does not return the record and an error", fset.Position(n.Pos()))
			} else if id, ok := n.Results[0].(*ast.Ident); !ok || id.Name != "record" {
				t.Errorf("%s: a restore that ends here returns something other than the VM's own record", fset.Position(n.Pos()))
			}
		case *ast.AssignStmt:
			for index, lhs := range n.Lhs {
				switch target := lhs.(type) {
				case *ast.Ident:
					if target.Name == "record" && !(n == first && index == 0) {
						t.Errorf("%s: the record is assigned again", fset.Position(n.Pos()))
					}
				case *ast.StarExpr:
					if id, ok := target.X.(*ast.Ident); ok && id.Name == "record" {
						t.Errorf("%s: the record is overwritten", fset.Position(n.Pos()))
					}
				case *ast.SelectorExpr:
					if id, ok := target.X.(*ast.Ident); ok && id.Name == "record" && seeded[target.Sel.Name] {
						t.Errorf("%s: record.%s is set after the start; newVMRecord seeds it", fset.Position(n.Pos()), target.Sel.Name)
					}
				}
			}
		}
		return true
	}
	ast.Inspect(fn.Body, walk)
	if returns < 20 {
		t.Fatalf("found only %d returns in bootAndVerifyVM; the walk is not seeing the function", returns)
	}
}

func isCallTo(expr ast.Expr, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == name
}

// evidenceSpec says how the fakes of an evidenceRun fail. The zero value is a
// restore of three disks that reaches VM registration.
type evidenceSpec struct {
	clusterStatus  int            // status of the cluster resources request; 0 is 200 with no VM
	clusterBody    string         // its body
	nodeStatus     int            // status of the VM's node-local lookup; 0 is "no such VM"
	createStatus   int            // status of the create request; 0 is 200
	createOK       bool           // the create request is accepted, and its task ends well
	startStatus    int            // status of the start request, once the VM is created
	mapExit        map[string]int // by slot: a nonzero exit refuses that disk's map
	noLoopIdentity string         // slot whose loop device has no readable backing file
	qemuImgExit    int            // qemu-img's exit status
	scanFails      string         // slot whose integrity scan or copy fails
}

type evidenceRun struct {
	t        *testing.T
	o        *Orchestrator
	vm       config.VM
	stateDir string
	mapLog   string
}

func newEvidenceRun(t *testing.T, spec evidenceSpec) *evidenceRun {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/resources":
			if spec.clusterStatus != 0 {
				http.Error(w, `{"errors":"cluster resources are unavailable"}`, spec.clusterStatus)
				return
			}
			body := spec.clusterBody
			if body == "" {
				body = `[]`
			}
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(body)})
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/localhost/qemu/9001/config":
			// Teardown asks whether the VM it registered exists: it does not.
			http.Error(w, `{"errors": "Configuration file does not exist"}`, http.StatusNotFound)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/localhost/qemu/9001/status/current":
			switch spec.nodeStatus {
			case 0:
				http.Error(w, `{"errors": "Configuration file does not exist"}`, http.StatusNotFound)
			case 200:
				_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`{"status":"stopped"}`)})
			default:
				http.Error(w, `{"errors":"the node is unavailable"}`, spec.nodeStatus)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/localhost/qemu":
			if spec.createStatus != 0 {
				http.Error(w, `{"errors":"create refused"}`, spec.createStatus)
				return
			}
			if !spec.createOK {
				t.Errorf("a create request was answered; this fake PVE refuses it unless told to accept it")
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"UPID:localhost:00000001:00000001:00000001:qmcreate:9001:root@pam:"`)})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/localhost/tasks/"):
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`{"status":"stopped","exitstatus":"OK"}`)})
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/localhost/qemu/9001/status/start":
			http.Error(w, `{"errors":"start refused"}`, spec.startStatus)
		default:
			t.Errorf("unexpected PVE request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	// Three loop devices, each backed by a file the run could have mapped.
	dir := t.TempDir()
	sys := filepath.Join(dir, "sys")
	old := sysutil.SysBlockDir
	t.Cleanup(func() { sysutil.SysBlockDir = old })
	sysutil.SysBlockDir = sys
	loops := map[string]string{"scsi0": "/dev/loop71", "scsi1": "/dev/loop72", "scsi2": "/dev/loop73"}
	for slot, device := range loops {
		if slot == spec.noLoopIdentity {
			if err := os.MkdirAll(filepath.Join(sys, filepath.Base(device), "loop", "backing_file"), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		backing := filepath.Join(sys, filepath.Base(device), "loop", "backing_file")
		if err := os.MkdirAll(filepath.Dir(backing), 0o755); err != nil {
			t.Fatal(err)
		}
		// The file a map of the slot's archive is attached to.
		suffix, err := pbs.MapNameSuffix("vm/7214/2026-09-27T03:12:59Z", "drive-"+slot)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(backing, []byte("/run/pbs-loopdev/certistack-test"+suffix+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mapLog := filepath.Join(dir, "map-args.txt")
	var client strings.Builder
	client.WriteString("#!/bin/sh\ncase \"$1\" in\nmap)\n  printf '%s\\n' \"$*\" >> '" + mapLog + "'\n  case \"$*\" in\n")
	for _, slot := range []string{"scsi0", "scsi1", "scsi2"} {
		client.WriteString(fmt.Sprintf("  *drive-%s.img*)\n    printf 'synthetic map refusal\\n' >&2; ", slot))
		if code := spec.mapExit[slot]; code != 0 {
			client.WriteString(fmt.Sprintf("exit %d;;\n", code))
		} else {
			client.WriteString(fmt.Sprintf("echo 'Image mapped to %s'; exit 0;;\n", loops[slot]))
		}
	}
	client.WriteString("  esac;;\nesac\nexit 19\n")
	writeExecutable(t, filepath.Join(dir, "proxmox-backup-client"), client.String())
	// A detach releases the loop as the kernel would: its sysfs entry goes.
	writeExecutable(t, filepath.Join(dir, "losetup"), "#!/bin/sh\n[ \"$1\" = -d ] && /bin/rm -f '"+sys+"'/\"${2##*/}\"/loop/backing_file\nexit 0\n")
	writeExecutable(t, filepath.Join(dir, "qemu-img"), fmt.Sprintf("#!/bin/sh\nfor a; do last=$a; done\n: > \"$last\"\nexit %d\n", spec.qemuImgExit))
	t.Setenv("PATH", dir)

	vm := config.VM{
		VMID: 9001, SourceVMID: 7214, Name: "database",
		SourcePBS: config.SourcePBS{StorageID: "pbs", Snapshot: "vm/7214/2026-09-27T03:12:59Z", Drives: []config.SourceDrive{
			{Slot: "scsi0", Archive: "drive-scsi0.img.fidx"}, {Slot: "scsi1", Archive: "drive-scsi1.img.fidx"}, {Slot: "scsi2", Archive: "drive-scsi2.img.fidx"}}},
		SourceCryptMode: pbs.CryptModeSignOnly, SourceSignatureVerified: true,
		SourceTags: []string{"tier-1", "mapped-source"}, ExcludedDisks: []string{"local-cache"}, OmittedDisks: []string{"scsi9"},
		SourceConsistency: pbs.ConsistencyQuiesced, SourceConsistencyDetail: "guest agent freeze confirmed",
		CopyBeforeBoot: config.CopyBeforeBootNever,
		// The guest is not adapted to the sandbox network unless a case asks.
		NetworkRecovery: config.NetworkRecovery{Mode: "preserve"},
	}
	stateDir := t.TempDir()
	// The overlay's directory must be private to the user that runs the worker.
	scratchDir := t.TempDir()
	if err := os.Chmod(scratchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The sandbox VM is created on the plan's VNet.
	plan := &config.Plan{Network: config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01"}}
	o := New(plan, Options{NodeName: "localhost", StateDir: stateDir, ScratchDir: scratchDir}, pbs.New(pbs.Config{Repository: "u@pbs!tok@pbs.example:store"}), pve.NewClient(pve.Config{BaseURL: server.URL}))
	o.cleanup = cleanup.New()
	o.unmapLeakedMapsFn = func([]*journal.MapIntent, map[string]bool, func() error) error { return nil }
	scan := func(device string) error {
		for slot, loop := range loops {
			if loop == device && slot == spec.scanFails {
				return errors.New("a chunk does not match its digest")
			}
		}
		return nil
	}
	o.verifyImageFn = func(_ context.Context, _, device string, _ pbs.DiskSize, _ func(int64)) (*pbs.VerifySummary, string, error) {
		if err := scan(device); err != nil {
			return nil, "", err
		}
		return &pbs.VerifySummary{Detail: "verified"}, strings.Repeat("ab", 32), nil
	}
	o.copyImageFn = func(_ context.Context, _, device, _, copyPath string, _ pbs.DiskSize, _ func(int64)) (*pbs.VerifySummary, string, error) {
		if err := scan(device); err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(copyPath, []byte("a copy"), 0o600); err != nil {
			return nil, "", err
		}
		return &pbs.VerifySummary{Detail: "verified"}, strings.Repeat("cd", 32), nil
	}
	return &evidenceRun{t: t, o: o, vm: vm, stateDir: stateDir, mapLog: mapLog}
}

func writeExecutable(t *testing.T, path, script string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}
