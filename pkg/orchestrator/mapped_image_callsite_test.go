// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// scanCall is what the run asked of a scan of one mapped disk.
type scanCall struct {
	snapshot, device, fusePath string
	want                       pbs.DiskSize
}

var errScanStops = errors.New("the test's scan stops the run here")

// scanOrchestrator maps the test VM as a run does (the loop fixture's client
// makes /dev/loop7 and a fake qemu-img makes the overlay) and replaces the two
// scans with ones that record what they were asked and stop the run. The VM's
// backup records a manifest size and a different configuration size for its
// disk.
func scanOrchestrator(t *testing.T, copyBeforeBoot string) (*Orchestrator, config.VM, *[]scanCall) {
	t.Helper()
	f := newLoopFixture(t, "exit 0")
	qemuImg := "#!/bin/sh\nfor last; do :; done\n: > \"$last\"\n"
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.log), "qemu-img"), []byte(qemuImg), 0o755); err != nil {
		t.Fatal(err)
	}
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	if err := os.Chmod(o.opts.ScratchDir, 0o700); err != nil { // the overlay's directory must be private
		t.Fatal(err)
	}
	o.deviceBytesFn = func(string) (int64, error) { return 36 << 20, nil }
	o.freeBytesFn = func(string) (int64, error) { return 500 << 30, nil }
	o.sharedDisksFn = func(context.Context, string, string) ([]string, error) { return nil, nil }

	var calls []scanCall
	o.verifyImageFn = func(_ context.Context, snapshot, device string, want pbs.DiskSize, _ func(int64)) (*pbs.VerifySummary, string, error) {
		calls = append(calls, scanCall{snapshot: snapshot, device: device, want: want})
		return nil, "", errScanStops
	}
	o.copyImageFn = func(_ context.Context, snapshot, device, fusePath, _ string, want pbs.DiskSize, _ func(int64)) (*pbs.VerifySummary, string, error) {
		calls = append(calls, scanCall{snapshot: snapshot, device: device, fusePath: fusePath, want: want})
		return nil, "", errScanStops
	}
	o.plan.Network = config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"}
	vm := mapTestVM()
	vm.NetworkRecovery = config.NetworkRecovery{Mode: "preserve"} // the guest's disk is left as it is
	vm.CopyBeforeBoot = copyBeforeBoot
	vm.SourceImageBytes = map[string]int64{"scsi0": 36 << 20}
	vm.SourceDiskBytes = map[string]int64{"scsi0": 33 << 20}
	return o, vm, &calls
}

// The scans reject a map that is not the length the backup records, but
// only when they are told the length. Handing them pbs.DiskSize{} at either call
// kept the whole suite green and let a short map pass again ("neither gives a
// size, so only the read of the whole map was checked"). The run is driven through
// bootAndVerifyVM to the scan, and the scan is asked for the manifest's size and
// the configuration's, for the disk it maps.
func TestTheRunsScansAreToldTheLengthTheBackupRecords(t *testing.T) {
	want := pbs.DiskSize{Manifest: 36 << 20, Config: 33 << 20}
	t.Run("the integrity scan", func(t *testing.T) {
		o, vm, calls := scanOrchestrator(t, config.CopyBeforeBootNever)
		if _, err := o.bootAndVerifyVM(context.Background(), vm, 60, nil); !errors.Is(err, errScanStops) {
			t.Fatalf("bootAndVerifyVM = %v, want the run to reach the integrity scan", err)
		}
		if len(*calls) != 1 || (*calls)[0].want != want || (*calls)[0].snapshot != mapTestSnapshot || (*calls)[0].device != "/dev/loop7" {
			t.Fatalf("scan calls = %+v, want one of /dev/loop7 in %s with %+v", *calls, mapTestSnapshot, want)
		}
	})
	t.Run("the scan that copies before boot", func(t *testing.T) {
		o, vm, calls := scanOrchestrator(t, config.CopyBeforeBootAlways)
		if _, err := o.bootAndVerifyVM(context.Background(), vm, 60, nil); err == nil || !errors.Is(err, errScanStops) {
			t.Fatalf("bootAndVerifyVM = %v, want the run to reach the copying scan", err)
		}
		if len(*calls) != 1 || (*calls)[0].want != want || (*calls)[0].snapshot != mapTestSnapshot || (*calls)[0].device != "/dev/loop7" {
			t.Fatalf("scan calls = %+v, want one copy of /dev/loop7 in %s with %+v", *calls, mapTestSnapshot, want)
		}
	})
	t.Run("a backup that recorded neither", func(t *testing.T) {
		o, vm, calls := scanOrchestrator(t, config.CopyBeforeBootNever)
		vm.SourceImageBytes, vm.SourceDiskBytes = nil, nil
		if _, err := o.bootAndVerifyVM(context.Background(), vm, 60, nil); !errors.Is(err, errScanStops) {
			t.Fatalf("bootAndVerifyVM = %v", err)
		}
		if len(*calls) != 1 || (*calls)[0].want != (pbs.DiskSize{}) {
			t.Fatalf("scan calls = %+v, want an empty DiskSize: nothing is known", *calls)
		}
	})
}

// Whatever else is added to the orchestrator, a scan of a mapped disk goes by
// verifyMappedDisk or copyMappedDisk, which always pass the disk's length: a
// direct call of pbs.VerifyMappedImage*, or CopyMappedImage*, has to be one of
// them, and a test of the call sites above cannot see a call it does not drive.
func TestMappedImageScansAreCalledOnlyThroughTheLengthHelpers(t *testing.T) {
	scans := map[string]bool{"VerifyMappedImage": true, "VerifyMappedImageWithProgress": true, "CopyMappedImageWithProgress": true}
	allowed := map[string]bool{"verifyMappedDisk": true, "copyMappedDisk": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				selector, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "pbs" && scans[selector.Sel.Name] {
					found++
					if !allowed[fn.Name.Name] {
						t.Errorf("%s: %s uses pbs.%s itself; a scan goes by verifyMappedDisk or copyMappedDisk, which pass the disk's length", file, fn.Name.Name, selector.Sel.Name)
					}
				}
				return true
			})
		}
	}
	if found != 2 {
		t.Errorf("found %d uses of the mapped-image scans, want the two defaults of the helpers", found)
	}
}
