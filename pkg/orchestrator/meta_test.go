// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// The backup's meta line matters where PVE resolves the machine from
// it: a Windows guest with an unversioned machine type.
func TestMetaMattersOnlyForUnpinnedWindows(t *testing.T) {
	for _, tc := range []struct {
		ostype, machine string
		want            bool
	}{
		{"win10", "q35", true},
		{"win11", "", true},
		{"w2k8", "pc", true},
		{"win10", "q35,viommu=virtio", true},
		{"win10", "pc-q35-8.1", false},
		{"win11", "pc-q35-11.0+pve2", false},
		{"l26", "q35", false},
		{"other", "", false},
	} {
		if got := windowsOSType(tc.ostype) && unversionedMachine(tc.machine); got != tc.want {
			t.Errorf("%s/%q: %v, want %v", tc.ostype, tc.machine, got, tc.want)
		}
	}
}

// The record lists the empty CD-ROM drives the sandbox VM really has, read
// back from PVE, not the ones it was asked to have.
func TestRecordEmptyCDROMsReadsWhatTheVMHas(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"sata0":"none,media=cdrom","scsi0":"certistack-scratch:17214/x.qcow2"}}`))
	}))
	defer server.Close()
	o := New(&config.Plan{}, Options{NodeName: "pve1", StateDir: t.TempDir()}, nil, pve.NewClient(pve.Config{BaseURL: server.URL}))
	record := &probe.VMValidationRecord{RestoredHardware: &probe.RestoredHardware{}}
	o.recordEmptyCDROMs(context.Background(), record, config.VM{VMID: 17214, SourceCDROMs: []string{"ide2", "sata0"}})
	if got := record.RestoredHardware.EmptyCDROMs; len(got) != 1 || got[0] != "sata0" {
		t.Fatalf("EmptyCDROMs = %v, want only the drive the VM has", got)
	}
}
