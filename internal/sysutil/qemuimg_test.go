// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"strings"
	"testing"
)

// The disposable overlay skips the per-cluster refcount update.
func TestDeltaOverlayArgs(t *testing.T) {
	got := strings.Join(deltaOverlayArgs("/dev/loop3", "/var/lib/certistack/w/scsi0.qcow2"), " ")
	want := "create -f qcow2 -o lazy_refcounts=on -b /dev/loop3 -F raw /var/lib/certistack/w/scsi0.qcow2"
	if got != want {
		t.Fatalf("qemu-img %s, want qemu-img %s", got, want)
	}
}

// An unsafe rebase swaps the backing without reading either image.
func TestRebaseOverlayArgs(t *testing.T) {
	got := strings.Join(rebaseOverlayArgs("/w/scsi0.qcow2", "/w/scsi0.raw"), " ")
	if want := "rebase -u -f qcow2 -F raw -b /w/scsi0.raw /w/scsi0.qcow2"; got != want {
		t.Fatalf("qemu-img %s, want qemu-img %s", got, want)
	}
}
