// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package initplan

import (
	"strings"
	"testing"
)

// The sentence every message that leaves a newcomer without overlay storage
// ends with, written out: the test pins what the reader sees.
const wantCreateOverlayStorageHint = "Create one on the node, as root: pvesm add dir certistack-scratch --path /var/lib/vz/certistack-scratch --content images --shared 0. On a cluster this defines the storage for every node; add --nodes NODE to limit it to this one. certistack setup adds it for you (quickstart, step 2)"

// A newcomer who skipped the storage step is told what is missing and, in
// the same message, the command that creates it (CR2-06). The note init
// prints when the node has no usable storage pointed at "the test-plan
// reference", a page that does not exist.
func TestComposeNoteForMissingOverlayStorageNamesThePageAndTheCommand(t *testing.T) {
	d := discovered()
	d.Storages = nil
	res, err := Compose(d, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var note string
	for _, n := range res.Notes {
		if strings.Contains(n, "has no storage the token can use for overlays") {
			note = n
		}
	}
	if note == "" {
		t.Fatalf("no note about the missing storage in %v", res.Notes)
	}
	if strings.Contains(note, "test-plan") {
		t.Errorf("the note names a page that does not exist: %s", note)
	}
	if !strings.Contains(note, "see storage.overlay_storage in the plan reference") {
		t.Errorf("the note does not point at the plan reference: %s", note)
	}
	if !strings.HasSuffix(note, wantCreateOverlayStorageHint) {
		t.Errorf("the note must end with the fix %q:\n%s", wantCreateOverlayStorageHint, note)
	}
}

// Every UEFI VM left out for want of storage was a dead end: the refusal said
// what is missing and not how to get it.
func TestComposeRefusalForUEFIOnlyBackupsEndsWithTheCommand(t *testing.T) {
	d := discovered()
	d.Storages = nil
	d.VMs = d.VMs[1:2] // dc-01, UEFI
	_, err := Compose(d, Options{})
	if err == nil {
		t.Fatal("a plan was written for a UEFI VM with no overlay storage")
	}
	for _, want := range []string{"VM 101 (dc-01): it boots with UEFI, which needs overlay storage for its firmware state"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lost %q:\n%v", want, err)
		}
	}
	if !strings.HasSuffix(err.Error(), wantCreateOverlayStorageHint) {
		t.Errorf("the refusal must end with the fix %q:\n%v", wantCreateOverlayStorageHint, err)
	}
	if strings.Count(err.Error(), "pvesm add dir") != 1 {
		t.Errorf("the command appears %d times, want once:\n%v", strings.Count(err.Error(), "pvesm add dir"), err)
	}
}

// A refusal for another reason does not carry a fix that would not help.
func TestComposeRefusalForOtherReasonsHasNoStorageFix(t *testing.T) {
	d := discovered()
	d.Storages = nil
	d.VMs = d.VMs[5:6] // the unreadable backup
	_, err := Compose(d, Options{})
	if err == nil || strings.Contains(err.Error(), "pvesm add") {
		t.Errorf("an encrypted backup's refusal = %v, want no storage command", err)
	}
}

// init --overlay-storage X on a node with nothing usable named the cause and
// no remedy.
func TestComposeRefusalForARequestedStorageOnANodeWithNoneEndsWithTheCommand(t *testing.T) {
	d := discovered()
	d.Storages = nil
	_, err := Compose(d, Options{OverlayStorage: "certistack-scratch"})
	if err == nil || !strings.Contains(err.Error(), `overlay storage "certistack-scratch" cannot hold overlays on node pve1`) {
		t.Fatalf("refusal = %v", err)
	}
	if !strings.HasSuffix(err.Error(), wantCreateOverlayStorageHint) {
		t.Errorf("the refusal must end with the fix %q:\n%v", wantCreateOverlayStorageHint, err)
	}
	// When the node has other storages the refusal lists them: that is the fix.
	_, err = Compose(discovered(), Options{OverlayStorage: "local-lvm"})
	if err == nil || !strings.Contains(err.Error(), "these can: nfs-big, scratch") {
		t.Errorf("refusal with alternatives = %v", err)
	}
}
