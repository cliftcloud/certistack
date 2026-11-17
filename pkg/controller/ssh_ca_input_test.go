// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// Controller staging applies the same regular-file and 1 MiB boundary
// as the PVE client, so a 16 MiB CA is not copied to the scp input in full.
func TestStagePVECAReadsOnlyABoundedRegularFile(t *testing.T) {
	dir := t.TempDir()
	data := bytes.Repeat([]byte("#"), pve.MaxCAFileBytes)
	source := filepath.Join(dir, "source.pem")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "pve-ca.pem")
	if err := stagePVECA(source, destination); err != nil {
		t.Fatalf("stage a CA at the limit: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("staged CA = %d bytes, %v; want the exact source", len(got), err)
	}
	if info, err := os.Stat(destination); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatalf("staged CA mode = %v, %v; want 0600", info.Mode(), err)
	}

	over := filepath.Join(dir, "over.pem")
	if err := os.WriteFile(over, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(over, pve.MaxCAFileBytes+1); err != nil {
		t.Fatal(err)
	}
	tooLargeDestination := filepath.Join(dir, "over-staged.pem")
	if err := stagePVECA(over, tooLargeDestination); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("stage a CA one byte over the limit: %v", err)
	}
	if _, err := os.Lstat(tooLargeDestination); !os.IsNotExist(err) {
		t.Fatalf("oversized CA left staging file: %v", err)
	}

	link := filepath.Join(dir, "pve-ca-link.pem")
	if err := os.Symlink(source, link); err != nil {
		t.Logf("symlink case unavailable: %v", err)
	} else if err := stagePVECA(link, filepath.Join(dir, "linked.pem")); err != nil {
		t.Fatalf("stage a symlink to a regular CA: %v", err)
	}
}

func TestStagePVECARefusesToReplaceAStagingFile(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "source.pem"), filepath.Join(dir, "pve-ca.pem")
	if err := os.WriteFile(source, []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stagePVECA(source, destination); err == nil || !os.IsExist(err) {
		t.Fatalf("stage over existing CA: %v", err)
	}
	if got, err := os.ReadFile(destination); err != nil || string(got) != "keep" {
		t.Fatalf("existing staging file = %q, %v; want preserved", got, err)
	}
}
