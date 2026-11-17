// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeImage writes a 70 MiB image: data, an 8 MiB hole, more data and a
// short unaligned tail, so the copy crosses a flush and leaves holes.
func writeImage(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	image := make([]byte, 70<<20+4097)
	for i := 0; i < 20<<20; i++ {
		image[i] = byte(i % 251)
	}
	for i := 28 << 20; i < len(image); i++ {
		image[i] = byte(i % 241)
	}
	path := filepath.Join(dir, "image.raw")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, image
}

// Copy-before-boot: the copy is byte for byte the image, and its digest
// is exactly what a verification pass of the same image reports.
func TestCopyImageIsExactAndHashesLikeAScan(t *testing.T) {
	dir := t.TempDir()
	path, image := writeImage(t, dir)
	src, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	copyPath := filepath.Join(dir, "copy.raw")

	digest, total, _, err := copyImage(context.Background(), src, path, copyPath, DiskSize{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if total != int64(len(image)) || !bytes.Equal(copied, image) {
		t.Fatalf("copy of %d bytes differs from the %d-byte image", len(copied), len(image))
	}
	if _, err := src.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	scanDigest, _, err := hashMappedImage(context.Background(), src, nil)
	if err != nil || scanDigest != digest {
		t.Fatalf("copy digest %s, scan digest %s (%v)", digest, scanDigest, err)
	}
	if info, err := os.Stat(copyPath); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("copy mode = %v, %v; want 0600", info.Mode(), err)
	}
}

func TestCopyImageRefusesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeImage(t, dir)
	src, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	existing := filepath.Join(dir, "existing.raw")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := copyImage(context.Background(), src, "", existing, DiskSize{}, nil); err == nil {
		t.Fatal("copy overwrote an existing file")
	}
	if data, _ := os.ReadFile(existing); string(data) != "keep" {
		t.Fatalf("existing file changed to %q", data)
	}
}

func TestAllZero(t *testing.T) {
	if !allZero(make([]byte, 100)) || allZero([]byte{0, 0, 1}) || !allZero(nil) {
		t.Fatal("allZero is wrong")
	}
}
