// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// The scan's own copy of the mapped device competed for memory with
// the FUSE file's copy the boot reads. Every range the scan has hashed is
// released, in order and exactly once, and the digest is unchanged.
func TestHashMappedImageDropsEveryScannedRange(t *testing.T) {
	content := bytes.Repeat([]byte("certistack"), (9<<20)/10+7) // 9 MiB + 70 bytes: three reads
	path := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	type span struct{ off, n int64 }
	var dropped []span
	orig := dropScannedPages
	dropScannedPages = func(file *os.File, off, n int64) {
		if file != f {
			t.Errorf("dropped pages of %s, want the scanned file", file.Name())
		}
		dropped = append(dropped, span{off, n})
		orig(file, off, n) // the real advice must be harmless on a regular file
	}
	defer func() { dropScannedPages = orig }()

	digest, total, err := hashMappedImage(context.Background(), f, nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if digest != hex.EncodeToString(sum[:]) || total != int64(len(content)) {
		t.Fatalf("digest %s total %d, want %x %d", digest, total, sum, len(content))
	}
	var next int64
	for _, s := range dropped {
		if s.off != next || s.n <= 0 {
			t.Fatalf("dropped %+v after %d: ranges must be contiguous", s, next)
		}
		next += s.n
	}
	if next != total || len(dropped) < 3 {
		t.Fatalf("dropped %d bytes in %d ranges, want all %d in at least 3", next, len(dropped), total)
	}
}
